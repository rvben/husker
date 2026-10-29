//! Guest-owned sessions outlive client connections. Logs and outcomes live on
//! the guest disk, so reconnecting and full-state suspend/resume preserve them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use husker_agent_proto::{
    AgentErrorCode, SessionEvent, SessionEventsResponse, SessionInfo, SessionStartRequest,
    SessionState, base64_encode,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

const MAX_SESSIONS: usize = 128;
const MAX_REPLAY_RECEIPTS: usize = 1024;
const MAX_RUNNING: usize = 16;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENTS: u64 = 4096;
const EVENT_PAGE_SIZE: usize = 128;
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_STATUS_BYTES: u64 = 16 * 1024;

pub struct SessionStore {
    root: PathBuf,
    active: Mutex<HashMap<String, ActiveSession>>,
    /// Source of the per-start sequence numbers in `active`.
    next_sequence: AtomicU64,
    creation: tokio::sync::Mutex<()>,
}

/// A session this agent process started and still supervises. The sequence
/// number of the start that created the entry tells a finishing worker
/// whether the entry under its id is still its own: a session removed and
/// started again under the same id while the previous worker is publishing
/// its outcome gets a new entry, which that worker must not evict.
struct ActiveSession {
    sequence: u64,
    /// Taken by the first cancellation, so a repeat is a no-op.
    cancel: Option<oneshot::Sender<()>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Why the store refused a request. The classified variants reach the host
/// as an [`AgentErrorCode`] beside the message; everything else is a failure
/// the message alone describes.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid session id")]
    InvalidId,
    #[error("session not found")]
    NotFound,
    #[error("too many running sessions (limit {MAX_RUNNING})")]
    TooManyRunning,
    #[error("session retention limit reached; remove finished sessions")]
    RetentionLimitReached,
    #[error("session retention limit exceeded")]
    RetentionLimitExceeded,
    #[error("cancel the running session before removing it")]
    Running,
    #[error("session id already exists")]
    IdExists,
    #[error("session replay conflict: specification changed, removed, or lacks a receipt")]
    ReplayConflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl SessionError {
    /// The classification sent to the host, `None` for an unclassified failure.
    pub fn code(&self) -> Option<AgentErrorCode> {
        Some(match self {
            Self::InvalidId => AgentErrorCode::InvalidSessionId,
            Self::NotFound => AgentErrorCode::SessionNotFound,
            Self::TooManyRunning => AgentErrorCode::TooManyRunningSessions,
            Self::RetentionLimitReached | Self::RetentionLimitExceeded => {
                AgentErrorCode::SessionRetentionLimit
            }
            Self::Running => AgentErrorCode::SessionRunning,
            Self::IdExists => AgentErrorCode::SessionIdExists,
            Self::ReplayConflict => AgentErrorCode::SessionReplayConflict,
            Self::Other(_) => return None,
        })
    }
}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.into())
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(error: serde_json::Error) -> Self {
        Self::Other(error.into())
    }
}

impl From<tokio::task::JoinError> for SessionError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self::Other(error.into())
    }
}

/// An unclassified refusal: the message is all the host learns about it.
fn unclassified(message: &'static str) -> SessionError {
    SessionError::Other(anyhow::anyhow!(message))
}

/// Return `error` from the enclosing function unless `condition` holds.
macro_rules! ensure {
    ($condition:expr, $error:expr $(,)?) => {
        if !$condition {
            return Err($error);
        }
    };
}

impl SessionStore {
    /// Create an isolated guest session store. Tests use a temporary directory.
    pub fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            root,
            active: Mutex::new(HashMap::new()),
            next_sequence: AtomicU64::new(0),
            creation: tokio::sync::Mutex::new(()),
        })
    }

    /// Drop the active entry for `id` if it still belongs to the start that
    /// was given `sequence`.
    fn release(&self, id: &str, sequence: u64) {
        let mut active = self.active.lock().unwrap();
        if active
            .get(id)
            .is_some_and(|session| session.sequence == sequence)
        {
            active.remove(id);
        }
    }

    fn directory(&self, id: &str) -> Result<PathBuf, SessionError> {
        let bytes = id.as_bytes();
        ensure!(
            bytes.len() == 36
                && bytes.iter().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        *b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                }),
            SessionError::InvalidId
        );
        Ok(self.root.join(id))
    }

    async fn save(&self, info: &SessionInfo) -> Result<(), SessionError> {
        let dir = self.directory(&info.id)?;
        let bytes = serde_json::to_vec(info)?;
        ensure!(
            bytes.len() <= MAX_STATUS_BYTES as usize,
            unclassified("session status exceeds limit")
        );
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temporary = dir.join(format!(
            "status-{}.tmp",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = tokio::fs::File::create(&temporary).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        tokio::fs::rename(temporary, dir.join("status.json")).await?;
        let directory = tokio::fs::File::open(dir).await?;
        directory.sync_all().await?;
        Ok(())
    }

    async fn read_status(&self, id: &str) -> Result<SessionInfo, SessionError> {
        let path = self.directory(id)?.join("status.json");
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SessionError::NotFound
            } else {
                SessionError::Other(anyhow::Error::new(error).context("reading session status"))
            }
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= MAX_STATUS_BYTES as usize,
            unclassified("session status exceeds limit")
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(crate) async fn get(&self, id: &str) -> Result<SessionInfo, SessionError> {
        let mut info = self.read_status(id).await?;
        // An agent restart cannot reconstruct Tokio's process handles. Preserve
        // the log but report the interruption rather than claiming it is live.
        if info.state == SessionState::Running && !self.active.lock().unwrap().contains_key(id) {
            // A worker may have completed between the first read and the map
            // check. Re-read its atomic outcome before marking an interruption.
            info = self.read_status(id).await?;
            if info.state != SessionState::Running {
                return Ok(info);
            }
            info.state = SessionState::Interrupted;
            info.finished_at = Some(now());
            self.save(&info).await?;
        }
        Ok(info)
    }

    pub(crate) async fn list(&self) -> Result<Vec<SessionInfo>, SessionError> {
        let _creation = self.creation.lock().await;
        self.list_entries().await
    }

    async fn list_entries(&self) -> Result<Vec<SessionInfo>, SessionError> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut sessions = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() && entry.file_name() != ".removed" {
                // A crash before initial status publication leaves only an
                // empty log and temporary metadata. No worker starts until
                // status is published. Recover these owned transaction scraps
                // under the creation lock so they cannot poison future lists.
                if !tokio::fs::try_exists(entry.path().join("status.json")).await? {
                    self.directory(&entry.file_name().to_string_lossy())?;
                    let log = tokio::fs::metadata(entry.path().join("events.jsonl")).await;
                    let empty = match log {
                        Ok(metadata) => metadata.len() == 0,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                        Err(error) => return Err(error.into()),
                    };
                    ensure!(
                        empty,
                        unclassified(
                            "incomplete session has retained output; inspect the guest session directory"
                        )
                    );
                    tokio::fs::remove_dir_all(entry.path()).await?;
                    continue;
                }
                sessions.push(self.get(&entry.file_name().to_string_lossy()).await?);
                ensure!(
                    sessions.len() <= MAX_SESSIONS,
                    SessionError::RetentionLimitExceeded
                );
            }
        }
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        Ok(sessions)
    }

    /// Start a session running `request`, under the request's own timeout or
    /// `default_timeout` when it carries none.
    pub(crate) async fn start(
        self: &Arc<Self>,
        request: SessionStartRequest,
        default_timeout: Duration,
    ) -> Result<SessionInfo, SessionError> {
        // Once accepted, guest ownership includes the start transaction itself.
        // Dropping a client request cannot strand an active-map entry or kill a
        // child between spawn, durable status publication and worker handoff.
        let store = self.clone();
        tokio::spawn(async move { store.start_owned(request, default_timeout, false).await })
            .await?
    }

    pub(crate) async fn start_replay(
        self: &Arc<Self>,
        request: SessionStartRequest,
        default_timeout: Duration,
    ) -> Result<SessionInfo, SessionError> {
        let store = self.clone();
        tokio::spawn(async move { store.start_owned(request, default_timeout, true).await }).await?
    }

    async fn start_owned(
        self: &Arc<Self>,
        request: SessionStartRequest,
        default_timeout: Duration,
        replay: bool,
    ) -> Result<SessionInfo, SessionError> {
        ensure!(
            request.exec.command.len() <= 4096,
            unclassified("session command exceeds limit")
        );
        let _creation = self.creation.lock().await;
        let dir = self.directory(&request.id)?;
        let sessions = self.list_entries().await?;
        let specification = serde_json::to_vec(&(
            &request.exec.command,
            &request.exec.args,
            &request.exec.working_dir,
            &request.exec.env,
            request
                .exec
                .timeout_secs
                .unwrap_or(default_timeout.as_secs()),
        ))?;
        ensure!(
            !replay || specification.len() <= 64 * 1024,
            unclassified("session specification exceeds limit")
        );
        let digest = format!("v1:{}", hex::encode(Sha256::digest(&specification)));
        if replay {
            ensure!(
                !tokio::fs::try_exists(self.root.join(".removed").join(&request.id)).await?,
                SessionError::ReplayConflict
            );
            if tokio::fs::try_exists(&dir).await? {
                let file = tokio::fs::File::open(dir.join("request.sha256"))
                    .await
                    .map_err(|_| SessionError::ReplayConflict)?;
                let mut bytes = Vec::new();
                file.take(69).read_to_end(&mut bytes).await?;
                ensure!(bytes == digest.as_bytes(), SessionError::ReplayConflict);
                return self.get(&request.id).await;
            }
            // Reserve receipt space at acceptance, so removing sessions always works.
            let mut count = 0;
            match tokio::fs::read_dir(self.root.join(".removed")).await {
                Ok(mut entries) => {
                    while entries.next_entry().await?.is_some() {
                        count += 1;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            for session in &sessions {
                if tokio::fs::try_exists(self.directory(&session.id)?.join("request.sha256"))
                    .await?
                {
                    count += 1;
                }
            }
            ensure!(
                count < MAX_REPLAY_RECEIPTS,
                unclassified(
                    "replay receipt budget exhausted; destroy this VM before accepting more submissions"
                )
            );
        }
        ensure!(
            self.active.lock().unwrap().len() < MAX_RUNNING,
            SessionError::TooManyRunning
        );
        ensure!(
            sessions.len() < MAX_SESSIONS,
            SessionError::RetentionLimitReached
        );
        tokio::fs::create_dir_all(&self.root).await?;
        tokio::fs::create_dir(&dir)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => SessionError::IdExists,
                _ => SessionError::Other(
                    anyhow::Error::new(error).context("creating the session directory"),
                ),
            })?;
        let mut accepted = false;
        let start: Result<SessionInfo, SessionError> = async {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
            }
            let (mut command, timeout) =
                super::build_exec_command(&request.exec, default_timeout)
                    .map_err(|e| anyhow::anyhow!(e.message))?;
            command.process_group(0)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let log = tokio::fs::File::create(dir.join("events.jsonl")).await?;
            let early_child = if replay { None } else { Some(command.spawn().context("starting session command")?) };
            let early_group = early_child.as_ref().map(|child| child.id().context("session process has no id").map(|id| ProcessGroup(id as i32))).transpose()?;
            if replay {
                let mut receipt = tokio::fs::File::create(dir.join("request.sha256")).await?;
                receipt.write_all(digest.as_bytes()).await?;
                receipt.sync_all().await?;
            }
            let info = SessionInfo {
                id: request.id.clone(), command: request.exec.command.clone(),
                state: SessionState::Running, created_at: now(), finished_at: None,
                exit_code: None, output_truncated: false,
            };
            let (cancel, cancelled) = oneshot::channel();
            let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
            self.active.lock().unwrap().insert(
                info.id.clone(),
                ActiveSession {
                    sequence,
                    cancel: Some(cancel),
                },
            );
            if let Err(error) = self.save(&info).await {
                self.release(&info.id, sequence);
                return Err(error);
            }
            if replay {
                // Once status is published, recovery must never execute this ID again.
                accepted = true;
                if let Err(error) = async {
                    tokio::fs::File::open(&self.root).await?.sync_all().await?;
                    if let Some(parent) = self.root.parent() {
                        tokio::fs::File::open(parent).await?.sync_all().await?;
                    }
                    Ok::<_, std::io::Error>(())
                }.await {
                    self.release(&info.id, sequence);
                    return Err(error.into());
                }
            }
            let child = match early_child.map(Ok).unwrap_or_else(|| command.spawn()) {
                Ok(child) => child,
                Err(error) => {
                    let mut failed = info.clone();
                    failed.state = SessionState::Interrupted;
                    failed.finished_at = Some(now());
                    let saved = self.save(&failed).await;
                    self.release(&info.id, sequence);
                    saved?;
                    return Err(anyhow::Error::new(error).context("starting accepted session command").into());
                }
            };
            let group = match early_group { Some(group) => group, None => ProcessGroup(child.id().context("session process has no id")? as i32) };
            let store = self.clone();
            let mut outcome = info.clone();
            tokio::spawn(async move {
                if let Err(error) = run(child, group, timeout, cancelled, log, &mut outcome).await {
                    tracing::warn!(session = %outcome.id, %error, "session execution failed");
                    outcome.state = SessionState::Interrupted;
                }
                outcome.finished_at = Some(now());
                if let Err(error) = store.save(&outcome).await {
                    tracing::warn!(session = %outcome.id, %error, "session outcome could not be saved");
                }
                store.release(&outcome.id, sequence);
            });
            Ok(info)
        }.await;
        if start.is_err() && !accepted {
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
        start
    }

    pub(crate) async fn cancel(&self, id: &str) -> Result<SessionInfo, SessionError> {
        let info = self.get(id).await?;
        if let Some(sender) = self
            .active
            .lock()
            .unwrap()
            .get_mut(id)
            .and_then(|session| session.cancel.take())
        {
            let _ = sender.send(());
        }
        Ok(info)
    }

    pub(crate) async fn remove(&self, id: &str) -> Result<(), SessionError> {
        let _creation = self.creation.lock().await;
        let info = self.get(id).await?;
        ensure!(info.state != SessionState::Running, SessionError::Running);
        if tokio::fs::try_exists(self.directory(id)?.join("request.sha256")).await? {
            let tombstones = self.root.join(".removed");
            tokio::fs::create_dir_all(&tombstones).await?;
            let mut receipt = tokio::fs::File::create(tombstones.join(id)).await?;
            receipt.write_all(b"removed").await?;
            receipt.sync_all().await?;
            tokio::fs::File::open(tombstones).await?.sync_all().await?;
            tokio::fs::File::open(&self.root).await?.sync_all().await?;
        }
        tokio::fs::remove_dir_all(self.directory(id)?).await?;
        Ok(())
    }

    pub(crate) async fn events(
        &self,
        id: &str,
        after: u64,
    ) -> Result<SessionEventsResponse, SessionError> {
        let session = self.get(id).await?;
        let file = tokio::fs::File::open(self.directory(id)?.join("events.jsonl")).await?;
        ensure!(
            file.metadata().await?.len() <= MAX_LOG_BYTES,
            unclassified("session log exceeds limit")
        );
        let mut reader = BufReader::new(file.take(MAX_LOG_BYTES));
        let mut events = Vec::new();
        let mut has_more = false;
        let mut previous = 0;
        loop {
            let mut line = Vec::new();
            let n = (&mut reader)
                .take(MAX_RECORD_BYTES)
                .read_until(b'\n', &mut line)
                .await?;
            ensure!(
                n < MAX_RECORD_BYTES as usize,
                unclassified("session event exceeds limit")
            );
            // Ignore an in-progress append until its terminating newline appears.
            if line.last() != Some(&b'\n') {
                break;
            }
            let event: SessionEvent = serde_json::from_slice(&line)?;
            ensure!(
                event.sequence == previous + 1 && event.sequence <= MAX_EVENTS,
                unclassified("invalid session event sequence")
            );
            previous = event.sequence;
            if event.sequence > after {
                if events.len() == EVENT_PAGE_SIZE {
                    has_more = true;
                    break;
                }
                events.push(event);
            }
        }
        let next_cursor = events.last().map_or(after, |e| e.sequence);
        Ok(SessionEventsResponse {
            session,
            events,
            next_cursor,
            has_more,
        })
    }
}

/// Sessions own the whole process group, including child tools started by an agent.
struct ProcessGroup(i32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // SAFETY: the positive PID was obtained from a child placed in its own
        // group. A negative pid targets that group, never the agent's group.
        unsafe {
            libc::kill(-self.0, libc::SIGKILL);
        }
    }
}

async fn run(
    mut child: tokio::process::Child,
    group: ProcessGroup,
    timeout: Duration,
    mut cancelled: oneshot::Receiver<()>,
    mut log: tokio::fs::File,
    outcome: &mut SessionInfo,
) -> anyhow::Result<()> {
    let mut stdout = child.stdout.take().context("missing session stdout")?;
    let mut stderr = child.stderr.take().context("missing session stderr")?;
    let mut out_buf = [0u8; 8192];
    let mut err_buf = [0u8; 8192];
    let mut out_open = true;
    let mut err_open = true;
    let mut captured = 0;
    let mut sequence = 0;
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut drain_deadline = None;
    loop {
        if outcome.exit_code.is_some() && !out_open && !err_open {
            break;
        }
        let (stream, chunk): (&str, &[u8]) = tokio::select! {
            n = stdout.read(&mut out_buf), if out_open => {
                let n = n?; if n == 0 { out_open = false; continue; }
                ("stdout", &out_buf[..n])
            }
            n = stderr.read(&mut err_buf), if err_open => {
                let n = n?; if n == 0 { err_open = false; continue; }
                ("stderr", &err_buf[..n])
            }
            status = child.wait(), if outcome.exit_code.is_none() => {
                outcome.exit_code = Some(status?.code().unwrap_or(-1));
                outcome.state = SessionState::Completed;
                drain_deadline = Some(tokio::time::Instant::now() + super::EXEC_DRAIN_GRACE);
                continue;
            }
            _ = &mut cancelled, if outcome.exit_code.is_none() => {
                // Drop group before waiting, so nested processes cannot survive cancellation.
                unsafe { libc::kill(-group.0, libc::SIGKILL); }
                let _ = child.wait().await;
                outcome.exit_code = Some(130); outcome.state = SessionState::Cancelled;
                drain_deadline = Some(tokio::time::Instant::now() + super::EXEC_DRAIN_GRACE);
                continue;
            }
            _ = &mut deadline, if outcome.exit_code.is_none() => {
                unsafe { libc::kill(-group.0, libc::SIGKILL); }
                let _ = child.wait().await;
                outcome.exit_code = Some(124); outcome.state = SessionState::TimedOut;
                drain_deadline = Some(tokio::time::Instant::now() + super::EXEC_DRAIN_GRACE);
                continue;
            }
            _ = async {
                match drain_deadline { Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await }
            }, if outcome.exit_code.is_some() => break,
        };
        let retained = if sequence < MAX_EVENTS {
            chunk.len().min(MAX_OUTPUT_BYTES - captured)
        } else {
            0
        };
        outcome.output_truncated |= retained < chunk.len();
        if retained > 0 {
            captured += retained;
            sequence += 1;
            let event = SessionEvent {
                sequence,
                stream: stream.into(),
                data: base64_encode(&chunk[..retained]),
            };
            let mut bytes = serde_json::to_vec(&event)?;
            bytes.push(b'\n');
            log.write_all(&bytes).await?;
            log.flush().await?;
        }
    }
    log.sync_data().await?;
    drop(group);
    Ok(())
}

pub(crate) fn store() -> &'static Arc<SessionStore> {
    static STORE: std::sync::OnceLock<Arc<SessionStore>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| SessionStore::new(Path::new("/var/lib/husker/sessions").into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use husker_agent_proto::{ExecRequest, base64_decode};

    const ID: &str = "12345678-1234-1234-1234-123456789abc";

    /// The default exec timeout these tests start sessions under. Every
    /// request here names its own timeout, so the value never applies.
    const TIMEOUT: Duration = Duration::from_secs(600);

    fn request(command: &str) -> SessionStartRequest {
        SessionStartRequest {
            id: ID.into(),
            exec: ExecRequest {
                command: "sh".into(),
                args: vec!["-c".into(), command.into()],
                working_dir: Some("/tmp".into()),
                env: Vec::new(),
                timeout_secs: Some(5),
            },
        }
    }

    async fn finished(store: &SessionStore) -> SessionInfo {
        finished_within(store, Duration::from_secs(10)).await
    }

    async fn finished_within(store: &SessionStore, bound: Duration) -> SessionInfo {
        tokio::time::timeout(bound, async {
            loop {
                let info = store.get(ID).await.unwrap();
                if info.state != SessionState::Running {
                    return info;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn durable_replay_runs_once_and_rejects_changed_or_removed_specifications() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().join("sessions"));
        let counter = temp.path().join("counter");
        let req = request(&format!("printf x >> '{}'; sleep 0.1", counter.display()));
        let (a, b) = tokio::join!(
            store.start_replay(req.clone(), TIMEOUT),
            store.start_replay(req.clone(), TIMEOUT)
        );
        assert_eq!(a.unwrap().id, b.unwrap().id);
        assert_eq!(finished(&store).await.state, SessionState::Completed);
        let reopened = SessionStore::new(temp.path().join("sessions"));
        assert_eq!(
            reopened
                .start_replay(req.clone(), TIMEOUT)
                .await
                .unwrap()
                .state,
            SessionState::Completed
        );
        assert_eq!(tokio::fs::read(counter).await.unwrap(), b"x");
        let mut changed = req.clone();
        changed.exec.env.push(("SECRET".into(), "not-saved".into()));
        assert!(matches!(
            reopened.start_replay(changed, TIMEOUT).await,
            Err(SessionError::ReplayConflict)
        ));
        reopened.remove(ID).await.unwrap();
        assert!(reopened.list().await.unwrap().is_empty());
        assert!(matches!(
            reopened.start_replay(req, TIMEOUT).await,
            Err(SessionError::ReplayConflict)
        ));
    }

    #[tokio::test]
    async fn accepted_but_unspawned_replay_recovers_as_interrupted() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        let req = request("printf must-not-execute");
        let dir = temp.path().join(ID);
        tokio::fs::create_dir(&dir).await.unwrap();
        let digest = format!(
            "v1:{}",
            hex::encode(Sha256::digest(
                serde_json::to_vec(&(
                    &req.exec.command,
                    &req.exec.args,
                    &req.exec.working_dir,
                    &req.exec.env,
                    req.exec.timeout_secs.unwrap_or(TIMEOUT.as_secs())
                ))
                .unwrap()
            ))
        );
        tokio::fs::write(dir.join("request.sha256"), digest)
            .await
            .unwrap();
        tokio::fs::write(dir.join("events.jsonl"), b"")
            .await
            .unwrap();
        store
            .save(&SessionInfo {
                id: ID.into(),
                command: "sh".into(),
                state: SessionState::Running,
                created_at: now(),
                finished_at: None,
                exit_code: None,
                output_truncated: false,
            })
            .await
            .unwrap();
        assert_eq!(
            store.start_replay(req, TIMEOUT).await.unwrap().state,
            SessionState::Interrupted
        );
        assert!(store.events(ID, 0).await.unwrap().events.is_empty());
    }

    #[tokio::test]
    async fn replay_budget_blocks_new_acceptance_without_blocking_removal_or_legacy_starts() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().join("sessions"));
        let removed = store.root.join(".removed");
        tokio::fs::create_dir_all(&removed).await.unwrap();
        for n in 0..MAX_REPLAY_RECEIPTS - 1 {
            tokio::fs::write(removed.join(format!("old-{n}")), b"removed")
                .await
                .unwrap();
        }
        store.start_replay(request("true"), TIMEOUT).await.unwrap();
        finished(&store).await;
        store.remove(ID).await.unwrap();
        assert!(store.list().await.unwrap().is_empty());
        let mut second = request("true");
        second.id = "22345678-1234-1234-1234-123456789abc".into();
        assert!(
            store
                .start_replay(second.clone(), TIMEOUT)
                .await
                .unwrap_err()
                .to_string()
                .contains("budget exhausted")
        );
        assert!(store.start(second, TIMEOUT).await.is_ok());
    }

    #[tokio::test]
    async fn replay_specification_limit_does_not_change_legacy_session_limits() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        let mut req = request("true");
        req.exec
            .env
            .push(("TEST_PAYLOAD".into(), "x".repeat(70 * 1024)));
        store.start(req.clone(), TIMEOUT).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::Completed);
        store.remove(ID).await.unwrap();
        assert!(
            store
                .start_replay(req, TIMEOUT)
                .await
                .unwrap_err()
                .to_string()
                .contains("specification exceeds limit")
        );
    }

    #[tokio::test]
    async fn detached_session_persists_binary_logs_and_reconnect_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store
            .start(
                request("sleep 0.05; printf '\\377done'; printf error >&2"),
                TIMEOUT,
            )
            .await
            .unwrap();
        let info = finished(&store).await;
        assert_eq!(info.exit_code, Some(0));
        let reopened = SessionStore::new(temp.path().into());
        let events = reopened.events(ID, 0).await.unwrap();
        let output: Vec<u8> = events
            .events
            .iter()
            .filter(|e| e.stream == "stdout")
            .flat_map(|e| base64_decode(&e.data).unwrap())
            .collect();
        assert_eq!(output, b"\xffdone");
        assert!(events.events.iter().any(|e| e.stream == "stderr"));
        assert!(
            reopened
                .events(ID, events.next_cursor)
                .await
                .unwrap()
                .events
                .is_empty()
        );
        reopened.remove(ID).await.unwrap();
        assert!(reopened.get(ID).await.is_err());
    }

    #[tokio::test]
    async fn cancellation_terminates_nested_process_group_children() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("child-survived");
        let store = SessionStore::new(temp.path().join("sessions"));
        store
            .start(
                request(&format!(
                    r#"sh -c 'sleep 1; touch "{}"' & printf ready; wait"#,
                    marker.display()
                )),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while store.events(ID, 0).await.unwrap().events.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        store.cancel(ID).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::Cancelled);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            !marker.exists(),
            "nested child survived process-group cancellation"
        );
    }

    #[tokio::test]
    async fn cancellation_and_timeout_report_distinct_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store.start(request("sleep 60"), TIMEOUT).await.unwrap();
        assert!(store.remove(ID).await.is_err());
        store.cancel(ID).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::Cancelled);
        store.remove(ID).await.unwrap();
        let mut req = request("sleep 60");
        req.exec.timeout_secs = Some(1);
        store.start(req, TIMEOUT).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::TimedOut);
    }

    #[tokio::test]
    async fn a_predecessor_finishing_late_leaves_a_restarted_session_supervised() {
        // A worker publishes its outcome before it releases its active entry,
        // and `remove` accepts the session as soon as that outcome is
        // persisted, so a session started again under the same id can be
        // live when the previous worker's release runs. That release must
        // not evict the successor: it stays running and its cancel sender
        // stays reachable.
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store.start(request("sleep 60"), TIMEOUT).await.unwrap();
        let predecessor = store.active.lock().unwrap()[ID].sequence;
        store.cancel(ID).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::Cancelled);
        store.remove(ID).await.unwrap();
        store.start(request("sleep 60"), TIMEOUT).await.unwrap();

        store.release(ID, predecessor);

        assert_eq!(store.get(ID).await.unwrap().state, SessionState::Running);
        store.cancel(ID).await.unwrap();
        assert_eq!(
            finished(&store).await.state,
            SessionState::Cancelled,
            "the restarted session must still be cancellable"
        );
    }

    #[tokio::test]
    async fn session_output_is_bounded_without_blocking_command() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        // Capturing 5 MB writes and flushes hundreds of log records, which a
        // loaded host can stretch past the module's 5 s session timeout. The
        // timeout here only has to outlast that I/O: a capture loop that
        // stopped reading at the cap would leave `head` blocked on a full
        // pipe until the timeout killed it, so the exit code still tells.
        let mut req = request("head -c 5000000 /dev/zero");
        req.exec.timeout_secs = Some(120);
        store.start(req, TIMEOUT).await.unwrap();
        let info = finished_within(&store, Duration::from_secs(150)).await;
        assert_eq!(info.exit_code, Some(0));
        assert!(info.output_truncated);
        let size = tokio::fs::metadata(temp.path().join(ID).join("events.jsonl"))
            .await
            .unwrap()
            .len();
        assert!(size < 6 * 1024 * 1024);
    }

    #[tokio::test]
    async fn cancelled_client_does_not_cancel_the_start_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        let creation = store.creation.lock().await;
        let owned = store.clone();
        let client =
            tokio::spawn(async move { owned.start(request("printf accepted"), TIMEOUT).await });
        tokio::task::yield_now().await;
        client.abort();
        drop(creation);
        tokio::time::timeout(Duration::from_secs(3), async {
            while store.get(ID).await.is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let info = finished(&store).await;
        assert_eq!(info.exit_code, Some(0));
        tokio::time::timeout(Duration::from_secs(3), async {
            while !store.active.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(store.events(ID, 0).await.unwrap().events.len(), 1);
    }

    #[tokio::test]
    async fn oversized_and_unterminated_log_records_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store.start(request("printf hello"), TIMEOUT).await.unwrap();
        finished(&store).await;
        let path = temp.path().join(ID).join("events.jsonl");
        let complete = tokio::fs::read(&path).await.unwrap();
        let mut partial = complete.clone();
        partial.extend_from_slice(b"{\"sequence\":2");
        tokio::fs::write(&path, partial).await.unwrap();
        assert_eq!(store.events(ID, 0).await.unwrap().events.len(), 1);
        tokio::fs::write(&path, vec![b'x'; MAX_RECORD_BYTES as usize + 1])
            .await
            .unwrap();
        assert!(store.events(ID, 0).await.is_err());
        let file = tokio::fs::File::create(&path).await.unwrap();
        file.set_len(MAX_LOG_BYTES + 1).await.unwrap();
        assert!(store.events(ID, 0).await.is_err());
    }

    #[tokio::test]
    async fn restart_recovers_unpublished_start_without_discarding_retained_output() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        let dir = temp.path().join(ID);
        tokio::fs::create_dir(&dir).await.unwrap();
        tokio::fs::write(dir.join("events.jsonl"), b"")
            .await
            .unwrap();
        assert!(store.list().await.unwrap().is_empty());
        assert!(!dir.exists());
        tokio::fs::create_dir(&dir).await.unwrap();
        tokio::fs::write(dir.join("events.jsonl"), b"retained evidence")
            .await
            .unwrap();
        assert!(store.list().await.is_err());
        assert_eq!(
            tokio::fs::read(dir.join("events.jsonl")).await.unwrap(),
            b"retained evidence"
        );
    }

    #[tokio::test]
    async fn paths_duplicates_and_spawn_failures_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        assert!(matches!(
            store.get("../../etc/passwd").await,
            Err(SessionError::InvalidId)
        ));
        assert!(matches!(
            store.get("00000000-0000-0000-0000-000000000000").await,
            Err(SessionError::NotFound)
        ));
        let mut bad = request("true");
        bad.exec.command = "/no/such/program".into();
        let spawn_failure = store.start(bad, TIMEOUT).await.unwrap_err();
        assert!(matches!(spawn_failure, SessionError::Other(_)));
        assert!(
            format!("{spawn_failure:#}").starts_with("starting session command: "),
            "unexpected spawn failure: {spawn_failure:#}"
        );
        assert!(!temp.path().join(ID).exists());
        store.start(request("sleep 60"), TIMEOUT).await.unwrap();
        assert!(matches!(
            store.start(request("true"), TIMEOUT).await,
            Err(SessionError::IdExists)
        ));
        assert!(matches!(store.remove(ID).await, Err(SessionError::Running)));
        store.cancel(ID).await.unwrap();
        finished(&store).await;
    }

    #[test]
    fn classified_refusals_keep_their_wire_codes_and_messages() {
        // Daemons from husker 0.4.51 and 0.4.52 classify a refusal by its
        // message, so the message of every coded variant is part of the wire
        // contract for as long as those daemons run.
        let cases = [
            (
                SessionError::InvalidId,
                AgentErrorCode::InvalidSessionId,
                "invalid session id",
            ),
            (
                SessionError::NotFound,
                AgentErrorCode::SessionNotFound,
                "session not found",
            ),
            (
                SessionError::TooManyRunning,
                AgentErrorCode::TooManyRunningSessions,
                "too many running sessions (limit 16)",
            ),
            (
                SessionError::RetentionLimitReached,
                AgentErrorCode::SessionRetentionLimit,
                "session retention limit reached; remove finished sessions",
            ),
            (
                SessionError::RetentionLimitExceeded,
                AgentErrorCode::SessionRetentionLimit,
                "session retention limit exceeded",
            ),
            (
                SessionError::Running,
                AgentErrorCode::SessionRunning,
                "cancel the running session before removing it",
            ),
            (
                SessionError::IdExists,
                AgentErrorCode::SessionIdExists,
                "session id already exists",
            ),
        ];
        for (error, code, message) in cases {
            assert_eq!(error.code(), Some(code), "{error}");
            assert_eq!(error.to_string(), message);
        }
        let other = unclassified("session log exceeds limit");
        assert_eq!(other.code(), None);
        assert_eq!(format!("{other:#}"), "session log exceeds limit");
        let chained = SessionError::Other(
            anyhow::Error::new(std::io::Error::other("disk gone"))
                .context("reading session status"),
        );
        assert_eq!(chained.code(), None);
        assert_eq!(format!("{chained:#}"), "reading session status: disk gone");
    }
}
