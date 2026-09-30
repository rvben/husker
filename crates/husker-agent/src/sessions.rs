//! Guest-owned sessions outlive client connections. Logs and outcomes live on
//! the guest disk, so reconnecting and full-state suspend/resume preserve them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use husker_agent_proto::{
    SessionEvent, SessionEventsResponse, SessionInfo, SessionStartRequest, SessionState,
    base64_encode,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

const MAX_SESSIONS: usize = 128;
const MAX_RUNNING: usize = 16;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENTS: u64 = 4096;
const EVENT_PAGE_SIZE: usize = 128;
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_STATUS_BYTES: u64 = 16 * 1024;

pub struct SessionStore {
    root: PathBuf,
    active: Mutex<HashMap<String, Option<oneshot::Sender<()>>>>,
    creation: tokio::sync::Mutex<()>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SessionStore {
    /// Create an isolated guest session store. Tests use a temporary directory.
    pub fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            root,
            active: Mutex::new(HashMap::new()),
            creation: tokio::sync::Mutex::new(()),
        })
    }

    fn directory(&self, id: &str) -> Result<PathBuf> {
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
            "invalid session id"
        );
        Ok(self.root.join(id))
    }

    async fn save(&self, info: &SessionInfo) -> Result<()> {
        let dir = self.directory(&info.id)?;
        let bytes = serde_json::to_vec(info)?;
        ensure!(
            bytes.len() <= MAX_STATUS_BYTES as usize,
            "session status exceeds limit"
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

    async fn read_status(&self, id: &str) -> Result<SessionInfo> {
        let path = self.directory(id)?.join("status.json");
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("session not found")
            } else {
                anyhow::Error::new(error).context("reading session status")
            }
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= MAX_STATUS_BYTES as usize,
            "session status exceeds limit"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(crate) async fn get(&self, id: &str) -> Result<SessionInfo> {
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

    pub(crate) async fn list(&self) -> Result<Vec<SessionInfo>> {
        let _creation = self.creation.lock().await;
        self.list_entries().await
    }

    async fn list_entries(&self) -> Result<Vec<SessionInfo>> {
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut sessions = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
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
                        "incomplete session has retained output; inspect the guest session directory"
                    );
                    tokio::fs::remove_dir_all(entry.path()).await?;
                    continue;
                }
                sessions.push(self.get(&entry.file_name().to_string_lossy()).await?);
                ensure!(
                    sessions.len() <= MAX_SESSIONS,
                    "session retention limit exceeded"
                );
            }
        }
        sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        Ok(sessions)
    }

    pub(crate) async fn start(
        self: &Arc<Self>,
        request: SessionStartRequest,
    ) -> Result<SessionInfo> {
        // Once accepted, guest ownership includes the start transaction itself.
        // Dropping a client request cannot strand an active-map entry or kill a
        // child between spawn, durable status publication and worker handoff.
        let store = self.clone();
        tokio::spawn(async move { store.start_owned(request).await }).await?
    }

    async fn start_owned(self: &Arc<Self>, request: SessionStartRequest) -> Result<SessionInfo> {
        ensure!(
            request.exec.command.len() <= 4096,
            "session command exceeds limit"
        );
        let _creation = self.creation.lock().await;
        let dir = self.directory(&request.id)?;
        ensure!(
            self.active.lock().unwrap().len() < MAX_RUNNING,
            "too many running sessions (limit {MAX_RUNNING})"
        );
        ensure!(
            self.list_entries().await?.len() < MAX_SESSIONS,
            "session retention limit reached; remove finished sessions"
        );
        tokio::fs::create_dir_all(&self.root).await?;
        tokio::fs::create_dir(&dir)
            .await
            .context("session id already exists")?;
        let start = async {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
            }
            let (mut command, timeout) = super::build_exec_command(&request.exec)
                .map_err(|e| anyhow::anyhow!(e.message))?;
            command.process_group(0)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let log = tokio::fs::File::create(dir.join("events.jsonl")).await?;
            let child = command.spawn().context("starting session command")?;
            let group = ProcessGroup(child.id().context("session process has no id")? as i32);
            let info = SessionInfo {
                id: request.id.clone(), command: request.exec.command.clone(),
                state: SessionState::Running, created_at: now(), finished_at: None,
                exit_code: None, output_truncated: false,
            };
            let (cancel, cancelled) = oneshot::channel();
            self.active.lock().unwrap().insert(info.id.clone(), Some(cancel));
            if let Err(error) = self.save(&info).await {
                self.active.lock().unwrap().remove(&info.id);
                return Err(error);
            }
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
                store.active.lock().unwrap().remove(&outcome.id);
            });
            Ok(info)
        }.await;
        if start.is_err() {
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
        start
    }

    pub(crate) async fn cancel(&self, id: &str) -> Result<SessionInfo> {
        let info = self.get(id).await?;
        if let Some(sender) = self
            .active
            .lock()
            .unwrap()
            .get_mut(id)
            .and_then(Option::take)
        {
            let _ = sender.send(());
        }
        Ok(info)
    }

    pub(crate) async fn remove(&self, id: &str) -> Result<()> {
        let _creation = self.creation.lock().await;
        let info = self.get(id).await?;
        ensure!(
            info.state != SessionState::Running,
            "cancel the running session before removing it"
        );
        tokio::fs::remove_dir_all(self.directory(id)?).await?;
        Ok(())
    }

    pub(crate) async fn events(&self, id: &str, after: u64) -> Result<SessionEventsResponse> {
        let session = self.get(id).await?;
        let file = tokio::fs::File::open(self.directory(id)?.join("events.jsonl")).await?;
        ensure!(
            file.metadata().await?.len() <= MAX_LOG_BYTES,
            "session log exceeds limit"
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
            ensure!(n < MAX_RECORD_BYTES as usize, "session event exceeds limit");
            // Ignore an in-progress append until its terminating newline appears.
            if line.last() != Some(&b'\n') {
                break;
            }
            let event: SessionEvent = serde_json::from_slice(&line)?;
            ensure!(
                event.sequence == previous + 1 && event.sequence <= MAX_EVENTS,
                "invalid session event sequence"
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
) -> Result<()> {
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
        tokio::time::timeout(Duration::from_secs(10), async {
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
    async fn detached_session_persists_binary_logs_and_reconnect_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store
            .start(request("sleep 0.05; printf '\\377done'; printf error >&2"))
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
    async fn cancellation_and_timeout_report_distinct_outcomes() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store.start(request("sleep 60")).await.unwrap();
        assert!(store.remove(ID).await.is_err());
        store.cancel(ID).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::Cancelled);
        store.remove(ID).await.unwrap();
        let mut req = request("sleep 60");
        req.exec.timeout_secs = Some(1);
        store.start(req).await.unwrap();
        assert_eq!(finished(&store).await.state, SessionState::TimedOut);
    }

    #[tokio::test]
    async fn session_output_is_bounded_without_blocking_command() {
        let temp = tempfile::tempdir().unwrap();
        let store = SessionStore::new(temp.path().into());
        store
            .start(request("head -c 5000000 /dev/zero"))
            .await
            .unwrap();
        let info = finished(&store).await;
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
        let client = tokio::spawn(async move { owned.start(request("printf accepted")).await });
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
        store.start(request("printf hello")).await.unwrap();
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
        assert!(store.get("../../etc/passwd").await.is_err());
        let mut bad = request("true");
        bad.exec.command = "/no/such/program".into();
        assert!(store.start(bad).await.is_err());
        assert!(!temp.path().join(ID).exists());
        store.start(request("sleep 60")).await.unwrap();
        assert!(store.start(request("true")).await.is_err());
        store.cancel(ID).await.unwrap();
        finished(&store).await;
    }
}
