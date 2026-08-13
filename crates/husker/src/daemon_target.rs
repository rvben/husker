//! Daemon target selection and transport lifecycle.
//!
//! A [`ResolvedDaemonTarget`] represents user intent before any transport side
//! effect. Connecting it produces a [`DaemonTarget`] that owns the authenticated
//! daemon adapter and, for `ssh://`, the tunnel guard for exactly the same
//! lifetime. Locality remains a property of the selected host rather than the
//! tunnel's loopback endpoint.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::daemon_client::DaemonClient;

pub(crate) const DEFAULT_API_URL: &str = "http://127.0.0.1:7777";
const SSH_REMOTE_DAEMON_PORT: u16 = 7777;

/// A saved daemon target: a name mapped to an HTTP(S) or SSH URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContextEntry {
    pub(crate) api_url: String,
}

/// Named daemon targets plus the currently selected one.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Contexts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) current: Option<String>,
    #[serde(default)]
    pub(crate) contexts: BTreeMap<String, ContextEntry>,
}

pub(crate) fn contexts_path() -> PathBuf {
    if let Some(path) = std::env::var_os("HUSKER_CONTEXTS_FILE") {
        return PathBuf::from(path);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".config/husker/contexts.toml")
}

/// Load saved contexts, or an empty set if the optional file is absent or
/// unreadable. An explicitly selected missing context is still rejected during
/// resolution.
pub(crate) fn load_contexts() -> Contexts {
    std::fs::read_to_string(contexts_path())
        .ok()
        .and_then(|contents| toml::from_str(&contents).ok())
        .unwrap_or_default()
}

pub(crate) fn save_contexts(contexts: &Contexts) -> Result<()> {
    let path = contexts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(contexts).context("serializing contexts")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))
}

#[derive(Debug)]
enum ResolvedTransport {
    Direct,
    Ssh(SshTarget),
}

/// A validated target selection before an SSH process or HTTP client exists.
#[derive(Debug)]
pub(crate) struct ResolvedDaemonTarget {
    selected_url: String,
    transport: ResolvedTransport,
    local: bool,
}

impl ResolvedDaemonTarget {
    /// Resolve target precedence: explicit URL, explicitly named context,
    /// current context, then the local default.
    pub(crate) fn resolve(
        explicit_api_url: Option<&str>,
        context_name: Option<&str>,
        contexts: &Contexts,
    ) -> Result<Self> {
        let selected = if let Some(url) = explicit_api_url {
            url.to_string()
        } else if let Some(name) = context_name {
            contexts
                .contexts
                .get(name)
                .ok_or_else(|| {
                    anyhow::anyhow!("unknown context '{name}' (list with `husker context list`)")
                })?
                .api_url
                .clone()
        } else if let Some(entry) = contexts
            .current
            .as_deref()
            .and_then(|name| contexts.contexts.get(name))
        {
            entry.api_url.clone()
        } else {
            DEFAULT_API_URL.to_string()
        };
        Self::parse(selected)
    }

    pub(crate) fn parse(selected_url: String) -> Result<Self> {
        if selected_url.starts_with("ssh://") {
            return Ok(Self {
                transport: ResolvedTransport::Ssh(parse_ssh_url(&selected_url)?),
                selected_url,
                local: false,
            });
        }

        let parsed = reqwest::Url::parse(&selected_url)
            .with_context(|| format!("invalid daemon API URL '{selected_url}'"))?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https"),
            "daemon API URL must use http://, https://, or ssh://"
        );
        anyhow::ensure!(
            parsed.query().is_none() && parsed.fragment().is_none(),
            "daemon API URL cannot contain a query or fragment"
        );
        let host = parsed
            .host_str()
            .context("daemon API URL is missing a host")?;
        let ip_host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        let local = host.eq_ignore_ascii_case("localhost")
            || ip_host
                .parse::<IpAddr>()
                .map(|address| address.is_loopback())
                .unwrap_or(false);
        Ok(Self {
            selected_url,
            transport: ResolvedTransport::Direct,
            local,
        })
    }

    #[cfg(test)]
    fn selected_url(&self) -> &str {
        &self.selected_url
    }

    pub(crate) fn is_local(&self) -> bool {
        self.local
    }

    pub(crate) async fn connect(self, api_token: Option<String>) -> Result<DaemonTarget> {
        let local = self.local;
        match self.transport {
            ResolvedTransport::Direct => {
                let api_url = self.selected_url.trim_end_matches('/').to_string();
                let daemon = DaemonClient::new(&api_url, api_token.clone());
                Ok(DaemonTarget {
                    api_url,
                    api_token,
                    daemon,
                    local,
                    _tunnel: None,
                })
            }
            ResolvedTransport::Ssh(target) => {
                let tunnel = SshTunnel::establish(target).await?;
                let api_url = tunnel.local_url();
                let daemon = DaemonClient::new(&api_url, api_token.clone());
                Ok(DaemonTarget {
                    api_url,
                    api_token,
                    daemon,
                    local: false,
                    _tunnel: Some(tunnel),
                })
            }
        }
    }
}

/// A connected target session. Dropping it tears down any SSH tunnel after the
/// last command operation has released the embedded daemon adapter.
pub(crate) struct DaemonTarget {
    api_url: String,
    api_token: Option<String>,
    daemon: DaemonClient,
    local: bool,
    _tunnel: Option<SshTunnel>,
}

impl DaemonTarget {
    pub(crate) fn daemon(&self) -> &DaemonClient {
        &self.daemon
    }

    pub(crate) fn api_url(&self) -> &str {
        &self.api_url
    }

    pub(crate) fn api_token(&self) -> Option<&str> {
        self.api_token.as_deref()
    }

    pub(crate) fn is_local(&self) -> bool {
        self.local
    }

    pub(crate) fn client_with_timeout(&self, timeout: Duration) -> Result<DaemonClient> {
        DaemonClient::with_timeout(&self.api_url, self.api_token.clone(), timeout)
    }
}

/// Validate a URL before persisting it as a named context.
pub(crate) fn validate_context_url(url: &str) -> Result<()> {
    ResolvedDaemonTarget::parse(url.to_string()).map(|_| ())
}

/// A parsed `ssh://[user@]host[:sshport]` target.
#[derive(Debug, PartialEq, Eq)]
struct SshTarget {
    user: Option<String>,
    host: String,
    ssh_port: Option<u16>,
}

fn parse_ssh_url(url: &str) -> Result<SshTarget> {
    let rest = url
        .strip_prefix("ssh://")
        .context("API URL must start with ssh://")?;
    anyhow::ensure!(
        !rest.contains(['/', '?', '#']),
        "ssh:// daemon URL cannot contain a path, query, or fragment"
    );
    let (user, hostport) = match rest.split_once('@') {
        Some((user, hostport)) => {
            anyhow::ensure!(!user.is_empty(), "ssh:// URL has an empty user");
            (Some(user.to_string()), hostport)
        }
        None => (None, rest),
    };
    let (host, ssh_port) = match hostport.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .with_context(|| format!("invalid ssh port in ssh:// URL: {port}"))?;
            (host.to_string(), Some(port))
        }
        None => (hostport.to_string(), None),
    };
    anyhow::ensure!(!host.is_empty(), "ssh:// URL is missing a host");
    anyhow::ensure!(
        !host.chars().any(char::is_whitespace),
        "ssh:// URL host cannot contain whitespace"
    );
    anyhow::ensure!(ssh_port != Some(0), "ssh:// URL port must be non-zero");
    Ok(SshTarget {
        user,
        host,
        ssh_port,
    })
}

fn ssh_tunnel_args(target: &SshTarget, local_port: u16, remote_port: u16) -> Vec<String> {
    let mut args = vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "LogLevel=ERROR".to_string(),
        "-L".to_string(),
        format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"),
    ];
    if let Some(port) = target.ssh_port {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    args.push(match &target.user {
        Some(user) => format!("{user}@{}", target.host),
        None => target.host.clone(),
    });
    args
}

static SSH_TUNNEL_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn register_ssh_tunnel_for_atexit(pid: i32) {
    SSH_TUNNEL_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| unsafe {
        libc::atexit(kill_ssh_tunnel_atexit);
    });
}

extern "C" fn kill_ssh_tunnel_atexit() {
    let pid = SSH_TUNNEL_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        // Safety: kill(2) is async-signal-safe and valid from an atexit handler.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

struct SshTunnel {
    child: tokio::process::Child,
    local_port: u16,
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        SSH_TUNNEL_PID.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SshTunnel {
    async fn establish(target: SshTarget) -> Result<Self> {
        let local_port = reserve_local_port()?;
        let args = ssh_tunnel_args(&target, local_port, SSH_REMOTE_DAEMON_PORT);
        let mut command = tokio::process::Command::new("ssh");
        command
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .context("spawning ssh for the ssh:// tunnel (is the ssh client installed?)")?;
        if let Some(pid) = child.id() {
            register_ssh_tunnel_for_atexit(pid as i32);
        }
        let mut tunnel = Self { child, local_port };
        tunnel.wait_ready().await?;
        Ok(tunnel)
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                anyhow::bail!(
                    "ssh tunnel exited before it was ready (status {status}); check that you can \
                     `ssh` to the host and the daemon listens on \
                     127.0.0.1:{SSH_REMOTE_DAEMON_PORT}"
                );
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", self.local_port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("timed out establishing the ssh:// tunnel to the daemon");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }
}

fn reserve_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("reserving a local port for the ssh:// tunnel")?;
    Ok(listener.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(url: &str) -> ContextEntry {
        ContextEntry {
            api_url: url.to_string(),
        }
    }

    #[test]
    fn resolution_precedence_and_fallback_are_deterministic() {
        let mut contexts = Contexts {
            current: Some("current".into()),
            ..Contexts::default()
        };
        contexts
            .contexts
            .insert("current".into(), context("http://localhost:7777"));
        contexts
            .contexts
            .insert("named".into(), context("ssh://user@host"));

        let explicit = ResolvedDaemonTarget::resolve(
            Some("https://example.test:7777"),
            Some("named"),
            &contexts,
        )
        .unwrap();
        assert_eq!(explicit.selected_url(), "https://example.test:7777");

        let named = ResolvedDaemonTarget::resolve(None, Some("named"), &contexts).unwrap();
        assert_eq!(named.selected_url(), "ssh://user@host");

        let current = ResolvedDaemonTarget::resolve(None, None, &contexts).unwrap();
        assert_eq!(current.selected_url(), "http://localhost:7777");

        let fallback = ResolvedDaemonTarget::resolve(None, None, &Contexts::default()).unwrap();
        assert_eq!(fallback.selected_url(), DEFAULT_API_URL);
    }

    #[test]
    fn explicit_unknown_context_is_an_error_but_stale_current_falls_back() {
        let error =
            ResolvedDaemonTarget::resolve(None, Some("missing"), &Contexts::default()).unwrap_err();
        assert!(error.to_string().contains("missing"));

        let contexts = Contexts {
            current: Some("missing".into()),
            ..Contexts::default()
        };
        let target = ResolvedDaemonTarget::resolve(None, None, &contexts).unwrap();
        assert_eq!(target.selected_url(), DEFAULT_API_URL);
    }

    #[test]
    fn locality_uses_the_parsed_host_and_survives_transport_selection() {
        assert!(
            ResolvedDaemonTarget::parse("http://127.0.0.2:7777".into())
                .unwrap()
                .is_local()
        );
        assert!(
            ResolvedDaemonTarget::parse("http://[::1]:7777".into())
                .unwrap()
                .is_local()
        );
        assert!(
            !ResolvedDaemonTarget::parse("http://localhost.example:7777".into())
                .unwrap()
                .is_local()
        );
        assert!(
            !ResolvedDaemonTarget::parse("ssh://localhost".into())
                .unwrap()
                .is_local()
        );
    }

    #[test]
    fn invalid_or_unsupported_urls_fail_before_transport_side_effects() {
        assert!(ResolvedDaemonTarget::parse("not a url".into()).is_err());
        assert!(ResolvedDaemonTarget::parse("ftp://host/path".into()).is_err());
        assert!(ResolvedDaemonTarget::parse("ssh://".into()).is_err());
        assert!(ResolvedDaemonTarget::parse("ssh://@host".into()).is_err());
        assert!(ResolvedDaemonTarget::parse("ssh://host/path".into()).is_err());
        assert!(ResolvedDaemonTarget::parse("http://host?token=bad".into()).is_err());
    }

    #[test]
    fn ssh_parsing_and_args_preserve_user_port_and_dedicated_lifetime() {
        let target = parse_ssh_url("ssh://ubuntu@192.0.2.5:2222").unwrap();
        assert_eq!(target.user.as_deref(), Some("ubuntu"));
        assert_eq!(target.host, "192.0.2.5");
        assert_eq!(target.ssh_port, Some(2222));

        let args = ssh_tunnel_args(&target, 15000, 7777);
        assert!(
            args.windows(2).any(|values| {
                values[0] == "-L" && values[1] == "127.0.0.1:15000:127.0.0.1:7777"
            })
        );
        assert!(
            args.windows(2)
                .any(|values| values[0] == "-p" && values[1] == "2222")
        );
        assert_eq!(args.last().map(String::as_str), Some("ubuntu@192.0.2.5"));
        assert!(!args.iter().any(|arg| arg.starts_with("ControlPersist=")));
        assert!(!args.iter().any(|arg| arg == "ControlMaster=auto"));
    }

    #[test]
    fn contexts_roundtrip_toml() {
        let mut contexts = Contexts {
            current: Some("linux".into()),
            ..Contexts::default()
        };
        contexts
            .contexts
            .insert("linux".into(), context("ssh://ubuntu@host"));
        let encoded = toml::to_string_pretty(&contexts).unwrap();
        assert_eq!(toml::from_str::<Contexts>(&encoded).unwrap(), contexts);
    }

    #[tokio::test]
    async fn direct_connection_owns_normalized_authenticated_adapter() {
        let target = ResolvedDaemonTarget::parse("http://localhost:7777/".into())
            .unwrap()
            .connect(Some("secret".into()))
            .await
            .unwrap();

        assert!(target.is_local());
        assert_eq!(target.api_url(), "http://localhost:7777");
        assert_eq!(target.api_token(), Some("secret"));
        let request = target.daemon().get("/v1/health").build().unwrap();
        assert_eq!(request.url().as_str(), "http://localhost:7777/v1/health");
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer secret")
        );
    }
}
