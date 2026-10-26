//! A client whose stdout reader has gone away. A `husker` command ends the way
//! `cat` does, by the SIGPIPE the kernel raises for the first write after the
//! reader closed; a job keeps that write as an error so its VM is still
//! destroyed, and then fails without a panic.

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

/// The write end of a pipe whose read end is already closed, so the very
/// first write to it fails rather than filling a buffer.
fn closed_pipe_writer() -> OwnedFd {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe(2) fills exactly the two descriptors `fds` has room for.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe(2): {}", std::io::Error::last_os_error());
    // SAFETY: pipe(2) just returned both descriptors and nothing else owns them.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(reader);
    writer
}

/// `husker` with its stdout already unreadable, isolated from any saved
/// context or live daemon on the developer's machine.
fn husker_with_closed_stdout(temp: &std::path::Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_husker"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(closed_pipe_writer()))
        .stderr(Stdio::piped())
        .env_remove("HUSKER_CONTEXT")
        .env("HUSKER_CONTEXTS_FILE", temp.join("contexts.toml"))
        .env("HUSKER_DATA_DIR", temp.join("data"));
    command
}

/// Run the command and collect its status and stderr. `Command::output` would
/// replace the configured stdout with a pipe of its own, which is exactly the
/// reader these tests must not have.
async fn finish(command: &mut tokio::process::Command) -> std::process::Output {
    command.spawn().unwrap().wait_with_output().await.unwrap()
}

#[tokio::test]
async fn a_client_command_ends_by_sigpipe_without_a_word() {
    let temp = tempfile::tempdir().unwrap();
    let output = finish(husker_with_closed_stdout(temp.path()).arg("schema")).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGPIPE),
        "status {:?}, stderr: {stderr}",
        output.status
    );
    assert!(
        stderr.is_empty(),
        "a reader that went away is not worth reporting: {stderr}"
    );
}

/// The job stub needs no host backend; the `linux-net` build adds a local
/// Firecracker preflight that would refuse before the daemon is asked.
#[cfg(not(feature = "linux-net"))]
mod job {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::{
            State,
            ws::{Message, WebSocketUpgrade},
        },
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    type Requests = Arc<Mutex<Vec<(String, String)>>>;

    /// The REST side of a daemon that boots, readies, runs and destroys the
    /// one job VM a test asks for, recording every request so the test can
    /// see what the job did.
    async fn handle(
        State(requests): State<Requests>,
        request: Request<Body>,
    ) -> axum::response::Response {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        requests
            .lock()
            .unwrap()
            .push((method.clone(), path.clone()));
        let body = match (method.as_str(), path.as_str()) {
            ("GET", "/v1/profiles") => json!({ "profiles": {} }),
            ("POST", "/v1/vms") => {
                return (StatusCode::CREATED, axum::Json(json!({}))).into_response();
            }
            ("GET", "/v1/vms/job-x") => json!({
                "id": "vm-job-x",
                "name": "job-x",
                "state": "running",
                "pid": 42,
                "vcpu_count": 1,
                "mem_size_mib": 128,
                "vsock_cid": 7,
                "host_ip": null,
                "guest_ip": null,
                "created_at": "2026-08-13T00:00:00Z",
                "updated_at": "2026-08-13T00:00:00Z",
                "userdata_status": null,
                "vmm": "firecracker",
                "boot_mode": "direct",
                "rootfs_path": "/images/rootfs.ext4",
                "kernel_path": "/images/vmlinux",
                "volume": null,
                "network": "nat",
                "idle_timeout_secs": null,
                "suspend_ttl_secs": null,
                "auto_resume": null,
                "suspended_at": null,
            }),
            ("GET", "/v1/vms/job-x/ready") => json!({ "vm": "job-x", "ready": true }),
            ("POST", "/v1/vms/job-x/exec") => {
                json!({ "exit_code": 0, "stdout": "", "stderr": "" })
            }
            ("DELETE", "/v1/vms/job-x") => return StatusCode::NO_CONTENT.into_response(),
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({
                        "kind": "not_found",
                        "message": format!("the stub does not serve {method} {path}"),
                    })),
                )
                    .into_response();
            }
        };
        axum::Json(body).into_response()
    }

    /// The streamed exec a text-mode job uses: one line of output, then the
    /// exit. The job's first write of that line is what hits the closed pipe.
    async fn stream(State(requests): State<Requests>, ws: WebSocketUpgrade) -> impl IntoResponse {
        requests
            .lock()
            .unwrap()
            .push(("GET".into(), "/v1/vms/job-x/exec/stream".into()));
        ws.on_upgrade(|mut socket| async move {
            let start = socket.recv().await.unwrap().unwrap();
            assert!(matches!(start, Message::Text(_)));
            for output in [
                husker_api::WsExecOutput::Started {
                    streaming: Some(true),
                    guest_protocol_version: Some(4),
                },
                husker_api::WsExecOutput::Stdout {
                    data: husker_agent_proto::base64_encode(b"live\n"),
                },
                husker_api::WsExecOutput::Exit { exit_code: 0 },
            ] {
                let frame = Message::Text(serde_json::to_string(&output).unwrap().into());
                // The job may already have hung up after its write failed.
                if socket.send(frame).await.is_err() {
                    break;
                }
            }
        })
    }

    struct Daemon {
        requests: Requests,
        url: String,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Daemon {
        async fn serve() -> Self {
            let requests: Requests = Arc::default();
            let app = Router::new()
                .route("/v1/vms/job-x/exec/stream", get(stream))
                .fallback(handle)
                .with_state(requests.clone());
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                requests,
                url,
                server,
            }
        }

        /// Run `husker job --name job-x job-image -- true` in `format` with
        /// stdout already unreadable.
        async fn job(&self, format: &str) -> std::process::Output {
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("config.toml"), "").unwrap();
            finish(
                husker_with_closed_stdout(temp.path())
                    .args(["--api-url", &self.url, "--output", format, "--config"])
                    .arg(temp.path().join("config.toml"))
                    .args(["job", "--name", "job-x", "job-image", "--", "true"]),
            )
            .await
        }

        fn destroyed_the_job_vm(&self) -> bool {
            self.requests
                .lock()
                .unwrap()
                .contains(&("DELETE".into(), "/v1/vms/job-x".into()))
        }

        fn requests(&self) -> Vec<(String, String)> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// The job must have destroyed its VM, ended by its own exit code rather
    /// than a signal, and named the undelivered output instead of panicking.
    fn assert_cleaned_up_and_failed(daemon: &Daemon, output: &std::process::Output) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            daemon.destroyed_the_job_vm(),
            "the job must destroy its VM even though nobody reads its output: {:?}\n{stderr}",
            daemon.requests()
        );
        assert_eq!(
            output.status.signal(),
            None,
            "a job must not die by SIGPIPE before its cleanup: {stderr}"
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "undelivered output is a failure, not a panic: {stderr}"
        );
        assert!(
            !stderr.contains("panicked"),
            "a closed stdout is an error, not a panic: {stderr}"
        );
        assert!(
            stderr.contains("could not be written to stdout"),
            "the failure must say the output went undelivered: {stderr}"
        );
    }

    /// Text output streams the command's output as it happens, so the pipe
    /// breaks while the VM is still running and cleanup is still to come.
    #[tokio::test]
    async fn a_streaming_job_still_destroys_its_vm_then_fails_without_a_panic() {
        let daemon = Daemon::serve().await;
        let output = daemon.job("text").await;
        assert_cleaned_up_and_failed(&daemon, &output);
        assert!(
            daemon
                .requests()
                .contains(&("GET".into(), "/v1/vms/job-x/exec/stream".into())),
            "a text job streams its output: {:?}",
            daemon.requests()
        );
    }

    /// JSON output is one document written after the VM is already gone, so
    /// the only thing left to get right is failing instead of panicking.
    #[tokio::test]
    async fn a_json_job_reports_an_undelivered_result_without_a_panic() {
        let daemon = Daemon::serve().await;
        let output = daemon.job("json").await;
        assert_cleaned_up_and_failed(&daemon, &output);
    }
}
