#![cfg(not(feature = "linux-net"))]
//! Error kinds the CLI raises itself, checked on the real binary against a
//! stub daemon that records every request it receives. A refusal the CLI
//! makes up front must leave the daemon untouched; the same command in its
//! supported form must reach it.

use std::process::Output;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    response::IntoResponse,
};
use serde_json::Value;
use tempfile::TempDir;

/// Answers a request given its method and its path with query string.
type Responder = Arc<dyn Fn(&str, &str) -> (StatusCode, String) + Send + Sync>;

struct Stub {
    requests: Mutex<Vec<(String, String)>>,
    respond: Responder,
}

async fn handle(State(stub): State<Arc<Stub>>, request: Request<Body>) -> axum::response::Response {
    let method = request.method().to_string();
    let target = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    stub.requests
        .lock()
        .unwrap()
        .push((method.clone(), target.clone()));
    let (status, body) = (stub.respond)(&method, &target);
    let content_type = if body.starts_with('{') {
        "application/json"
    } else {
        "text/plain"
    };
    (status, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// A daemon that knows no route; the answer every refusal test expects to
/// stay unused.
fn no_route(_method: &str, _target: &str) -> (StatusCode, String) {
    (
        StatusCode::NOT_FOUND,
        r#"{"kind":"route_not_found","message":"no such route"}"#.into(),
    )
}

struct Fixture {
    url: String,
    temp: TempDir,
    stub: Arc<Stub>,
}

impl Fixture {
    async fn start(
        respond: impl Fn(&str, &str) -> (StatusCode, String) + Send + Sync + 'static,
    ) -> Self {
        let stub = Arc::new(Stub {
            requests: Mutex::new(Vec::new()),
            respond: Arc::new(respond),
        });
        let app = Router::new().fallback(handle).with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), "").unwrap();
        Self { url, temp, stub }
    }

    /// A target no daemon listens on: a port that was bound and released.
    async fn unreachable() -> Self {
        let mut fixture = Self::start(no_route).await;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        fixture.url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        fixture
    }

    /// Run the CLI against the stub with the given arguments after the
    /// connection flags; `--output` goes in `args` so a test states it.
    async fn husker(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_husker"))
            .args(["--api-url", &self.url, "--config"])
            .arg(self.temp.path().join("config.toml"))
            .args(args)
            .env_remove("HUSKER_CONTEXT")
            .env(
                "HUSKER_CONTEXTS_FILE",
                self.temp.path().join("contexts.toml"),
            )
            .env("HUSKER_DATA_DIR", self.temp.path().join("data"))
            .output()
            .await
            .unwrap()
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.stub.requests.lock().unwrap().clone()
    }
}

/// The error envelope, which the contract puts on the last line of stderr.
fn envelope(output: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let last = stderr.lines().last().unwrap_or_default();
    serde_json::from_str(last)
        .unwrap_or_else(|_| panic!("the last stderr line is not an envelope:\n{stderr}"))
}

/// Assert a command was refused as `invalid_usage` before any request and
/// return its hint.
async fn refused_up_front(args: &[&str]) -> String {
    let fixture = Fixture::start(no_route).await;
    let output = fixture.husker(args).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The request log is checked first: a refusal that happens after a round
    // trip can still exit 2 by coincidence (a 404 from the stub), so the log
    // is what tells "refused up front" from "failed later".
    assert!(
        fixture.requests().is_empty(),
        "{args:?} reached the daemon before refusing: {:?}",
        fixture.requests()
    );
    assert_eq!(output.status.code(), Some(2), "{args:?}:\n{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "invalid_usage", "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
    error["hint"]
        .as_str()
        .unwrap_or_else(|| panic!("{args:?} refused without a hint"))
        .to_owned()
}

#[tokio::test]
async fn following_logs_as_json_is_refused_before_any_request() {
    let hint = refused_up_front(&["--output", "json", "logs", "vm", "--follow"]).await;
    assert!(hint.contains("--follow"), "{hint}");
}

#[tokio::test]
async fn following_a_non_serial_log_as_json_is_refused_like_the_serial_one() {
    // The logs route only follows the serial console, so the CLI drops
    // --follow for other sources; the refusal still applies to what was asked.
    refused_up_front(&["--output", "json", "logs", "vm", "--follow", "--userdata"]).await;
}

#[tokio::test]
async fn following_session_events_as_json_is_refused_before_any_request() {
    let hint = refused_up_front(&["--output", "json", "events", "vm", "sid", "--follow"]).await;
    assert!(hint.contains("--after"), "{hint}");
}

#[tokio::test]
async fn a_preview_tunnel_has_no_json_form() {
    let hint = refused_up_front(&["--output", "json", "preview", "vm", "8080"]).await;
    assert!(hint.contains("--output text"), "{hint}");
}

#[tokio::test]
async fn a_shell_without_a_terminal_is_refused_before_any_request() {
    // The fixture runs the binary with stdin closed, which is what a pipe or
    // a CI job gives a shell: no terminal to bridge. A shell has only a text
    // form, so the refusal must be the terminal one, not the JSON one.
    let hint = refused_up_front(&["--output", "text", "shell", "vm"]).await;
    assert!(hint.contains("`husker exec`"), "{hint}");
}

#[tokio::test]
async fn a_log_snapshot_keeps_its_json_form() {
    let fixture = Fixture::start(|method, target| {
        if method == "GET" && target.starts_with("/v1/vms/vm/logs?") {
            (StatusCode::OK, "boot ok\n".into())
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture
        .husker(&["--output", "json", "logs", "vm", "--tail", "5"])
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["action"], "logs");
    assert_eq!(document["follow"], false);
    assert_eq!(document["logs"], "boot ok\n");
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn a_vm_that_never_reports_ready_times_out_under_its_own_kind() {
    let fixture = Fixture::start(|method, target| {
        if method == "GET" && target == "/v1/vms/vm/ready" {
            (StatusCode::OK, r#"{"vm":"vm","ready":false}"#.into())
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture
        .husker(&["--output", "json", "wait", "vm", "--timeout", "1"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "timeout", "{stderr}");
    assert_eq!(
        error["message"],
        "timed out after 1s waiting for VM 'vm' to become ready"
    );
    assert!(error["hint"].as_str().unwrap().contains("--timeout"));
    assert!(output.stdout.is_empty());
    assert!(
        fixture
            .requests()
            .iter()
            .all(|(_, target)| target == "/v1/vms/vm/ready"),
        "{:?}",
        fixture.requests()
    );
}

#[tokio::test]
async fn a_command_the_daemon_timed_out_is_reported_as_a_timeout() {
    let fixture = Fixture::start(|method, target| {
        if method == "POST" && target == "/v1/vms/vm/exec" {
            (
                StatusCode::REQUEST_TIMEOUT,
                concat!(
                    r#"{"kind":"exec_timeout","#,
                    r#""message":"command execution timed out and the agent did not respond","#,
                    r#""hint":"increase exec timeout policy or optimize guest command runtime"}"#
                )
                .into(),
            )
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture
        .husker(&["--output", "json", "exec", "vm", "--", "sleep", "999"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "timeout", "{stderr}");
    assert_eq!(
        error["message"],
        "command execution timed out and the agent did not respond"
    );
    assert_eq!(
        error["hint"],
        "increase exec timeout policy or optimize guest command runtime"
    );
    assert!(output.stdout.is_empty());
}

/// A daemon whose exec route reports a command that ended with `exit_code`.
fn exec_ended_with(
    exit_code: i32,
) -> impl Fn(&str, &str) -> (StatusCode, String) + Send + Sync + 'static {
    move |method, target| {
        if method == "POST" && target == "/v1/vms/vm/exec" {
            (
                StatusCode::OK,
                format!(r#"{{"exit_code":{exit_code},"stdout":"","stderr":"boom\n"}}"#),
            )
        } else {
            no_route(method, target)
        }
    }
}

/// A guest exit code is the command's result, not a tool failure, so it must
/// never be wrapped in an error envelope.
fn assert_no_envelope(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .lines()
            .last()
            .is_none_or(|last| serde_json::from_str::<Value>(last).is_err()),
        "a guest exit code must not be reported as a tool error:\n{stderr}"
    );
}

#[tokio::test]
async fn a_guest_command_that_fails_is_reported_as_its_own_result() {
    let fixture = Fixture::start(exec_ended_with(3)).await;
    let output = fixture
        .husker(&["--output", "json", "exec", "vm", "--", "false"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let document: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("stdout is not one JSON document:\n{stderr}"));
    assert_eq!(document["status"], "error", "{document}");
    assert_eq!(document["action"], "exec");
    assert_eq!(document["result"]["exit_code"], 3);
    assert_eq!(document["result"]["stderr"], "boom\n");
    assert_no_envelope(&output);
}

#[tokio::test]
async fn an_unreachable_daemon_carries_its_remedy_in_the_hint() {
    let fixture = Fixture::unreachable().await;
    let output = fixture.husker(&["--output", "json", "info", "vm"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "daemon_unreachable", "{stderr}");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.starts_with("cannot connect to daemon at http://127.0.0.1:"),
        "{message}"
    );
    assert!(
        !message.contains("hint"),
        "the remedy belongs in the hint field, not the message: {message}"
    );
    assert!(
        error["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("`husker daemon`")),
        "{error}"
    );
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn text_output_prints_the_hint_on_its_own_line() {
    let fixture = Fixture::unreachable().await;
    let output = fixture.husker(&["--output", "text", "info", "vm"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(5), "{stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert!(
        lines[0].starts_with("Error: cannot connect to daemon at "),
        "{stderr}"
    );
    let printed_hint = lines
        .iter()
        .find_map(|line| line.strip_prefix("hint: "))
        .unwrap_or_else(|| panic!("no hint line:\n{stderr}"));
    // The envelope stays the last line and carries the same hint.
    assert_eq!(envelope(&output)["error"]["hint"], printed_hint, "{stderr}");
    assert!(printed_hint.contains("`husker daemon`"), "{printed_hint}");
}

/// The daemon's refusal of a lifecycle command for a VM in the wrong state,
/// as `map_error` renders `CoreError::InvalidState`.
fn wrong_state(vm: &str, actual: &str, expected: &str) -> (StatusCode, String) {
    (
        StatusCode::CONFLICT,
        serde_json::json!({
            "kind": "invalid_state",
            "message": format!("VM '{vm}' is {actual}, expected {expected}"),
            "details": {"vm": vm, "actual": actual, "expected": expected},
        })
        .to_string(),
    )
}

#[tokio::test]
async fn a_hint_the_cli_adds_keeps_the_daemons_message_intact() {
    let fixture = Fixture::start(|method, target| {
        if method == "POST" && target == "/v1/vms/vm/pause" {
            wrong_state("vm", "stopped", "running")
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture.husker(&["--output", "json", "pause", "vm"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "conflict", "{stderr}");
    assert_eq!(
        error["message"], "VM 'vm' is stopped, expected running",
        "{stderr}"
    );
    assert_eq!(
        error["hint"], "start the VM first with `husker run`",
        "{stderr}"
    );
}

/// The remedy is chosen by the state the daemon's details name. A VM whose
/// name mentions a state, refused for being in another, gets no advice for
/// the state in its name; a refusal that names no state gets none at all.
#[tokio::test]
async fn a_state_remedy_follows_the_refusal_details_not_the_message() {
    let fixture = Fixture::start(|method, target| {
        match (method, target) {
        ("POST", "/v1/vms/stopped-worker/resume") => {
            wrong_state("stopped-worker", "creating", "paused or suspended")
        }
        ("POST", "/v1/vms/vm/suspend") => (
            StatusCode::CONFLICT,
            r#"{"kind":"invalid_state","message":"VM 'vm' is stopped, expected running or paused"}"#
                .into(),
        ),
        _ => no_route(method, target),
    }
    })
    .await;

    let output = fixture
        .husker(&["--output", "json", "resume", "stopped-worker"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(
        error["message"], "VM 'stopped-worker' is creating, expected paused or suspended",
        "{stderr}"
    );
    assert!(error.get("hint").is_none(), "{stderr}");

    let output = fixture.husker(&["--output", "json", "suspend", "vm"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(
        error["message"], "VM 'vm' is stopped, expected running or paused",
        "{stderr}"
    );
    assert!(error.get("hint").is_none(), "{stderr}");
}

/// A daemon that refuses VM creation with `kind`, as it does for a request
/// argument its own validation rejects.
fn creation_refused_with(kind: &'static str) -> impl Fn(&str, &str) -> (StatusCode, String) {
    move |method, target| {
        if method == "POST" && target == "/v1/vms" {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    concat!(
                        r#"{{"kind":"{}","#,
                        r#""message":"invalid argument: vmm \"qemu\" was requested, but this daemon runs apple_vz only","#,
                        r#""hint":"omit --vmm to use the daemon's backend"}}"#
                    ),
                    kind
                ),
            )
        } else {
            no_route(method, target)
        }
    }
}

#[tokio::test]
async fn a_request_argument_the_daemon_rejected_is_invalid_usage() {
    let fixture = Fixture::start(creation_refused_with("invalid_argument")).await;
    let output = fixture
        .husker(&["--output", "json", "run", "--vmm", "qemu", "--name", "vm"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a request the daemon rejected exits like a flag the parser rejected: {stderr}"
    );
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "invalid_usage", "{stderr}");
    assert_eq!(
        error["message"],
        "invalid argument: vmm \"qemu\" was requested, but this daemon runs apple_vz only",
        "{stderr}"
    );
    assert_eq!(
        error["hint"], "omit --vmm to use the daemon's backend",
        "{stderr}"
    );
    assert!(
        fixture
            .requests()
            .contains(&("POST".to_string(), "/v1/vms".to_string())),
        "the refusal came from the daemon: {:?}",
        fixture.requests()
    );
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn a_daemon_400_kind_the_cli_does_not_list_is_still_invalid_usage() {
    let fixture = Fixture::start(creation_refused_with("invalid_mount_spec")).await;
    let output = fixture
        .husker(&["--output", "json", "run", "--vmm", "qemu", "--name", "vm"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(
        error["kind"], "invalid_usage",
        "the status classifies a kind outside the CLI vocabulary: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

/// A VM name already taken gets the way to free it. The CLI recognises that
/// refusal by its kind: another conflict whose message happens to say
/// "already exists" is not it.
#[tokio::test]
async fn a_taken_vm_name_is_told_how_to_free_it() {
    let fixture = Fixture::start(|method, target| {
        if method == "POST" && target == "/v1/vms" {
            (
                StatusCode::CONFLICT,
                r#"{"kind":"vm_already_exists","message":"VM 'vm' already exists"}"#.into(),
            )
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture
        .husker(&["--output", "json", "run", "--vmm", "qemu", "--name", "vm"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["kind"], "conflict", "{stderr}");
    assert_eq!(error["message"], "VM 'vm' already exists", "{stderr}");
    assert_eq!(
        error["hint"],
        "if it is suspended, resume it with `husker resume vm`; \
         otherwise stop or destroy it first with `husker destroy vm`",
        "{stderr}"
    );

    let fixture = Fixture::start(|method, target| {
        if method == "POST" && target == "/v1/vms" {
            (
                StatusCode::CONFLICT,
                r#"{"kind":"image_already_exists","message":"image 'vm' already exists"}"#.into(),
            )
        } else {
            no_route(method, target)
        }
    })
    .await;
    let output = fixture
        .husker(&["--output", "json", "run", "--vmm", "qemu", "--name", "vm"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let error = &envelope(&output)["error"];
    assert_eq!(error["message"], "image 'vm' already exists", "{stderr}");
    assert!(error.get("hint").is_none(), "{stderr}");
}

#[tokio::test]
async fn a_guest_command_that_succeeds_is_reported_ok() {
    let fixture = Fixture::start(exec_ended_with(0)).await;
    let output = fixture
        .husker(&["--output", "json", "exec", "vm", "--", "true"])
        .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["status"], "ok", "{document}");
    assert_eq!(document["result"]["exit_code"], 0);
    assert_no_envelope(&output);
}
