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
