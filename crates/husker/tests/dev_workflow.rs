//! CLI workflows against a stub daemon; no host image/backend provisioning.
//! The no-linux-net contract build skips local Firecracker installation checks.
#![cfg(not(feature = "linux-net"))]

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Stub {
    requests: Mutex<Vec<(String, String, Value)>>,
    image_exists: bool,
    fail_setup: bool,
}
async fn handle(State(stub): State<Arc<Stub>>, request: Request<Body>) -> axum::response::Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let bytes = to_bytes(request.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    stub.requests
        .lock()
        .unwrap()
        .push((method.clone(), path.clone(), body));
    let (status, value) = if path.starts_with("/v1/images/") && method == "GET" {
        if stub.image_exists {
            (StatusCode::OK, json!({"name":"husker-dev"}))
        } else {
            (
                StatusCode::NOT_FOUND,
                json!({"kind":"image_not_found", "message":"missing"}),
            )
        }
    } else if path == "/v1/profiles" {
        (StatusCode::OK, json!({"profiles":{}}))
    } else if path.ends_with("/exec") {
        (
            StatusCode::OK,
            json!({"exit_code":if stub.fail_setup {1} else {0}, "stdout":"tools ready", "stderr":""}),
        )
    } else if path.ends_with("/sessions") {
        (
            StatusCode::CREATED,
            json!({
                "id":"01234567-89ab-cdef-0123-456789abcdef", "command":"runuser", "state":"running", "created_at":1,
                "finished_at":null,"exit_code":null,"output_truncated":false,
            }),
        )
    } else if method == "DELETE" {
        return StatusCode::NO_CONTENT.into_response();
    } else {
        (StatusCode::OK, json!({"name":"test", "state":"running"}))
    };
    (status, axum::Json(value)).into_response()
}

struct Fixture {
    stub: Arc<Stub>,
    url: String,
    server: tokio::task::JoinHandle<()>,
    temp: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(image_exists: bool, fail_setup: bool) -> Self {
        let stub = Arc::new(Stub {
            image_exists,
            fail_setup,
            ..Default::default()
        });
        let app = Router::new().fallback(handle).with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), "").unwrap();
        Self {
            stub,
            url,
            server,
            temp,
        }
    }
    async fn run(&self, args: &[&str]) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_husker"))
            .args(["--api-url", &self.url, "--output", "json", "--config"])
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
}

#[tokio::test]
async fn prepare_provisions_then_stops_commits_and_removes_only_its_builder() {
    let f = Fixture::new(false, false).await;
    let output = f.run(&["dev", "prepare", "--image", "dev-v1"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["action"], "dev-prepare");
    let requests = f.stub.requests.lock().unwrap();
    let create = requests
        .iter()
        .find(|(_, path, _)| path == "/v1/vms")
        .unwrap();
    assert_eq!(create.2["rootfs_path"], "ubuntu:24.04");
    assert_eq!(create.2["mem_size_mib"], 4096);
    assert_eq!(create.2["disk_size"], 20_u64 * 1024 * 1024 * 1024);
    let name = create.2["name"].as_str().unwrap();
    assert!(name.starts_with("dev-builder-"));
    let stop = requests
        .iter()
        .position(|(_, path, _)| path.ends_with("/stop"))
        .unwrap();
    let commit = requests
        .iter()
        .position(|(_, path, _)| path.ends_with("/commit-image"))
        .unwrap();
    let destroy = requests
        .iter()
        .position(|(method, _, _)| method == "DELETE")
        .unwrap();
    assert!(stop < commit && commit < destroy);
    assert_eq!(requests[commit].2, json!({"name":"dev-v1"}));
    assert_eq!(requests[destroy].1, format!("/v1/vms/{name}"));
}

#[tokio::test]
async fn preparation_refuses_existing_image_and_retains_failed_builder() {
    let exists = Fixture::new(true, false).await;
    assert!(!exists.run(&["dev", "prepare"]).await.status.success());
    assert!(
        !exists
            .stub
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, path, _)| path == "/v1/vms")
    );
    let failed = Fixture::new(false, true).await;
    let result = failed.run(&["dev", "prepare"]).await;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("retained for inspection"));
    assert!(
        !failed
            .stub
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(method, path, _)| method == "DELETE" || path.ends_with("/commit-image"))
    );
}

#[tokio::test]
async fn prompt_starts_detached_with_literal_prompt_and_secret_reference() {
    let f = Fixture::new(false, false).await;
    let prompt = "fix $HOME; $(whoami) without shell interpolation";
    let result = f
        .run(&[
            "prompt",
            "dev",
            prompt,
            "--secret",
            "OPENAI_API_KEY=agent-key",
        ])
        .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(output["session"]["state"], "running");
    let requests = f.stub.requests.lock().unwrap();
    let start = requests
        .iter()
        .find(|(_, path, _)| path.ends_with("/sessions"))
        .unwrap();
    assert_eq!(start.2["command"], "runuser");
    assert_eq!(start.2["args"].as_array().unwrap().last().unwrap(), prompt);
    assert_eq!(start.2["working_dir"], "/workspace");
    assert_eq!(start.2["env"]["CARGO_HOME"], "/opt/cargo");
    assert_eq!(start.2["secret_env"]["OPENAI_API_KEY"], "agent-key");
}
