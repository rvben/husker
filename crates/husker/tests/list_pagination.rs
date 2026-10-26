//! `husker list` paging against a stub daemon. A daemon that pages applies
//! `limit`/`offset` itself and reports the fleet size in `X-Total-Count`; an
//! older daemon returns every VM. The CLI prints the same page either way.
#![cfg(not(feature = "linux-net"))]

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, Request, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// The whole fleet the stub daemon knows, in creation order.
fn fleet() -> Vec<Value> {
    (0..3)
        .map(|i| {
            json!({
                "name": format!("vm-{i}"),
                "state": "running",
                "vcpu_count": 1,
                "mem_size_mib": 128,
                "guest_ip": format!("192.0.2.{}", 10 + i),
            })
        })
        .collect()
}

struct Stub {
    /// Whether the daemon applies `limit`/`offset` and reports `X-Total-Count`.
    pages: bool,
    /// Every request as (path, query string).
    requests: Mutex<Vec<(String, String)>>,
}

async fn handle(State(stub): State<Arc<Stub>>, request: Request<Body>) -> axum::response::Response {
    let query = request.uri().query().unwrap_or("").to_string();
    stub.requests
        .lock()
        .unwrap()
        .push((request.uri().path().to_string(), query.clone()));
    let fleet = fleet();
    if !stub.pages {
        return (StatusCode::OK, axum::Json(Value::Array(fleet))).into_response();
    }
    let param = |key: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
            .map(|value| value.parse::<usize>().unwrap())
    };
    let offset = param("offset").unwrap_or(0);
    let limit = param("limit").unwrap_or(usize::MAX);
    let total = fleet.len();
    let page: Vec<Value> = fleet.into_iter().skip(offset).take(limit).collect();
    (
        StatusCode::OK,
        [(HeaderName::from_static("x-total-count"), total.to_string())],
        axum::Json(Value::Array(page)),
    )
        .into_response()
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
    async fn new(pages: bool) -> Self {
        let stub = Arc::new(Stub {
            pages,
            requests: Mutex::new(Vec::new()),
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

    /// Run `husker list` with the given output format against the stub daemon.
    async fn invoke(&self, format: &str, args: &[&str]) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_husker"))
            .args(["--api-url", &self.url, "--output", format, "--config"])
            .arg(self.temp.path().join("config.toml"))
            .arg("list")
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

    /// Run `husker list`, require success and return its stdout.
    async fn run(&self, format: &str, args: &[&str]) -> String {
        let output = self.invoke(format, args).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    async fn list(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.run("json", args).await).unwrap()
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.stub.requests.lock().unwrap().clone()
    }
}

async fn assert_second_vm_is_the_page(fixture: &Fixture) {
    let page = fixture.list(&["--limit", "1", "--offset", "1"]).await;
    assert_eq!(page["items"], json!([fleet()[1]]));
    assert_eq!(page["total"], 3);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 1);
    assert_eq!(page["daemon_reachable"], true);

    // Field selection is applied by the CLI and never reaches the daemon.
    let names = fixture
        .list(&["--limit", "1", "--offset", "1", "--fields", "name"])
        .await;
    assert_eq!(names["items"], json!([{"name": "vm-1"}]));
    assert_eq!(names["total"], 3);

    let expected = ("/v1/vms".to_string(), "limit=1&offset=1".to_string());
    assert_eq!(fixture.requests(), vec![expected.clone(), expected]);
}

#[tokio::test]
async fn list_prints_the_page_a_paging_daemon_returns() {
    let fixture = Fixture::new(true).await;
    assert_second_vm_is_the_page(&fixture).await;
}

#[tokio::test]
async fn list_cuts_the_page_itself_for_a_daemon_that_returns_the_whole_fleet() {
    let fixture = Fixture::new(false).await;
    assert_second_vm_is_the_page(&fixture).await;
}

#[tokio::test]
async fn list_rejects_an_unknown_field_before_asking_the_daemon() {
    let fixture = Fixture::new(true).await;

    let output = fixture
        .invoke("json", &["--fields", "name,nosuchfield"])
        .await;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let envelope: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(envelope["error"]["kind"], "invalid_usage");
    assert_eq!(
        envelope["error"]["message"],
        "unknown field `nosuchfield` in --fields"
    );
    let hint = envelope["error"]["hint"].as_str().unwrap();
    assert!(
        hint.starts_with("valid fields: id, name, state, "),
        "{hint}"
    );
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn text_output_says_when_the_page_is_not_the_whole_fleet() {
    let fixture = Fixture::new(true).await;

    let first_page = fixture.run("text", &["--limit", "2"]).await;
    let lines: Vec<&str> = first_page.lines().collect();
    assert!(lines[0].starts_with("NAME"), "{first_page}");
    assert!(lines[1].starts_with("vm-0"), "{first_page}");
    assert!(lines[2].starts_with("vm-1"), "{first_page}");
    assert_eq!(
        lines[3],
        "2 of 3 VMs shown; use --offset 2 for the next page"
    );
    assert_eq!(lines.len(), 4);

    let last_page = fixture
        .run("text", &["--limit", "2", "--offset", "2"])
        .await;
    assert!(last_page.lines().nth(1).unwrap().starts_with("vm-2"));
    assert_eq!(last_page.lines().count(), 2, "{last_page}");

    let past_the_end = fixture.run("text", &["--offset", "5"]).await;
    assert_eq!(
        past_the_end.trim_end(),
        "No VMs at offset 5; the fleet has 3"
    );
}
