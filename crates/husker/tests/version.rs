//! `husker version` against a stub daemon. A daemon whose state store cannot
//! be read withholds the VM counts from `/v1/health`; the CLI must pass that
//! absence through instead of printing an empty fleet.
#![cfg(not(feature = "linux-net"))]

use axum::{Router, extract::State, routing::get};
use serde_json::{Value, json};

struct Fixture {
    url: String,
    server: tokio::task::JoinHandle<()>,
    temp: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn serve_health(State(health): State<Value>) -> axum::Json<Value> {
    axum::Json(health)
}

impl Fixture {
    /// Serve `health` as the daemon's `/v1/health` report.
    async fn new(health: Value) -> Self {
        let app = Router::new()
            .route("/v1/health", get(serve_health))
            .with_state(health);
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("config.toml"), "").unwrap();
        Self { url, server, temp }
    }

    /// Run `husker version` in the given output format and return its stdout.
    async fn version(&self, format: &str) -> String {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_husker"))
            .args(["--api-url", &self.url, "--output", format, "--config"])
            .arg(self.temp.path().join("config.toml"))
            .arg("version")
            .env_remove("HUSKER_CONTEXT")
            .env(
                "HUSKER_CONTEXTS_FILE",
                self.temp.path().join("contexts.toml"),
            )
            .env("HUSKER_DATA_DIR", self.temp.path().join("data"))
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
}

/// A daemon health report whose fleet counts are `vms`: an object with
/// `total` and `running`, or null when the state store could not be read.
fn health(vms: Value) -> Value {
    let state_db = if vms.is_null() { "degraded" } else { "ok" };
    json!({
        "status": state_db,
        "version": "9.9.9",
        "vms": vms,
        "checks": { "state_db": state_db, "vmm_backend": "ok", "network_backend": "n/a" },
        "uptime_seconds": 1,
        "backend": "firecracker",
        "capabilities": {
            "fork": false,
            "snapshot": false,
            "oci_import": false,
            "port_forward": true,
            "bridged_net": false,
        },
    })
}

#[tokio::test]
async fn version_reports_the_daemon_fleet_counts() {
    let fixture = Fixture::new(health(json!({ "total": 3, "running": 2 }))).await;

    let json: Value = serde_json::from_str(&fixture.version("json").await).unwrap();
    assert_eq!(json["client_version"], env!("CARGO_PKG_VERSION"), "{json}");
    assert_eq!(
        json["daemon"],
        json!({ "version": "9.9.9", "vms_total": 3, "vms_running": 2 }),
        "{json}"
    );

    assert_eq!(
        fixture.version("text").await,
        format!(
            "husker {}\ndaemon 9.9.9 (3 VMs, 2 running)\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[tokio::test]
async fn version_passes_withheld_fleet_counts_through() {
    let fixture = Fixture::new(health(Value::Null)).await;

    let json: Value = serde_json::from_str(&fixture.version("json").await).unwrap();
    assert_eq!(
        json["daemon"],
        json!({ "version": "9.9.9", "vms_total": null, "vms_running": null }),
        "withheld counts must stay null, never read as zero: {json}"
    );

    assert_eq!(
        fixture.version("text").await,
        format!(
            "husker {}\ndaemon 9.9.9 (VM counts unavailable)\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}
