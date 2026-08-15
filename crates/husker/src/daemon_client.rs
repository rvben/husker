//! Client-side adapter for the husker daemon HTTP seam.
//!
//! Command modules describe an HTTP operation; this module owns the transport
//! policy shared by every operation: base-URL resolution, bearer
//! authentication, connection diagnostics, and decoding the daemon's stable
//! error envelope. Keeping those concerns here prevents command orchestration
//! from depending on raw `reqwest` setup.

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use husker_api::{
    AddPortForwardRequest, ErrorResponse, ExecRequest, ExecResponse, GuestInfoResponse,
    PortForwardResponse, ProfilesResponse, ReadFileRequest, ReadFileResponse, ReadyResponse,
    VmResponse, WriteFileRequest, WriteFileResponse,
};

use crate::schema::exit_code;

/// Conservative decoded payload size for one guest-file write. The daemon's
/// default policy accepts up to 1 MiB, but that configured limit is not yet
/// exposed to clients, so uploads stay comfortably below the default.
pub(crate) const FILE_WRITE_CHUNK_BYTES: usize = 512 * 1024;

/// A failure returned by the daemon and suitable for the CLI error envelope.
#[derive(Debug, Clone)]
pub(crate) struct ApiFailure {
    pub(crate) message: String,
    pub(crate) kind: Option<String>,
    pub(crate) exit_code: i32,
    pub(crate) hint: Option<String>,
}

impl ApiFailure {
    /// Preserve structured daemon failures and connection classification when
    /// an operation has travelled through `anyhow` orchestration.
    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        if let Some(failure) = error.downcast_ref::<Self>() {
            return failure.clone();
        }
        if error.chain().any(|cause| cause.is::<DaemonUnreachable>()) {
            return Self {
                message: format!("{error:#}"),
                kind: Some("daemon_unreachable".into()),
                exit_code: exit_code::DAEMON_UNREACHABLE,
                hint: None,
            };
        }
        Self {
            message: format!("{error:#}"),
            kind: None,
            exit_code: exit_code::GENERAL,
            hint: None,
        }
    }
}

impl fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiFailure {}

impl From<String> for ApiFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            kind: None,
            exit_code: exit_code::GENERAL,
            hint: None,
        }
    }
}

impl From<&str> for ApiFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// Marker attached to connection failures so the process adapter can select
/// the stable daemon-unreachable exit code.
#[derive(Debug)]
pub(crate) struct DaemonUnreachable;

impl fmt::Display for DaemonUnreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("daemon unreachable")
    }
}

impl std::error::Error for DaemonUnreachable {}

/// Reusable adapter for one resolved daemon target.
///
/// Cloning this value reuses reqwest's connection pool. The base URL and token
/// travel with the client, so command modules cannot accidentally authenticate
/// one target with another target's policy.
#[derive(Clone, Debug)]
pub(crate) struct DaemonClient {
    http: reqwest::Client,
    base_url: String,
    api_token: Option<String>,
}

/// A guest-file read either carries a contract-checked slice or the daemon's
/// structured refusal. The payload-size distinction is retained because it
/// selects the one useful compatibility diagnostic the CLI can perform.
#[derive(Debug)]
pub(crate) enum FileReadOutcome {
    Read(ReadFileResponse),
    Failed {
        failure: ApiFailure,
        payload_too_large: bool,
    },
}

/// Result of the backward-compatible profiles probe. Only an absent endpoint
/// or an unreachable older daemon counts as unavailable; a malformed success
/// response is contract drift and remains an error.
#[derive(Debug)]
pub(crate) enum ProfilesOutcome {
    Available(ProfilesResponse),
    Unavailable,
}

impl DaemonClient {
    pub(crate) fn new(base_url: impl Into<String>, api_token: Option<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: normalize_base_url(base_url.into()),
            api_token,
        }
    }

    pub(crate) fn with_timeout(
        base_url: impl Into<String>,
        api_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(timeout).build()?,
            base_url: normalize_base_url(base_url.into()),
            api_token,
        })
    }

    pub(crate) fn get(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    pub(crate) fn post(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    pub(crate) fn put(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::PUT, path)
    }

    pub(crate) fn delete(&self, path: impl AsRef<str>) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::DELETE, path)
    }

    /// Fetch one VM through the daemon's shared wire contract.
    ///
    /// The route, subject used for daemon failures, and response DTO belong to
    /// this operation. Callers receive a VM, not a transport response they have
    /// to interpret independently.
    pub(crate) async fn vm(&self, name: &str) -> Result<VmResponse> {
        self.execute_json(self.get(format!("/v1/vms/{name}")), &format!("VM '{name}'"))
            .await
    }

    /// Execute a command in a VM and require the daemon's complete exec result.
    pub(crate) async fn exec(&self, name: &str, request: &ExecRequest) -> Result<ExecResponse> {
        self.execute_json(
            self.post(format!("/v1/vms/{name}/exec")).json(request),
            &format!("VM '{name}'"),
        )
        .await
    }

    /// Read one byte range from a guest file through the shared API contract.
    pub(crate) async fn read_file(
        &self,
        name: &str,
        path: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<FileReadOutcome> {
        let request = ReadFileRequest {
            path: path.to_string(),
            offset,
            len,
        };
        let subject = format!("VM '{name}'");
        let response = self
            .send(
                self.post(format!("/v1/vms/{name}/files/read"))
                    .json(&request),
            )
            .await?;
        if !response.status().is_success() {
            let payload_too_large = response.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE;
            return Ok(FileReadOutcome::Failed {
                failure: self.error(response, &subject).await,
                payload_too_large,
            });
        }
        let body: ReadFileResponse = self.decode_json(response, &subject).await?;
        let decoded_size = husker_agent_proto::base64_decode(&body.data)
            .map_err(|error| anyhow::anyhow!("{subject} returned invalid base64: {error}"))?
            .len() as u64;
        anyhow::ensure!(
            body.size == decoded_size,
            "{subject} file response reports {} bytes but contains {decoded_size}",
            body.size
        );
        Ok(FileReadOutcome::Read(body))
    }

    /// Fetch the readiness state without allowing a missing `ready` field to
    /// become a false value.
    pub(crate) async fn ready(&self, name: &str) -> Result<ReadyResponse> {
        self.execute_json(
            self.get(format!("/v1/vms/{name}/ready")),
            &format!("VM '{name}'"),
        )
        .await
    }

    /// Fetch the guest-agent feature contract for one VM.
    pub(crate) async fn guest_info(&self, name: &str) -> Result<GuestInfoResponse> {
        self.execute_json(
            self.get(format!("/v1/vms/{name}/guest-info")),
            &format!("VM '{name}'"),
        )
        .await
    }

    /// Write one guest-file chunk and require the daemon to report the number
    /// of bytes accepted.
    pub(crate) async fn write_file(
        &self,
        name: &str,
        request: &WriteFileRequest,
    ) -> Result<WriteFileResponse> {
        let expected = husker_agent_proto::base64_decode(&request.data)
            .map_err(|error| {
                anyhow::anyhow!("file-write request contained invalid base64: {error}")
            })?
            .len() as u64;
        let response: WriteFileResponse = self
            .execute_json(
                self.post(format!("/v1/vms/{name}/files/write"))
                    .json(request),
                &format!("VM '{name}'"),
            )
            .await?;
        anyhow::ensure!(
            response.bytes_written == expected,
            "VM '{name}' reported writing {} of {expected} bytes to {}",
            response.bytes_written,
            request.path
        );
        Ok(response)
    }

    /// Write a complete byte buffer, splitting large files into append-mode
    /// requests after verifying that the guest agent supports them.
    pub(crate) async fn write_file_bytes(
        &self,
        name: &str,
        path: &str,
        data: &[u8],
        mode: Option<u32>,
    ) -> Result<u64> {
        if data.len() <= FILE_WRITE_CHUNK_BYTES {
            return Ok(self
                .write_file(
                    name,
                    &WriteFileRequest {
                        path: path.to_string(),
                        data: husker_agent_proto::base64_encode(data),
                        mode,
                        append: false,
                    },
                )
                .await?
                .bytes_written);
        }

        let protocol_version = self.guest_info(name).await?.protocol_version;
        let required = husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND;
        anyhow::ensure!(
            protocol_version >= required,
            "cannot write a file larger than {FILE_WRITE_CHUNK_BYTES} bytes to VM '{name}': \
             the guest agent reports protocol version {protocol_version}, but chunked writes \
             require version {required} or newer. The VM image predates append support; \
             rebuild or re-import it with a current husker-agent"
        );

        let mut bytes_written = 0u64;
        for (index, chunk) in data.chunks(FILE_WRITE_CHUNK_BYTES).enumerate() {
            bytes_written += self
                .write_file(
                    name,
                    &WriteFileRequest {
                        path: path.to_string(),
                        data: husker_agent_proto::base64_encode(chunk),
                        mode,
                        append: index > 0,
                    },
                )
                .await?
                .bytes_written;
        }
        Ok(bytes_written)
    }

    /// Add a host-to-guest port mapping and return the daemon's effective bind.
    /// A requested host port of zero is intentionally not a usable fallback:
    /// only the daemon knows which port it actually bound.
    pub(crate) async fn add_port_forward(
        &self,
        name: &str,
        host_port: u16,
        guest_port: u16,
        bind_addr: Option<&str>,
    ) -> Result<PortForwardResponse> {
        let request = AddPortForwardRequest {
            host_port,
            guest_port,
            bind_addr: bind_addr.map(str::to_string),
        };
        self.execute_json(
            self.post(format!("/v1/vms/{name}/ports")).json(&request),
            &format!("VM '{name}'"),
        )
        .await
    }

    pub(crate) async fn profiles(&self) -> Result<ProfilesOutcome> {
        let response = match self.try_send(self.get("/v1/profiles")).await {
            Ok(response) => response,
            Err(_) => return Ok(ProfilesOutcome::Unavailable),
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(ProfilesOutcome::Unavailable);
        }
        if !response.status().is_success() {
            return Err(self.error(response, "listing daemon profiles").await.into());
        }
        Ok(ProfilesOutcome::Available(
            self.decode_json(response, "listing daemon profiles")
                .await?,
        ))
    }

    fn request(&self, method: reqwest::Method, path: impl AsRef<str>) -> reqwest::RequestBuilder {
        let request = self.http.request(method, self.url(path.as_ref()));
        match self.api_token.as_deref() {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    /// Send a request through this adapter, enriching connection failures with
    /// the resolved target and a stable marker for exit-code selection.
    pub(crate) async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        request.send().await.map_err(|error| {
            if error.is_connect() {
                anyhow::Error::new(DaemonUnreachable).context(format!(
                    "cannot connect to daemon at {}\n\
                     hint: start it with `husker daemon`, or point at a running daemon via \
                     --api-url / HUSKER_API_URL",
                    self.base_url
                ))
            } else {
                anyhow::anyhow!(error)
            }
        })
    }

    /// Send without translating transport errors. This is reserved for
    /// compatibility probes where an unreachable daemon intentionally means
    /// "feature unavailable" rather than a command failure.
    pub(crate) async fn try_send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> std::result::Result<reqwest::Response, reqwest::Error> {
        request.send().await
    }

    /// Decode a non-success response into the CLI's stable failure model.
    pub(crate) async fn error(&self, response: reqwest::Response, subject: &str) -> ApiFailure {
        let status = response.status();
        let exit_code = match status.as_u16() {
            404 => exit_code::NOT_FOUND,
            409 => exit_code::CONFLICT,
            401 | 403 => exit_code::DENIED,
            _ => exit_code::GENERAL,
        };
        let mut kind = None;
        let mut hint = None;
        let message = match response.text().await {
            Ok(body) if !body.is_empty() => {
                if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                    kind = Some(error.kind);
                    hint = error.hint;
                    error.message
                } else {
                    match serde_json::from_str::<serde_json::Value>(&body) {
                        Ok(json) => json["error"].as_str().map(String::from).unwrap_or(body),
                        Err(_) => body,
                    }
                }
            }
            _ => match status.as_u16() {
                404 => format!("{subject} not found"),
                409 => format!("{subject} already exists"),
                _ => format!("{subject}: {status}"),
            },
        };
        ApiFailure {
            message,
            kind,
            exit_code,
            hint,
        }
    }

    /// Complete an operation whose success response is part of the daemon's
    /// JSON contract. Keeping status handling and strict DTO decoding together
    /// prevents each command from inventing its own fallback semantics.
    async fn execute_json<T>(&self, request: reqwest::RequestBuilder, subject: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send(request).await?;
        if !response.status().is_success() {
            return Err(self.error(response, subject).await.into());
        }
        self.decode_json(response, subject).await
    }

    async fn decode_json<T>(&self, response: reqwest::Response, subject: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        response
            .json::<T>()
            .await
            .with_context(|| format!("daemon returned an invalid response for {subject}"))
    }

    fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{path}", self.base_url)
        } else {
            format!("{}/{path}", self.base_url)
        }
    }
}

fn normalize_base_url(mut base_url: String) -> String {
    while base_url.ends_with('/') {
        base_url.pop();
    }
    base_url
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::extract::Json as ExtractJson;
    use axum::http::StatusCode;
    use axum::routing::get;
    use serde_json::json;

    use super::*;

    async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn request_joins_paths_and_applies_bearer_auth() {
        let client = DaemonClient::new("http://example.invalid/", Some("secret".into()));
        let request = client.get("/v1/health").build().unwrap();

        assert_eq!(request.url().as_str(), "http://example.invalid/v1/health");
        assert_eq!(
            request.headers()[reqwest::header::AUTHORIZATION],
            "Bearer secret"
        );
    }

    #[test]
    fn request_without_token_has_no_authorization_header() {
        let client = DaemonClient::new("http://example.invalid", None);
        let request = client.get("v1/health").build().unwrap();

        assert_eq!(request.url().as_str(), "http://example.invalid/v1/health");
        assert!(
            !request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );
    }

    #[test]
    fn absolute_looking_path_cannot_redirect_credentials_to_another_host() {
        let client = DaemonClient::new("http://daemon.invalid", Some("secret".into()));
        let request = client
            .get("https://attacker.invalid/collect")
            .build()
            .unwrap();

        assert_eq!(
            request.url().as_str(),
            "http://daemon.invalid/https://attacker.invalid/collect"
        );
    }

    #[tokio::test]
    async fn send_reuses_target_in_connection_diagnostic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let base_url = format!("http://{address}");
        let client = DaemonClient::with_timeout(&base_url, None, Duration::from_secs(2)).unwrap();

        let error = client.send(client.get("/v1/health")).await.unwrap_err();

        assert!(error.chain().any(|cause| cause.is::<DaemonUnreachable>()));
        assert!(format!("{error:#}").contains(&base_url));
        let failure = ApiFailure::from_error(&error);
        assert_eq!(failure.kind.as_deref(), Some("daemon_unreachable"));
        assert_eq!(failure.exit_code, exit_code::DAEMON_UNREACHABLE);
    }

    #[tokio::test]
    async fn error_decodes_stable_daemon_envelope() {
        let app = axum::Router::new().route(
            "/v1/fail",
            get(|| async {
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "kind": "vm_conflict",
                        "message": "VM is busy",
                        "hint": "stop it first"
                    })),
                )
            }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let response = client.send(client.get("/v1/fail")).await.unwrap();

        let failure = client.error(response, "VM 'x'").await;

        assert_eq!(failure.kind.as_deref(), Some("vm_conflict"));
        assert_eq!(failure.exit_code, exit_code::CONFLICT);
        assert_eq!(failure.message, "VM is busy");
        assert_eq!(failure.hint.as_deref(), Some("stop it first"));
        task.abort();
    }

    #[tokio::test]
    async fn error_falls_back_for_empty_not_found_response() {
        let app = axum::Router::new().route("/v1/missing", get(|| async { StatusCode::NOT_FOUND }));
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let response = client.send(client.get("/v1/missing")).await.unwrap();

        let failure = client.error(response, "VM 'ghost'").await;

        assert_eq!(failure.exit_code, exit_code::NOT_FOUND);
        assert_eq!(failure.message, "VM 'ghost' not found");
        task.abort();
    }

    #[tokio::test]
    async fn error_preserves_legacy_json_and_plain_text_messages() {
        let app = axum::Router::new()
            .route(
                "/v1/legacy",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "backend exploded" })),
                    )
                }),
            )
            .route(
                "/v1/plain",
                get(|| async { (StatusCode::BAD_GATEWAY, "gateway timeout") }),
            );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let legacy = client.send(client.get("/v1/legacy")).await.unwrap();
        assert_eq!(
            client.error(legacy, "running VM").await.message,
            "backend exploded"
        );

        let plain = client.send(client.get("/v1/plain")).await.unwrap();
        assert_eq!(
            client.error(plain, "running VM").await.message,
            "gateway timeout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn error_maps_denied_conflict_and_generic_empty_responses() {
        let app = axum::Router::new()
            .route("/v1/denied", get(|| async { StatusCode::FORBIDDEN }))
            .route("/v1/conflict", get(|| async { StatusCode::CONFLICT }))
            .route(
                "/v1/failure",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let denied = client.send(client.get("/v1/denied")).await.unwrap();
        assert_eq!(
            client.error(denied, "VM").await.exit_code,
            exit_code::DENIED
        );

        let conflict = client.send(client.get("/v1/conflict")).await.unwrap();
        let conflict = client.error(conflict, "VM 'demo'").await;
        assert_eq!(conflict.exit_code, exit_code::CONFLICT);
        assert_eq!(conflict.message, "VM 'demo' already exists");

        let failure = client.send(client.get("/v1/failure")).await.unwrap();
        assert_eq!(
            client.error(failure, "creating VM").await.message,
            "creating VM: 500 Internal Server Error"
        );
        task.abort();
    }

    #[tokio::test]
    async fn vm_read_owns_its_route_and_decodes_the_shared_contract() {
        let app = axum::Router::new().route(
            "/v1/vms/demo",
            get(|| async {
                Json(json!({
                    "id": "vm-1",
                    "name": "demo",
                    "state": "running",
                    "pid": 42,
                    "vcpu_count": 2,
                    "mem_size_mib": 512,
                    "vsock_cid": 7,
                    "host_ip": "172.16.0.1",
                    "guest_ip": "172.16.0.2",
                    "created_at": "2026-08-13T00:00:00Z",
                    "updated_at": "2026-08-13T00:00:01Z",
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
                    "suspended_at": null
                }))
            }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let vm = client.vm("demo").await.unwrap();

        assert_eq!(vm.name, "demo");
        assert_eq!(vm.boot_mode, husker_core::BootKind::DirectKernel);
        task.abort();
    }

    #[tokio::test]
    async fn vm_read_rejects_a_response_that_drifted_from_the_shared_contract() {
        let app = axum::Router::new().route(
            "/v1/vms/demo",
            get(|| async { Json(json!({ "id": "vm-1", "name": "demo" })) }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let error = client.vm("demo").await.unwrap_err();

        assert!(format!("{error:#}").contains("invalid response for VM 'demo'"));
        task.abort();
    }

    #[tokio::test]
    async fn file_read_sends_the_shared_request_and_requires_the_shared_response() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/files/read",
            axum::routing::post(
                |ExtractJson(request): ExtractJson<serde_json::Value>| async move {
                    assert_eq!(request["path"], "/tmp/result");
                    assert_eq!(request["offset"], 12);
                    assert_eq!(request["len"], 64);
                    Json(json!({
                        "data": "aGVsbG8=",
                        "size": 5,
                        "total_size": 17,
                        "modified_nanos": 99
                    }))
                },
            ),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let file = client
            .read_file("demo", "/tmp/result", 12, Some(64))
            .await
            .unwrap();

        let FileReadOutcome::Read(file) = file else {
            panic!("expected a file slice");
        };
        assert_eq!(file.size, 5);
        assert_eq!(file.total_size, Some(17));
        task.abort();
    }

    #[tokio::test]
    async fn file_read_rejects_a_size_that_disagrees_with_its_data() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/files/read",
            axum::routing::post(|| async {
                Json(json!({
                    "data": "aGVsbG8=",
                    "size": 4,
                    "total_size": 5,
                    "modified_nanos": 99
                }))
            }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let error = client
            .read_file("demo", "/tmp/result", 0, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("reports 4 bytes but contains 5"));
        task.abort();
    }

    #[tokio::test]
    async fn exec_rejects_a_success_response_without_an_exit_code() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/exec",
            axum::routing::post(|| async { Json(json!({ "stdout": "ok", "stderr": "" })) }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let request = husker_api::ExecRequest {
            command: "true".into(),
            args: Vec::new(),
            working_dir: None,
            env: std::collections::HashMap::new(),
            secret_env: std::collections::HashMap::new(),
            connect_timeout_secs: None,
            timeout_secs: None,
        };

        let error = client.exec("demo", &request).await.unwrap_err();

        assert!(format!("{error:#}").contains("invalid response for VM 'demo'"));
        task.abort();
    }

    #[tokio::test]
    async fn file_write_rejects_a_partial_success() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/files/write",
            axum::routing::post(|| async { Json(json!({ "bytes_written": 2 })) }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let request = WriteFileRequest {
            path: "/tmp/result".into(),
            data: husker_agent_proto::base64_encode(b"hello"),
            mode: None,
            append: false,
        };

        let error = client.write_file("demo", &request).await.unwrap_err();

        assert!(format!("{error:#}").contains("reported writing 2 of 5 bytes"));
        task.abort();
    }

    #[tokio::test]
    async fn complete_file_write_chunks_large_payloads_in_order() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&writes);
        let app = axum::Router::new()
            .route(
                "/v1/vms/demo/guest-info",
                get(|| async {
                    Json(json!({
                        "ipv4": [],
                        "protocol_version": husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND,
                    }))
                }),
            )
            .route(
                "/v1/vms/demo/files/write",
                axum::routing::post(
                    move |ExtractJson(request): ExtractJson<serde_json::Value>| {
                        let captured = Arc::clone(&captured);
                        async move {
                            let len = husker_agent_proto::base64_decode(
                                request["data"].as_str().unwrap(),
                            )
                            .unwrap()
                            .len();
                            captured.lock().unwrap().push(request);
                            Json(json!({ "bytes_written": len }))
                        }
                    },
                ),
            );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let data = vec![0x5a; FILE_WRITE_CHUNK_BYTES + 17];

        let bytes = client
            .write_file_bytes("demo", "/tmp/archive.tar.gz", &data, Some(0o600))
            .await
            .unwrap();

        assert_eq!(bytes, data.len() as u64);
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0]["path"], "/tmp/archive.tar.gz");
        assert_eq!(writes[0]["append"], false);
        assert_eq!(writes[1]["append"], true);
        assert_eq!(writes[0]["mode"], 0o600);
        assert_eq!(
            husker_agent_proto::base64_decode(writes[0]["data"].as_str().unwrap())
                .unwrap()
                .len(),
            FILE_WRITE_CHUNK_BYTES
        );
        assert_eq!(
            husker_agent_proto::base64_decode(writes[1]["data"].as_str().unwrap())
                .unwrap()
                .len(),
            17
        );
        task.abort();
    }

    #[tokio::test]
    async fn complete_file_write_refuses_large_payload_for_legacy_agent() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/guest-info",
            get(|| async {
                Json(json!({
                    "ipv4": [],
                    "protocol_version": husker_agent_proto::MIN_PROTOCOL_VERSION_FOR_APPEND - 1,
                }))
            }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);
        let data = vec![0; FILE_WRITE_CHUNK_BYTES + 1];

        let error = client
            .write_file_bytes("demo", "/tmp/archive.tar.gz", &data, None)
            .await
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("protocol version"));
        assert!(message.contains("predates append support"));
        task.abort();
    }

    #[tokio::test]
    async fn port_forward_add_rejects_an_incomplete_success_payload() {
        let app = axum::Router::new().route(
            "/v1/vms/demo/ports",
            axum::routing::post(|| async { Json(json!({ "host_port": 49152 })) }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let error = client
            .add_port_forward("demo", 0, 8080, Some("127.0.0.1"))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("invalid response for VM 'demo'"));
        task.abort();
    }

    #[tokio::test]
    async fn profiles_probe_does_not_disguise_a_malformed_success_as_unavailable() {
        let app = axum::Router::new().route(
            "/v1/profiles",
            get(|| async { Json(json!({ "profiles": "not-an-object" })) }),
        );
        let (base_url, task) = serve(app).await;
        let client = DaemonClient::new(base_url, None);

        let error = client.profiles().await.unwrap_err();

        assert!(format!("{error:#}").contains("invalid response for listing daemon profiles"));
        task.abort();
    }
}
