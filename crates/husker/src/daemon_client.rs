//! Client-side adapter for the husker daemon HTTP seam.
//!
//! Command modules describe an HTTP operation; this module owns the transport
//! policy shared by every operation: base-URL resolution, bearer
//! authentication, connection diagnostics, and decoding the daemon's stable
//! error envelope. Keeping those concerns here prevents command orchestration
//! from depending on raw `reqwest` setup.

use std::fmt;
use std::time::Duration;

use anyhow::Result;

use crate::schema::exit_code;

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
        let message = match response.text().await {
            Ok(body) if !body.is_empty() => {
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(json) => {
                        kind = json["kind"].as_str().map(String::from);
                        if let Some(message) = json["message"].as_str() {
                            match json["hint"].as_str() {
                                Some(hint) => format!("{message} (hint: {hint})"),
                                None => message.to_string(),
                            }
                        } else if let Some(message) = json["error"].as_str() {
                            message.to_string()
                        } else {
                            body
                        }
                    }
                    Err(_) => body,
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
            hint: None,
        }
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
    use axum::Json;
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
        assert_eq!(failure.message, "VM is busy (hint: stop it first)");
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
}
