//! Request extractors whose rejections use the API error envelope.
//!
//! axum's own extractors answer a request they cannot parse with a plain-text
//! body, so the one class of failure a client always causes itself was the
//! one it could not branch on: no `kind`, no `message` field, nothing the CLI
//! or the SDK could map. Every extractor in this crate goes through these
//! wrappers, which delegate the parsing to axum and only translate the
//! rejection. The status codes stay axum's (400 for a syntax error, 422 for a
//! body of the wrong shape, 413 over the size limit, 415 without a JSON
//! content type, 426 for a WebSocket route opened without an upgrade), so no
//! consumer sees a status change, only a body it can read. The same module
//! answers for a path no route claims and for a method a route does not
//! accept, which axum would otherwise leave as an empty body.

use std::error::Error as _;
use std::ops::{Deref, DerefMut};

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::current_policy;
use crate::errors::{error_response, error_response_with_hint};

/// A request the API refused before any handler ran, carrying the status axum
/// assigned and the envelope fields a client branches on.
#[derive(Debug)]
pub(crate) struct Rejection {
    status: StatusCode,
    kind: &'static str,
    message: String,
    hint: Option<&'static str>,
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let body = match self.hint {
            Some(hint) => error_response_with_hint(self.kind, self.message, hint),
            None => error_response(self.kind, self.message),
        };
        (self.status, body).into_response()
    }
}

/// A JSON request body, or a JSON response body.
///
/// Mirrors `axum::Json` in both roles so a handler reads the same whether it
/// takes or returns one; only the rejection differs.
#[derive(Debug)]
pub(crate) struct Json<T>(pub T);

impl<S, T> FromRequest<S> for Json<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Rejection;

    async fn from_request(request: Request, state: &S) -> Result<Self, Rejection> {
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(rejection)),
        }
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Typed path parameters of a matched route.
#[derive(Debug)]
pub(crate) struct Path<T>(pub T);

impl<S, T> FromRequestParts<S> for Path<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(path_rejection(rejection)),
        }
    }
}

/// Typed query parameters.
#[derive(Debug)]
pub(crate) struct Query<T>(pub T);

impl<S, T> FromRequestParts<S> for Query<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(query_rejection(rejection, parts.uri.query())),
        }
    }
}

/// A pending WebSocket upgrade.
#[derive(Debug)]
pub(crate) struct WebSocketUpgrade(pub axum::extract::ws::WebSocketUpgrade);

impl<S> FromRequestParts<S> for WebSocketUpgrade
where
    S: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Rejection> {
        match axum::extract::ws::WebSocketUpgrade::from_request_parts(parts, state).await {
            Ok(upgrade) => Ok(Self(upgrade)),
            Err(rejection) => Err(websocket_rejection(rejection)),
        }
    }
}

fn json_rejection(rejection: JsonRejection) -> Rejection {
    let status = rejection.status();
    let (kind, message, hint) = match &rejection {
        JsonRejection::JsonSyntaxError(_) => ("invalid_json", rejection.body_text(), None),
        JsonRejection::MissingJsonContentType(_) => (
            "unsupported_media_type",
            rejection.body_text(),
            Some("send the body with Content-Type: application/json"),
        ),
        // The body limit is the one rejection whose cause is a daemon setting
        // rather than the request's shape, so name the setting and its value.
        JsonRejection::BytesRejection(_) if status == StatusCode::PAYLOAD_TOO_LARGE => (
            "payload_too_large",
            format!(
                "request body exceeds the {} byte limit",
                current_policy().max_request_bytes
            ),
            Some(
                "split the transfer into smaller requests, or raise max_request_bytes in the daemon's api policy",
            ),
        ),
        _ => ("invalid_request_body", rejection.body_text(), None),
    };
    Rejection {
        status,
        kind,
        message,
        hint,
    }
}

fn path_rejection(rejection: PathRejection) -> Rejection {
    let kind = match &rejection {
        PathRejection::FailedToDeserializePathParams(_) => "invalid_path",
        // Only a route registered without the parameters its handler reads
        // produces this, which is a defect in the daemon, not the request.
        _ => "internal_error",
    };
    Rejection {
        status: rejection.status(),
        kind,
        message: rejection.body_text(),
        hint: None,
    }
}

/// axum's text does not say which query string failed, and serde's detail
/// ("invalid digit found in string") does not name the parameter, so the raw
/// query string goes into the message.
fn query_rejection(rejection: QueryRejection, query: Option<&str>) -> Rejection {
    let detail = rejection
        .source()
        .map_or_else(|| rejection.body_text(), ToString::to_string);
    Rejection {
        status: rejection.status(),
        kind: "invalid_query",
        message: format!(
            "invalid query string `{}`: {detail}",
            query.unwrap_or_default()
        ),
        hint: None,
    }
}

fn websocket_rejection(rejection: WebSocketUpgradeRejection) -> Rejection {
    Rejection {
        status: rejection.status(),
        kind: "websocket_upgrade_required",
        message: rejection.body_text(),
        hint: Some(
            "this route speaks WebSocket; open it with a WebSocket client, not a plain HTTP request",
        ),
    }
}

/// The response for a path no route claims.
pub(crate) async fn route_not_found(method: Method, uri: Uri) -> Rejection {
    Rejection {
        status: StatusCode::NOT_FOUND,
        kind: "route_not_found",
        message: format!("no route for {method} {}", uri.path()),
        hint: Some("GET /api-docs/openapi.json lists the routes this daemon serves"),
    }
}

/// The response for a route that exists but does not accept this method.
pub(crate) async fn method_not_allowed(method: Method, uri: Uri) -> Rejection {
    Rejection {
        status: StatusCode::METHOD_NOT_ALLOWED,
        kind: "method_not_allowed",
        message: format!("{method} is not allowed on {}", uri.path()),
        hint: Some("the Allow header lists the methods this route accepts"),
    }
}
