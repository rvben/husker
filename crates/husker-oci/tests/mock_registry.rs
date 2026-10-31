//! End-to-end import against an in-process mock OCI registry: exercises the full
//! pull pipeline (anonymous token, manifest, config + layer blobs, sha256
//! verification, download and unpack budgets, error reporting) and flatten,
//! including a zstd layer. No network, no real daemon.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use husker_oci::{ImportLimits, OciError};
use sha2::{Digest, Sha256};

/// Limits no test image comes near, for the paths where the limits are not
/// under test.
const ROOMY: ImportLimits = ImportLimits {
    max_download_bytes: 64 * 1024 * 1024,
    max_unpacked_bytes: 64 * 1024 * 1024,
};

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

fn tar_one(name: &str, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
        b.finish().unwrap();
    }
    buf
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

/// `len` bytes that gzip cannot shrink, from a fixed-seed xorshift generator,
/// for a layer whose served size must stay close to its content size.
fn noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// A blob as the registry will serve it, with the size the manifest declares
/// for it (normally the served length; a test may lie).
struct Blob {
    digest: String,
    bytes: Vec<u8>,
    declared_size: u64,
}

fn blob(bytes: Vec<u8>) -> Blob {
    Blob {
        digest: sha256_digest(&bytes),
        declared_size: bytes.len() as u64,
        bytes,
    }
}

fn manifest_for(config: &Blob, layers: &[&Blob]) -> Vec<u8> {
    let layers: Vec<serde_json::Value> = layers
        .iter()
        .map(|l| {
            serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": l.digest,
                "size": l.declared_size,
            })
        })
        .collect();
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config.digest,
            "size": config.declared_size,
        },
        "layers": layers,
    })
    .to_string()
    .into_bytes()
}

fn config_blob() -> Blob {
    blob(br#"{"architecture":"amd64","config":{}}"#.to_vec())
}

struct MockRegistry {
    manifest: (StatusCode, Vec<u8>),
    blobs: HashMap<String, Vec<u8>>,
    blob_requests: AtomicUsize,
    require_token: bool,
    token_response: (StatusCode, Vec<u8>),
    token_requests: AtomicUsize,
}

impl MockRegistry {
    /// A registry serving `manifest` and the given blobs under their digests.
    fn serving(manifest: Vec<u8>, blobs: Vec<Blob>) -> Self {
        Self {
            manifest: (StatusCode::OK, manifest),
            blobs: blobs.into_iter().map(|b| (b.digest, b.bytes)).collect(),
            blob_requests: AtomicUsize::new(0),
            require_token: false,
            token_response: (StatusCode::NOT_FOUND, vec![]),
            token_requests: AtomicUsize::new(0),
        }
    }

    /// A registry whose manifest route answers `status` with `body`.
    fn failing(status: StatusCode, body: &[u8]) -> Self {
        Self {
            manifest: (status, body.to_vec()),
            blobs: HashMap::new(),
            blob_requests: AtomicUsize::new(0),
            require_token: false,
            token_response: (StatusCode::NOT_FOUND, vec![]),
            token_requests: AtomicUsize::new(0),
        }
    }
}

fn authorized(reg: &MockRegistry, headers: &HeaderMap) -> bool {
    !reg.require_token
        || headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            == Some("Bearer fixture-pull-token")
}

async fn serve_token(State(reg): State<Arc<MockRegistry>>) -> impl IntoResponse {
    reg.token_requests.fetch_add(1, Ordering::SeqCst);
    (reg.token_response.0, reg.token_response.1.clone())
}

async fn serve_manifest(
    State(reg): State<Arc<MockRegistry>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !authorized(&reg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (status, body) = &reg.manifest;
    (
        *status,
        [(
            header::CONTENT_TYPE,
            "application/vnd.oci.image.manifest.v1+json",
        )],
        body.clone(),
    )
        .into_response()
}

async fn serve_blob(
    State(reg): State<Arc<MockRegistry>>,
    Path((_repo, digest)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    reg.blob_requests.fetch_add(1, Ordering::SeqCst);
    if !authorized(&reg, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match reg.blobs.get(&digest) {
        Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serve `registry` on a loopback port and return that port. `127.0.0.1`
/// selects the http scheme, so the client talks to the mock.
async fn spawn(registry: &Arc<MockRegistry>) -> u16 {
    let app = Router::new()
        .route("/token", get(serve_token))
        .route("/v2/{repo}/manifests/{reference}", get(serve_manifest))
        .route("/v2/{repo}/blobs/{digest}", get(serve_blob))
        .with_state(Arc::clone(registry));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn anonymous_registry_never_requests_an_unrelated_token_page() {
    let config = config_blob();
    let manifest = manifest_for(&config, &[]);
    let mut registry = MockRegistry::serving(manifest, vec![config]);
    // Mirrors Artifact Registry's unrelated /token page, which previously
    // failed the token-response size/JSON checks before a manifest was tried.
    registry.token_response = (StatusCode::OK, vec![b'x'; 65 * 1024]);
    let registry = Arc::new(registry);
    let port = spawn(&registry).await;
    Import::new().run(port, ROOMY).await.unwrap();
    assert_eq!(registry.token_requests.load(Ordering::SeqCst), 0);
    assert_eq!(registry.blob_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unauthorized_manifest_retries_with_token_for_manifest_and_blobs() {
    let config = config_blob();
    let layer = blob(gzip(&tar_one("authenticated.txt", b"content")));
    let manifest = manifest_for(&config, &[&layer]);
    let mut registry = MockRegistry::serving(manifest, vec![config, layer]);
    registry.require_token = true;
    registry.token_response = (
        StatusCode::OK,
        br#"{"token":"fixture-pull-token"}"#.to_vec(),
    );
    let registry = Arc::new(registry);
    let port = spawn(&registry).await;
    let import = Import::new();
    import.run(port, ROOMY).await.unwrap();
    assert!(import.dest.path().join("authenticated.txt").exists());
    assert_eq!(registry.token_requests.load(Ordering::SeqCst), 1);
    assert_eq!(registry.blob_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn manifest_failures_other_than_unauthorized_do_not_attempt_authentication() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::BAD_GATEWAY,
    ] {
        let registry = Arc::new(MockRegistry::failing(status, b""));
        let port = spawn(&registry).await;
        let error = Import::new().run(port, ROOMY).await.unwrap_err();
        assert!(
            matches!(error, OciError::Status { status: actual, .. } if actual == status.as_u16())
        );
        assert_eq!(registry.token_requests.load(Ordering::SeqCst), 0);
    }
}

struct Import {
    spool: tempfile::TempDir,
    dest: tempfile::TempDir,
}

impl Import {
    fn new() -> Self {
        Self {
            spool: tempfile::tempdir().unwrap(),
            dest: tempfile::tempdir().unwrap(),
        }
    }

    async fn run(&self, port: u16, limits: ImportLimits) -> Result<(), OciError> {
        husker_oci::pull_and_flatten(
            &format!("127.0.0.1:{port}/demo:latest"),
            "amd64",
            self.spool.path(),
            self.dest.path(),
            limits,
        )
        .await
        .map(|_| ())
    }

    fn spool_is_empty(&self) -> bool {
        std::fs::read_dir(self.spool.path())
            .map(|entries| entries.count() == 0)
            .unwrap_or(true)
    }
}

#[tokio::test]
async fn import_pulls_and_flattens_gzip_and_zstd_layers() {
    let config = config_blob();
    let gzip_layer = blob(gzip(&tar_one("from-gzip.txt", b"gzip-content")));
    let zstd_layer =
        blob(zstd::encode_all(&tar_one("from-zstd.txt", b"zstd-content")[..], 0).unwrap());
    let manifest = manifest_for(&config, &[&gzip_layer, &zstd_layer]);
    let registry = Arc::new(MockRegistry::serving(
        manifest,
        vec![config, gzip_layer, zstd_layer],
    ));
    let port = spawn(&registry).await;

    let import = Import::new();
    import
        .run(port, ROOMY)
        .await
        .expect("import should pull + flatten both layers");

    let dest = import.dest.path();
    assert!(dest.join("from-gzip.txt").exists(), "gzip layer flattened");
    assert_eq!(
        std::fs::read_to_string(dest.join("from-zstd.txt")).unwrap(),
        "zstd-content"
    );
    assert!(
        import.spool_is_empty(),
        "spooled blobs are removed once applied"
    );
}

#[tokio::test]
async fn download_is_cut_off_when_the_registry_under_declares_sizes() {
    let config = config_blob();
    let mut layer = blob(gzip(&tar_one("big.bin", &noise(3000))));
    assert!(layer.bytes.len() > 3000, "the layer must not compress away");
    // The manifest claims the layer is one byte; the served body is over 3 KiB.
    layer.declared_size = 1;
    let manifest = manifest_for(&config, &[&layer]);
    let registry = Arc::new(MockRegistry::serving(manifest, vec![config, layer]));
    let port = spawn(&registry).await;

    // Positive control: with room to spare the lie does not matter.
    let generous = Import::new();
    generous.run(port, ROOMY).await.unwrap();
    assert!(generous.dest.path().join("big.bin").exists());

    let tight = Import::new();
    let limits = ImportLimits {
        max_download_bytes: 2048,
        ..ROOMY
    };
    let err = tight.run(port, limits).await.unwrap_err();
    assert!(
        matches!(err, OciError::DownloadTooLarge { limit: 2048 }),
        "bytes received are charged, not the declared size: {err}"
    );
    assert!(tight.spool_is_empty(), "the partial spool file is removed");
}

#[tokio::test]
async fn declared_oversize_is_refused_before_any_blob_is_fetched() {
    let config = config_blob();
    let mut layer = blob(gzip(&tar_one("small.txt", b"small")));
    layer.declared_size = 10 * 1024 * 1024 * 1024;
    let manifest = manifest_for(&config, &[&layer]);
    let registry = Arc::new(MockRegistry::serving(manifest, vec![config, layer]));
    let port = spawn(&registry).await;

    let import = Import::new();
    let limits = ImportLimits {
        max_download_bytes: 1024 * 1024,
        ..ROOMY
    };
    let err = import.run(port, limits).await.unwrap_err();
    assert!(
        matches!(err, OciError::DownloadTooLarge { limit } if limit == 1024 * 1024),
        "{err}"
    );
    assert_eq!(
        registry.blob_requests.load(Ordering::SeqCst),
        0,
        "no blob is requested for an image the manifest already puts over the limit"
    );
}

#[tokio::test]
async fn unpack_is_cut_off_at_the_limit() {
    let config = config_blob();
    // One MiB of zeros compresses to a few KiB but unpacks to one MiB.
    let layer = blob(gzip(&tar_one("bomb.bin", &vec![0u8; 1024 * 1024])));
    let manifest = manifest_for(&config, &[&layer]);
    let registry = Arc::new(MockRegistry::serving(manifest, vec![config, layer]));
    let port = spawn(&registry).await;

    let import = Import::new();
    let limits = ImportLimits {
        max_unpacked_bytes: 64 * 1024,
        ..ROOMY
    };
    let err = import.run(port, limits).await.unwrap_err();
    assert!(
        matches!(err, OciError::UnpackedTooLarge { limit } if limit == 64 * 1024),
        "{err}"
    );
    assert!(
        import.spool_is_empty(),
        "the spool holds nothing after a failed unpack"
    );
}

#[tokio::test]
async fn corrupted_blob_is_rejected() {
    let config = config_blob();
    let mut layer = blob(gzip(&tar_one("file.txt", b"content")));
    // Serve different bytes under the digest the manifest names.
    layer.bytes = gzip(&tar_one("file.txt", b"tampered"));
    let manifest = manifest_for(&config, &[&layer]);
    let registry = Arc::new(MockRegistry::serving(manifest, vec![config, layer]));
    let port = spawn(&registry).await;

    let import = Import::new();
    let err = import.run(port, ROOMY).await.unwrap_err();
    assert!(
        matches!(&err, OciError::Malformed(m) if m.contains("digest mismatch")),
        "{err}"
    );
    assert!(
        !import.dest.path().join("file.txt").exists(),
        "nothing from an unverified blob reaches the rootfs"
    );
}

#[tokio::test]
async fn registry_errors_are_reported_by_code_not_echoed() {
    let structured = Arc::new(MockRegistry::failing(
        StatusCode::UNAUTHORIZED,
        br#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
    ));
    let port = spawn(&structured).await;
    let err = Import::new().run(port, ROOMY).await.unwrap_err();
    match err {
        OciError::Status { status, detail, .. } => {
            assert_eq!(status, 401);
            assert_eq!(detail, "UNAUTHORIZED: authentication required");
        }
        other => panic!("expected a status error, got {other}"),
    }

    let unstructured = Arc::new(MockRegistry::failing(
        StatusCode::UNAUTHORIZED,
        b"<html>evil</html>",
    ));
    let port = spawn(&unstructured).await;
    let err = Import::new().run(port, ROOMY).await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("401"), "{text}");
    assert!(text.contains("Unauthorized"), "{text}");
    assert!(!text.contains("evil"), "the body is never echoed: {text}");
}
