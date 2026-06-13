//! End-to-end import against an in-process mock OCI registry: exercises the full
//! pull pipeline (anonymous token, manifest, config + layer blobs, sha256
//! verification) and flatten, including a zstd layer. No network, no real daemon.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use sha2::{Digest, Sha256};

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
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

struct MockRegistry {
    manifest: Vec<u8>,
    blobs: HashMap<String, Vec<u8>>,
}

async fn serve_manifest(State(reg): State<Arc<MockRegistry>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/vnd.oci.image.manifest.v1+json",
        )],
        reg.manifest.clone(),
    )
}

async fn serve_blob(
    State(reg): State<Arc<MockRegistry>>,
    Path((_repo, digest)): Path<(String, String)>,
) -> impl IntoResponse {
    match reg.blobs.get(&digest) {
        Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::test]
async fn import_pulls_and_flattens_gzip_and_zstd_layers() {
    // Build the blobs: a minimal config, a gzip layer, and a zstd layer.
    let config = br#"{"architecture":"amd64","config":{}}"#.to_vec();
    let gzip_layer = gzip(&tar_one("from-gzip.txt", b"gzip-content"));
    let zstd_layer = zstd::encode_all(&tar_one("from-zstd.txt", b"zstd-content")[..], 0).unwrap();

    let config_digest = sha256_digest(&config);
    let gzip_digest = sha256_digest(&gzip_layer);
    let zstd_digest = sha256_digest(&zstd_layer);

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [
            { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": gzip_digest, "size": gzip_layer.len() },
            { "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": zstd_digest, "size": zstd_layer.len() },
        ],
    })
    .to_string()
    .into_bytes();

    let mut blobs = HashMap::new();
    blobs.insert(config_digest, config);
    blobs.insert(gzip_digest, gzip_layer);
    blobs.insert(zstd_digest, zstd_layer);
    let registry = Arc::new(MockRegistry { manifest, blobs });

    let app = Router::new()
        // 404 on /token => the client proceeds with an anonymous (empty) token.
        .route("/token", get(|| async { StatusCode::NOT_FOUND }))
        .route("/v2/{repo}/manifests/{reference}", get(serve_manifest))
        .route("/v2/{repo}/blobs/{digest}", get(serve_blob))
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 127.0.0.1 => http scheme (registry_base), so the client hits the mock.
    let dir = tempfile::tempdir().unwrap();
    husker_oci::pull_and_flatten(
        &format!("127.0.0.1:{port}/demo:latest"),
        "amd64",
        dir.path(),
    )
    .await
    .expect("import should pull + flatten both layers");

    assert!(
        dir.path().join("from-gzip.txt").exists(),
        "gzip layer flattened"
    );
    assert!(
        dir.path().join("from-zstd.txt").exists(),
        "zstd layer flattened"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("from-zstd.txt")).unwrap(),
        "zstd-content"
    );
}
