use std::fs;

use husker::images::{DownloadSpec, fetch_and_verify, parse_manifest, resolve_download_base};
use sha2::{Digest, Sha256};

#[test]
fn parse_manifest_extracts_sha_for_named_file() {
    let manifest = "abc123  kernel-aarch64\n\
                    def456  rootfs-aarch64.ext4\n";
    let map = parse_manifest(manifest);
    assert_eq!(
        map.get("kernel-aarch64").map(String::as_str),
        Some("abc123")
    );
    assert_eq!(
        map.get("rootfs-aarch64.ext4").map(String::as_str),
        Some("def456")
    );
}

#[tokio::test]
async fn fetch_manifest_parses_asset_lines() {
    let body: &[u8] = b"deadbeef  kernel-aarch64\nc0ffee  rootfs-aarch64.ext4\n";
    let server = mock_server(body).await;
    let manifest = husker::images::fetch_manifest(&server.url).await.unwrap();
    assert_eq!(manifest.get("kernel-aarch64").unwrap(), "deadbeef");
    assert_eq!(manifest.get("rootfs-aarch64.ext4").unwrap(), "c0ffee");
}

#[tokio::test]
async fn fetch_and_verify_rejects_sha_mismatch() {
    let body: &[u8] = b"payload";
    let server = mock_server(body).await;
    let dest = tempfile::NamedTempFile::new().unwrap();
    let err = fetch_and_verify(DownloadSpec {
        url: format!("{}/asset", server.url),
        expected_sha256: "0".repeat(64),
        dest: dest.path().to_path_buf(),
    })
    .await
    .expect_err("mismatched sha must error");
    assert!(
        err.to_string().contains("sha256"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn resolve_download_base_passes_through_pinned_tag() {
    let pinned = "https://github.com/rvben/husker/releases/download/images-2026-04-21";
    let got = resolve_download_base(pinned).await.unwrap();
    assert_eq!(got, pinned);
}

#[tokio::test]
async fn resolve_download_base_rejects_non_github_repo_url() {
    let err = resolve_download_base("https://example.com/husker")
        .await
        .expect_err("non-github URL must not resolve");
    assert!(
        err.to_string().contains("github.com"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn fetch_and_verify_writes_file_on_match() {
    let body: &[u8] = b"payload";
    let mut hasher = Sha256::new();
    hasher.update(body);
    let sha = hex::encode(hasher.finalize());
    let server = mock_server(body).await;
    let dest = tempfile::NamedTempFile::new().unwrap();
    fetch_and_verify(DownloadSpec {
        url: format!("{}/asset", server.url),
        expected_sha256: sha,
        dest: dest.path().to_path_buf(),
    })
    .await
    .expect("verified download");
    let written = fs::read(dest.path()).unwrap();
    assert_eq!(written, body);
}

struct Server {
    url: String,
    _handle: tokio::task::JoinHandle<()>,
}

async fn mock_server(body: &'static [u8]) -> Server {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the HTTP request so the socket can close cleanly with FIN
            // instead of RST. RST occurs on macOS when a socket is dropped
            // with unread data in the receive buffer.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        }
    });
    Server {
        url: format!("http://{}", addr),
        _handle: handle,
    }
}
