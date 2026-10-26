//! The image puller against a stub release host: all-or-nothing installs,
//! stalled transfers, and the comparison of already-installed images with
//! the release manifest.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use husker::http::HttpTimeouts;
use husker::images::{
    AssetState, DownloadSpec, PullStage, compare_installed, fetch_manifest, parse_manifest,
    pull_image_set, release_specs, resolve_download_base,
};
use sha2::{Digest, Sha256};

const KERNEL: &[u8] = b"kernel bytes";
const ROOTFS: &[u8] = b"rootfs bytes, a little longer";

/// Short enough that a stalled host fails the test quickly, long enough that
/// a loaded CI runner never trips it on a healthy transfer.
fn fast() -> HttpTimeouts {
    HttpTimeouts {
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A release host serving a fixed set of assets by path; anything else is 404.
struct Release {
    assets: HashMap<String, Vec<u8>>,
}

async fn handle(
    State(release): State<Arc<Release>>,
    request: Request<Body>,
) -> axum::response::Response {
    let name = request.uri().path().trim_start_matches('/').to_string();
    match release.assets.get(&name) {
        Some(body) => (StatusCode::OK, body.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no such asset").into_response(),
    }
}

async fn release_host(assets: &[(&str, &[u8])]) -> String {
    let release = Arc::new(Release {
        assets: assets
            .iter()
            .map(|(name, body)| (name.to_string(), body.to_vec()))
            .collect(),
    });
    let app = Router::new().fallback(handle).with_state(release);
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

/// A host that accepts a connection, reads the request and sends `prefix`,
/// then never sends another byte and never closes.
async fn stalling_host(prefix: &'static [u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await;
        sock.write_all(prefix).await.unwrap();
        std::future::pending::<()>().await;
    });
    url
}

fn manifest_for(assets: &[(&str, &[u8])]) -> HashMap<String, String> {
    assets
        .iter()
        .map(|(name, body)| (name.to_string(), sha256(body)))
        .collect()
}

/// The production target shape: the destination file name differs from the
/// asset name, as `default_kernel` and `default_rootfs` do.
fn targets(dir: &std::path::Path) -> Vec<(String, PathBuf)> {
    vec![
        ("kernel-x86_64".to_string(), dir.join("vmlinux")),
        ("rootfs-x86_64.ext4".to_string(), dir.join("alpine.ext4")),
    ]
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

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
    let url = release_host(&[("SHA256SUMS", body)]).await;
    let manifest = fetch_manifest(&url, fast()).await.unwrap();
    assert_eq!(manifest.get("kernel-aarch64").unwrap(), "deadbeef");
    assert_eq!(manifest.get("rootfs-aarch64.ext4").unwrap(), "c0ffee");
}

#[test]
fn release_specs_fail_before_any_download_when_the_manifest_lacks_an_asset() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = manifest_for(&[("kernel-x86_64", KERNEL)]);
    let err = release_specs("https://example.test/rel/", &manifest, &targets(dir.path()))
        .expect_err("a manifest without the rootfs must not produce a download set");
    assert!(
        err.to_string()
            .contains("rootfs-x86_64.ext4 missing from manifest"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn pull_image_set_installs_every_asset_once_the_whole_set_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let assets: &[(&str, &[u8])] = &[("kernel-x86_64", KERNEL), ("rootfs-x86_64.ext4", ROOTFS)];
    let url = release_host(assets).await;
    let specs = release_specs(&url, &manifest_for(assets), &targets(dir.path())).unwrap();

    let mut events: Vec<(String, PullStage)> = Vec::new();
    let reports = pull_image_set(&specs, fast(), |spec, stage| {
        if stage == PullStage::Verified {
            // A verified asset waits in its staging file until the whole set
            // has verified; installing it now would let a later failure leave
            // a kernel from this release beside a rootfs from the previous one.
            assert!(
                !spec.dest.exists(),
                "{} was installed before the whole set verified",
                spec.name
            );
            assert!(
                dir.path()
                    .join(format!(
                        "{}.part",
                        spec.dest.file_name().unwrap().to_string_lossy()
                    ))
                    .exists(),
                "{} has no staging file at the verified stage",
                spec.name
            );
        }
        events.push((spec.name.clone(), stage));
    })
    .await
    .expect("a complete release must install");

    assert_eq!(
        events,
        vec![
            ("kernel-x86_64".to_string(), PullStage::Downloading),
            ("kernel-x86_64".to_string(), PullStage::Verified),
            ("rootfs-x86_64.ext4".to_string(), PullStage::Downloading),
            ("rootfs-x86_64.ext4".to_string(), PullStage::Verified),
        ]
    );
    assert!(
        reports
            .iter()
            .all(|report| report.state == AssetState::Installed),
        "{reports:?}"
    );
    assert_eq!(fs::read(dir.path().join("vmlinux")).unwrap(), KERNEL);
    assert_eq!(fs::read(dir.path().join("alpine.ext4")).unwrap(), ROOTFS);
    assert_eq!(
        entries(dir.path()),
        vec!["alpine.ext4".to_string(), "vmlinux".to_string()],
        "staging files must not outlive the pull"
    );
}

#[tokio::test]
async fn pull_image_set_installs_nothing_when_a_later_asset_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let url = release_host(&[("kernel-x86_64", KERNEL)]).await;
    let manifest = manifest_for(&[("kernel-x86_64", KERNEL), ("rootfs-x86_64.ext4", ROOTFS)]);
    let specs = release_specs(&url, &manifest, &targets(dir.path())).unwrap();

    let err = pull_image_set(&specs, fast(), |_, _| {})
        .await
        .expect_err("a release missing its rootfs must not install");
    assert!(
        format!("{err:#}").contains("404"),
        "unexpected error: {err:#}"
    );
    assert_eq!(
        entries(dir.path()),
        Vec::<String>::new(),
        "the kernel that verified first must not be installed, and no staging file may remain"
    );
}

#[tokio::test]
async fn pull_image_set_installs_nothing_when_a_later_asset_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let url = release_host(&[("kernel-x86_64", KERNEL), ("rootfs-x86_64.ext4", ROOTFS)]).await;
    let mut manifest = manifest_for(&[("kernel-x86_64", KERNEL)]);
    manifest.insert("rootfs-x86_64.ext4".to_string(), "0".repeat(64));
    let specs = release_specs(&url, &manifest, &targets(dir.path())).unwrap();

    let err = pull_image_set(&specs, fast(), |_, _| {})
        .await
        .expect_err("a rootfs whose digest does not match must not install");
    assert!(
        err.to_string()
            .contains("sha256 mismatch for rootfs-x86_64.ext4"),
        "unexpected error: {err}"
    );
    assert_eq!(entries(dir.path()), Vec::<String>::new());
}

async fn pull_from_stalling_host(prefix: &'static [u8]) -> (tempfile::TempDir, anyhow::Error) {
    let dir = tempfile::tempdir().unwrap();
    let url = stalling_host(prefix).await;
    let specs = vec![DownloadSpec {
        name: "kernel-x86_64".to_string(),
        url: format!("{url}/kernel-x86_64"),
        expected_sha256: sha256(KERNEL),
        dest: dir.path().join("vmlinux"),
    }];
    let timeouts = HttpTimeouts {
        connect: Duration::from_secs(5),
        read: Duration::from_millis(300),
    };
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        pull_image_set(&specs, timeouts, |_, _| {}),
    )
    .await
    .expect("a host that stops sending must fail the pull within the read timeout")
    .expect_err("a stalled download must not succeed");
    (dir, err)
}

#[tokio::test]
async fn pull_image_set_gives_up_on_a_host_that_never_answers() {
    let (dir, err) = pull_from_stalling_host(b"").await;
    assert!(
        format!("{err:#}").contains("timed out"),
        "unexpected error: {err:#}"
    );
    assert_eq!(entries(dir.path()), Vec::<String>::new());
}

#[tokio::test]
async fn pull_image_set_gives_up_on_a_transfer_that_stalls_mid_body() {
    let (dir, err) =
        pull_from_stalling_host(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nkernel").await;
    assert!(
        format!("{err:#}").contains("timed out"),
        "unexpected error: {err:#}"
    );
    assert_eq!(
        entries(dir.path()),
        Vec::<String>::new(),
        "the partial staging file must be removed"
    );
}

#[tokio::test]
async fn compare_installed_reports_which_files_differ_from_the_release() {
    let dir = tempfile::tempdir().unwrap();
    let assets: &[(&str, &[u8])] = &[("kernel-x86_64", KERNEL), ("rootfs-x86_64.ext4", ROOTFS)];
    let specs = release_specs(
        "https://example.test/rel",
        &manifest_for(assets),
        &targets(dir.path()),
    )
    .unwrap();
    fs::write(dir.path().join("vmlinux"), KERNEL).unwrap();
    fs::write(
        dir.path().join("alpine.ext4"),
        b"an operator's customised rootfs",
    )
    .unwrap();

    let reports = compare_installed(&specs).await.unwrap();
    let states: Vec<(&str, AssetState)> = reports
        .iter()
        .map(|report| (report.name.as_str(), report.state))
        .collect();
    assert_eq!(
        states,
        vec![
            ("kernel-x86_64", AssetState::Current),
            ("rootfs-x86_64.ext4", AssetState::Differs),
        ]
    );
    assert_eq!(reports[1].path, dir.path().join("alpine.ext4"));
    assert_eq!(
        serde_json::to_value(&reports[1]).unwrap()["state"],
        "differs",
        "the state is part of the CLI's JSON output"
    );
    assert_eq!(
        fs::read(dir.path().join("alpine.ext4")).unwrap(),
        b"an operator's customised rootfs",
        "comparing must not touch the installed files"
    );
}

#[tokio::test]
async fn compare_installed_fails_on_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let specs = release_specs(
        "https://example.test/rel",
        &manifest_for(&[("kernel-x86_64", KERNEL), ("rootfs-x86_64.ext4", ROOTFS)]),
        &targets(dir.path()),
    )
    .unwrap();
    fs::write(dir.path().join("vmlinux"), KERNEL).unwrap();

    let err = compare_installed(&specs)
        .await
        .expect_err("a missing rootfs cannot be reported as current or differing");
    assert!(
        err.to_string().contains("alpine.ext4"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn resolve_download_base_passes_through_pinned_tag() {
    let pinned = "https://github.com/rvben/husker/releases/download/images-2026-04-21";
    let got = resolve_download_base(pinned, fast()).await.unwrap();
    assert_eq!(got, pinned);
}

#[tokio::test]
async fn resolve_download_base_rejects_non_github_repo_url() {
    let err = resolve_download_base("https://example.com/husker", fast())
        .await
        .expect_err("non-github URL must not resolve");
    assert!(
        err.to_string().contains("github.com"),
        "unexpected error: {err}"
    );
}
