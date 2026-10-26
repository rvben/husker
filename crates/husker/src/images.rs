use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::http::{self, HttpTimeouts};

/// Prefix used on image-release tags produced by `build-images.yml`.
/// A separate prefix keeps the images releases out of the semver "latest"
/// channel used by `pip install husker` binaries.
const IMAGES_TAG_PREFIX: &str = "images-";

/// How many pages of the releases listing to walk while looking for the images
/// channel. Bounds the cost of the search; in practice page 1 always carries an
/// images release, because every `v*` release triggers an image build.
const MAX_RELEASE_PAGES: u32 = 10;

/// One asset of an image release and the path it is installed at.
#[derive(Debug, Clone)]
pub struct DownloadSpec {
    /// Asset name as listed in the release manifest, e.g. `kernel-x86_64`.
    pub name: String,
    pub url: String,
    pub expected_sha256: String,
    pub dest: PathBuf,
}

/// How an installed default image relates to the release it was compared
/// with or pulled from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetState {
    /// Downloaded, verified and installed by this run.
    Installed,
    /// Already present and identical to the release asset.
    Current,
    /// Already present but different from the release asset. It is left in
    /// place: an operator may have customised it on purpose, and only
    /// `--force` replaces it.
    Differs,
}

/// The outcome for one default image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetReport {
    pub name: String,
    pub path: PathBuf,
    pub state: AssetState,
}

/// Milestones `pull_image_set` reports for each asset, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullStage {
    /// The download of this asset is starting.
    Downloading,
    /// The asset is downloaded and its digest matches the manifest. It is not
    /// installed until every asset in the set has reached this point.
    Verified,
}

/// Parse an Alpine-style `SHA256SUMS` manifest: one entry per line as
/// `<sha256>  <filename>`. Lines with fewer than two whitespace-delimited
/// tokens are silently skipped. Filenames with embedded whitespace are
/// not supported — the Alpine convention does not use them.
pub fn parse_manifest(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let sha = parts.next()?;
            let name = parts.next()?;
            Some((name.to_string(), sha.to_string()))
        })
        .collect()
}

/// Build the download set for `targets` (asset name, destination) from a
/// release manifest. Every asset is looked up before anything is downloaded,
/// so a manifest that lacks one fails the pull before it touches the data dir.
pub fn release_specs(
    base_url: &str,
    manifest: &HashMap<String, String>,
    targets: &[(String, PathBuf)],
) -> Result<Vec<DownloadSpec>> {
    let base = base_url.trim_end_matches('/');
    targets
        .iter()
        .map(|(name, dest)| {
            let sha = manifest
                .get(name)
                .ok_or_else(|| anyhow!("{name} missing from manifest at {base_url}"))?;
            Ok(DownloadSpec {
                name: name.clone(),
                url: format!("{base}/{name}"),
                expected_sha256: sha.clone(),
                dest: dest.clone(),
            })
        })
        .collect()
}

/// Download and install a set of release assets as one unit.
///
/// Every asset is streamed to a staging file beside its destination and
/// checked against its manifest digest. Only when all of them verify are they
/// moved into place, so a failure part way through the set, whether a network
/// error, a missing asset or a corrupt download, installs nothing: the kernel
/// and initramfs on disk always come from the same release. Each staging file
/// is flushed to stable storage before it is installed and its directory is
/// flushed afterwards, so a crash right after a pull cannot leave a truncated
/// image under a complete-looking name.
pub async fn pull_image_set(
    specs: &[DownloadSpec],
    timeouts: HttpTimeouts,
    mut progress: impl FnMut(&DownloadSpec, PullStage),
) -> Result<Vec<AssetReport>> {
    let client = http::client(timeouts)?;

    let mut staged: Vec<PathBuf> = Vec::with_capacity(specs.len());
    for spec in specs {
        progress(spec, PullStage::Downloading);
        match stage(&client, spec).await {
            Ok(part) => staged.push(part),
            Err(e) => {
                discard(&staged).await;
                return Err(e);
            }
        }
        progress(spec, PullStage::Verified);
    }

    for (spec, part) in specs.iter().zip(&staged) {
        if let Err(e) = install(part, &spec.dest).await {
            discard(&staged).await;
            return Err(e);
        }
    }

    Ok(specs
        .iter()
        .map(|spec| spec.report(AssetState::Installed))
        .collect())
}

/// Compare the installed files of `specs` with their manifest digests without
/// downloading anything. Every file is read in full, so this costs a few
/// seconds for a rootfs.
pub async fn compare_installed(specs: &[DownloadSpec]) -> Result<Vec<AssetReport>> {
    let mut reports = Vec::with_capacity(specs.len());
    for spec in specs {
        let state = if sha256_file(&spec.dest).await? == spec.expected_sha256 {
            AssetState::Current
        } else {
            AssetState::Differs
        };
        reports.push(spec.report(state));
    }
    Ok(reports)
}

impl DownloadSpec {
    fn report(&self, state: AssetState) -> AssetReport {
        AssetReport {
            name: self.name.clone(),
            path: self.dest.clone(),
            state,
        }
    }
}

/// Download one asset into its staging file and verify the digest. The
/// staging file is removed on any failure.
async fn stage(client: &reqwest::Client, spec: &DownloadSpec) -> Result<PathBuf> {
    let dir = parent_dir(&spec.dest);
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating parent dir {}", dir.display()))?;

    let part = staging_path(&spec.dest);
    let result = download_verified(client, spec, &part).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&part).await;
    }
    result.map(|()| part)
}

async fn download_verified(
    client: &reqwest::Client,
    spec: &DownloadSpec,
    part: &Path,
) -> Result<()> {
    let mut resp = client
        .get(&spec.url)
        .send()
        .await
        .with_context(|| format!("GET {}", spec.url))?
        .error_for_status()
        .with_context(|| format!("GET {}", spec.url))?;

    let mut file = tokio::fs::File::create(part)
        .await
        .with_context(|| format!("opening {}", part.display()))?;
    let mut hasher = Sha256::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("reading {}", spec.url))?
    {
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing {}", part.display()))?;
    }
    file.sync_all()
        .await
        .with_context(|| format!("flushing {}", part.display()))?;
    drop(file);

    let got = hex::encode(hasher.finalize());
    if got != spec.expected_sha256 {
        return Err(anyhow!(
            "sha256 mismatch for {}: expected {}, got {}",
            spec.name,
            spec.expected_sha256,
            got,
        ));
    }
    Ok(())
}

/// Move a verified staging file onto its destination and flush the directory
/// so the rename itself survives a crash.
async fn install(part: &Path, dest: &Path) -> Result<()> {
    tokio::fs::rename(part, dest)
        .await
        .with_context(|| format!("renaming {} -> {}", part.display(), dest.display()))?;
    let dir = parent_dir(dest);
    tokio::fs::File::open(dir)
        .await
        .with_context(|| format!("opening {}", dir.display()))?
        .sync_all()
        .await
        .with_context(|| format!("flushing {}", dir.display()))
}

/// Remove the staging files of a pull that did not complete. Errors are
/// ignored: the pull is already failing for a better reason, and an asset
/// installed before the failure no longer exists at its staging path.
async fn discard(staged: &[PathBuf]) {
    for part in staged {
        let _ = tokio::fs::remove_file(part).await;
    }
}

fn staging_path(dest: &Path) -> PathBuf {
    dest.with_file_name(format!(
        "{}.part",
        dest.file_name().unwrap_or_default().to_string_lossy()
    ))
}

/// The directory a destination lives in. A bare file name has the current
/// directory as its parent, which `Path::parent` reports as an empty path.
fn parent_dir(dest: &Path) -> &Path {
    match dest.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

async fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;

    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file =
            std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| format!("reading {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    })
    .await
    .context("hashing an installed image")?
}

pub async fn fetch_manifest(
    base_url: &str,
    timeouts: HttpTimeouts,
) -> Result<HashMap<String, String>> {
    let url = format!("{}/SHA256SUMS", base_url.trim_end_matches('/'));
    let body = http::client(timeouts)?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?
        .text()
        .await
        .with_context(|| format!("reading body {url}"))?;
    Ok(parse_manifest(&body))
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Turn the user-configured `images_base_url` into a concrete
/// `…/releases/download/<tag>` base URL. If the input already pins a
/// specific release, return it unchanged. Otherwise treat it as a GitHub
/// repo URL and ask the API for the newest release whose tag starts with
/// `images-`.
pub async fn resolve_download_base(config_url: &str, timeouts: HttpTimeouts) -> Result<String> {
    let trimmed = config_url.trim_end_matches('/');
    if trimmed.contains("/releases/download/") {
        return Ok(trimmed.to_string());
    }

    let repo_url = trimmed
        .trim_end_matches("/releases/latest/download")
        .trim_end_matches("/releases/latest")
        .trim_end_matches("/releases");
    let repo_path = repo_url
        .strip_prefix("https://github.com/")
        .or_else(|| repo_url.strip_prefix("http://github.com/"))
        .ok_or_else(|| {
            anyhow!(
                "cannot resolve images release from {config_url}: expected \
                 a github.com repo URL or a /releases/download/<tag> URL"
            )
        })?;

    let client = http::client(timeouts)?;

    // Walk the release pages newest-first until one carries an images-* tag.
    // Reading only the first page would silently resolve a STALE release once
    // 100 newer releases pile up after the last image build - and a stale tag
    // downloads successfully, so nothing downstream could ever flag it.
    let mut tags: Vec<String> = Vec::new();
    for page in 1..=MAX_RELEASE_PAGES {
        let api_url =
            format!("https://api.github.com/repos/{repo_path}/releases?per_page=100&page={page}");
        let releases: Vec<GithubRelease> = client
            .get(&api_url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .with_context(|| format!("GET {api_url}"))?
            .error_for_status()
            .with_context(|| format!("GET {api_url}"))?
            .json()
            .await
            .with_context(|| format!("parsing JSON from {api_url}"))?;

        // An empty page means the release list is exhausted.
        if releases.is_empty() {
            break;
        }
        let found_images = releases
            .iter()
            .any(|r| r.tag_name.starts_with(IMAGES_TAG_PREFIX));
        tags.extend(releases.into_iter().map(|r| r.tag_name));
        if found_images {
            break;
        }
    }

    let tag = select_images_tag(tags.into_iter()).ok_or_else(|| {
        anyhow!(
            "no '{IMAGES_TAG_PREFIX}*' release found at https://github.com/{repo_path} — \
             the first default images release may not be published yet"
        )
    })?;

    Ok(format!(
        "https://github.com/{repo_path}/releases/download/{tag}"
    ))
}

/// Pick the newest images release from a set of repository tags.
///
/// Newest is decided lexicographically, which is only correct because the tag
/// carries a UTC timestamp in a fixed-width, big-endian format
/// (`images-YYYY-MM-DDThhmmssZ`). The workflow that mints these tags must keep
/// that property: any tag whose first differing character can sort above a later
/// one - a version number, a run id, an unpadded field - would pin every host to
/// the wrong release, silently and permanently.
fn select_images_tag(tags: impl Iterator<Item = String>) -> Option<String> {
    tags.filter(|t| t.starts_with(IMAGES_TAG_PREFIX)).max()
}

#[cfg(test)]
mod tests {
    use super::select_images_tag;

    fn newest(tags: &[&str]) -> Option<String> {
        select_images_tag(tags.iter().map(|s| s.to_string()))
    }

    #[test]
    fn newest_images_tag_wins_across_both_tag_formats() {
        // Date-only tags predate the timestamped ones and must keep sorting
        // correctly against them: a date-only tag is a prefix of a timestamped
        // tag from the same day, so the timestamped one is newer.
        assert_eq!(
            newest(&[
                "images-2026-08-01",
                "images-2026-08-05T151200Z",
                "images-2026-07-01",
            ]),
            Some("images-2026-08-05T151200Z".to_string())
        );
        // A later date beats an earlier timestamped one.
        assert_eq!(
            newest(&["images-2026-08-05T151200Z", "images-2026-09-01"]),
            Some("images-2026-09-01".to_string())
        );
        // Two runs on the same day are ordered by time, not by arrival.
        assert_eq!(
            newest(&["images-2026-08-05T235900Z", "images-2026-08-05T010000Z"]),
            Some("images-2026-08-05T235900Z".to_string())
        );
    }

    #[test]
    fn version_tags_are_never_mistaken_for_images_releases() {
        // The repo's own `v*` releases share the tag list. They must be filtered
        // out, and - the reason the images tag is NOT version-stamped - a tag like
        // `images-v0.4.42` would sort above every date, pinning hosts to it
        // forever, so this asserts no such tag can be produced by the filter.
        assert_eq!(
            newest(&["v0.4.41", "v0.4.42", "images-2026-08-01"]),
            Some("images-2026-08-01".to_string())
        );
        assert!(
            "images-v0.4.42" > "images-2026-09-01",
            "the trap this avoids"
        );
        assert_eq!(newest(&["v0.4.41", "nightly"]), None);
    }

    /// Every fixture above, as a table the shell parity test replays.
    const TAG_FIXTURES: &[&[&str]] = &[
        &[
            "images-2026-08-01",
            "images-2026-08-05T151200Z",
            "images-2026-07-01",
        ],
        &["images-2026-08-05T151200Z", "images-2026-09-01"],
        &["images-2026-08-05T235900Z", "images-2026-08-05T010000Z"],
        &["v0.4.41", "v0.4.42", "images-2026-08-01"],
        &["v0.4.41", "nightly"],
    ];

    /// Run `scripts/ci/resolve-images-tag.sh` over a tag list. `None` when it
    /// exits non-zero, mirroring `select_images_tag` returning `None`.
    fn shell_newest(tags: &[&str]) -> Option<String> {
        use std::io::Write;
        use std::path::Path;
        use std::process::{Command, Stdio};

        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ci/resolve-images-tag.sh");
        let mut child = Command::new("bash")
            .arg(&script)
            .args(["--tags-file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawning {}: {e}", script.display()));
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(tags.join("\n").as_bytes())
            .expect("writing tags to the resolver");
        let out = child.wait_with_output().expect("running the resolver");

        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// CI resolves the images tag in shell, because it needs the tag before a
    /// husker binary exists to ask. That duplication is only safe while it is
    /// enforced, so pin the two implementations to the same answers.
    ///
    /// This is the test that was missing on 2026-08-05, when the tag format
    /// grew a timestamp (`images-2026-08-05` -> `images-2026-08-05T200756Z`):
    /// this function was updated with the fixtures above, five shell copies
    /// kept a regex that truncated the tag back to the date, and every nightly
    /// e2e downloaded a 404 for four days.
    #[test]
    fn shell_resolver_matches_rust() {
        for tags in TAG_FIXTURES {
            assert_eq!(
                shell_newest(tags),
                newest(tags),
                "scripts/ci/resolve-images-tag.sh disagrees with select_images_tag on {tags:?}"
            );
        }
    }
}
