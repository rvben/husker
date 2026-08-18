//! OCI image artifact materialization.
//!
//! This module owns the full filesystem side of an OCI import: pull and
//! flatten, guest-runtime injection, extracted-size policy, ext4 sizing, and
//! construction. Catalog naming and state persistence intentionally remain in
//! `images`, which owns the durable image catalog.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// Maximum apparent size accepted from a flattened OCI filesystem tree.
/// This is a decompression-bomb guard in addition to the compressed blob cap.
const MAX_ROOTFS_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub type OciMaterializationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<MaterializedOciImage, OciMaterializationError>> + Send + 'a>,
>;

#[derive(Debug, Clone, Copy)]
pub struct OciMaterializationRequest<'a> {
    pub reference: &'a str,
    pub destination: &'a Path,
    pub guest_agent: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedOciImage {
    pub size_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum OciMaterializationError {
    #[error("OCI import requires a non-empty embedded guest agent")]
    MissingGuestAgent,
    #[error("unsupported host architecture for OCI import: {0}")]
    UnsupportedArchitecture(String),
    #[error("create OCI work directory: {0}")]
    WorkDirectory(#[source] std::io::Error),
    #[error("pull {reference}: {source}")]
    Pull {
        reference: String,
        #[source]
        source: husker_oci::OciError,
    },
    #[error("inject guest runtime: {0}")]
    Runtime(String),
    #[error("measure extracted rootfs: {0}")]
    SizeTask(String),
    #[error("imported rootfs is {actual} bytes, over the {limit}-byte limit")]
    RootfsTooLarge { actual: u64, limit: u64 },
    #[error(transparent)]
    Storage(#[from] husker_storage::StorageError),
}

pub trait OciImageMaterializer: Send + Sync {
    fn materialize<'a>(
        &'a self,
        request: OciMaterializationRequest<'a>,
    ) -> OciMaterializationFuture<'a>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalOciImageMaterializer;

impl OciImageMaterializer for LocalOciImageMaterializer {
    fn materialize<'a>(
        &'a self,
        request: OciMaterializationRequest<'a>,
    ) -> OciMaterializationFuture<'a> {
        Box::pin(async move {
            if request.guest_agent.is_empty() {
                return Err(OciMaterializationError::MissingGuestAgent);
            }
            if request.destination.exists() {
                return Err(OciMaterializationError::Storage(
                    husker_storage::StorageError::VolumeImage(format!(
                        "OCI image destination already exists: {}",
                        request.destination.display()
                    )),
                ));
            }
            let architecture = oci_architecture(std::env::consts::ARCH)?;
            let work = tempfile::tempdir().map_err(OciMaterializationError::WorkDirectory)?;
            let rootfs_dir = work.path().join("rootfs");
            let image_config =
                husker_oci::pull_and_flatten(request.reference, architecture, &rootfs_dir)
                    .await
                    .map_err(|source| OciMaterializationError::Pull {
                        reference: request.reference.to_string(),
                        source,
                    })?;

            materialize_flattened_rootfs(
                &rootfs_dir,
                request.destination,
                request.guest_agent,
                image_config,
            )
            .await
        })
    }
}

fn oci_architecture(host_architecture: &str) -> Result<&'static str, OciMaterializationError> {
    match host_architecture {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(OciMaterializationError::UnsupportedArchitecture(
            other.to_string(),
        )),
    }
}

async fn materialize_flattened_rootfs(
    rootfs_dir: &Path,
    destination: &Path,
    guest_agent: &[u8],
    image_config: husker_oci::ImageConfig,
) -> Result<MaterializedOciImage, OciMaterializationError> {
    let runtime = husker_agent_proto::OciRuntimeConfig {
        env: image_config.env,
        working_dir: image_config.working_dir,
        entrypoint: image_config.entrypoint,
        cmd: image_config.cmd,
    };
    inject_guest_runtime(rootfs_dir, guest_agent, &runtime)?;

    let rootfs = rootfs_dir.to_owned();
    let tree_size = tokio::task::spawn_blocking(move || husker_storage::dir_apparent_size(&rootfs))
        .await
        .map_err(|error| OciMaterializationError::SizeTask(error.to_string()))?;
    if tree_size > MAX_ROOTFS_BYTES {
        return Err(OciMaterializationError::RootfsTooLarge {
            actual: tree_size,
            limit: MAX_ROOTFS_BYTES,
        });
    }

    let size_bytes = rootfs_image_size(tree_size);
    husker_storage::build_ext4_from_dir(rootfs_dir, destination, size_bytes).await?;
    Ok(MaterializedOciImage { size_bytes })
}

/// Size an imported OCI rootfs: the tree itself, growth headroom (the tree
/// again, floored at 512 MiB), and a 64 MiB base for ext4 metadata/journal.
fn rootfs_image_size(tree_size: u64) -> u64 {
    const MIN_HEADROOM: u64 = 512 * 1024 * 1024;
    const EXT4_BASE: u64 = 64 * 1024 * 1024;
    tree_size + tree_size.max(MIN_HEADROOM) + EXT4_BASE
}

/// Inject the agent and OCI runtime configuration without following paths from
/// the untrusted image outside its rootfs.
fn inject_guest_runtime(
    dir: &Path,
    agent: &[u8],
    oci_config: &husker_agent_proto::OciRuntimeConfig,
) -> Result<(), OciMaterializationError> {
    use std::os::unix::fs::PermissionsExt;

    fn replace_with_directory(path: &Path) -> Result<(), OciMaterializationError> {
        std::fs::remove_file(path)
            .or_else(|_| std::fs::remove_dir_all(path))
            .map_err(|error| {
                OciMaterializationError::Runtime(format!("replace {}: {error}", path.display()))
            })?;
        std::fs::create_dir(path).map_err(|error| {
            OciMaterializationError::Runtime(format!("mkdir {}: {error}", path.display()))
        })
    }

    /// Resolve a symlinked path component the way the guest resolves it, where
    /// an absolute target is relative to the image root. Answers `None` unless
    /// the result is a directory inside the image, so an image cannot redirect
    /// an injected file onto the host.
    fn resolve_inside_image(root: &Path, link: &Path) -> Option<PathBuf> {
        let target = std::fs::read_link(link).ok()?;
        let candidate = if target.is_absolute() {
            root.join(target.strip_prefix("/").ok()?)
        } else {
            link.parent()?.join(target)
        };
        let resolved = candidate.canonicalize().ok()?;
        (resolved.starts_with(root.canonicalize().ok()?) && resolved.is_dir()).then_some(resolved)
    }

    fn safe_target(dir: &Path, rel: &str) -> Result<PathBuf, OciMaterializationError> {
        let components: Vec<&str> = rel.split('/').filter(|part| !part.is_empty()).collect();
        let (directories, file) = components.split_at(components.len().saturating_sub(1));
        let mut current = dir.to_path_buf();
        for directory in directories {
            current = current.join(directory);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                // A distribution with a merged /usr ships `/sbin` as a symlink
                // to `usr/sbin`. Replacing that with a real directory leaves the
                // image unmerged, which its package manager refuses to install
                // into, so a link that stays inside the image is followed and
                // only one that escapes it is replaced.
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    match resolve_inside_image(dir, &current) {
                        Some(resolved) => current = resolved,
                        None => replace_with_directory(&current)?,
                    }
                }
                Ok(_) => replace_with_directory(&current)?,
                Err(_) => std::fs::create_dir(&current).map_err(|error| {
                    OciMaterializationError::Runtime(format!(
                        "mkdir {}: {error}",
                        current.display()
                    ))
                })?,
            }
        }
        Ok(current.join(file.first().copied().unwrap_or("")))
    }

    let write = |relative: &str, bytes: &[u8], mode: u32| {
        let target = safe_target(dir, relative)?;
        let _ = std::fs::remove_file(&target);
        std::fs::write(&target, bytes).map_err(|error| {
            OciMaterializationError::Runtime(format!("write {}: {error}", target.display()))
        })?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).map_err(
            |error| {
                OciMaterializationError::Runtime(format!("chmod {}: {error}", target.display()))
            },
        )?;
        Ok::<_, OciMaterializationError>(())
    };

    write("usr/local/bin/husker-agent", agent, 0o755)?;
    let config_json = serde_json::to_vec_pretty(oci_config)
        .map_err(|error| OciMaterializationError::Runtime(format!("serialize config: {error}")))?;
    write("etc/husker/oci-config.json", &config_json, 0o644)?;

    let init = safe_target(dir, "sbin/init")?;
    let _ = std::fs::remove_file(&init);
    std::os::unix::fs::symlink("/usr/local/bin/husker-agent", &init).map_err(|error| {
        OciMaterializationError::Runtime(format!("symlink {}: {error}", init.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn small_images_get_the_headroom_floor() {
        assert_eq!(rootfs_image_size(135 * MIB), (135 + 512 + 64) * MIB);
        assert_eq!(rootfs_image_size(8 * MIB), (8 + 512 + 64) * MIB);
    }

    #[test]
    fn large_images_keep_proportional_headroom() {
        let tree = 2200 * MIB;
        assert_eq!(rootfs_image_size(tree), tree * 2 + 64 * MIB);
    }

    #[test]
    fn architecture_mapping_is_owned_by_the_materializer() {
        assert_eq!(oci_architecture("x86_64").unwrap(), "amd64");
        assert_eq!(oci_architecture("aarch64").unwrap(), "arm64");
        assert!(matches!(
            oci_architecture("riscv64"),
            Err(OciMaterializationError::UnsupportedArchitecture(arch)) if arch == "riscv64"
        ));
    }

    #[tokio::test]
    async fn empty_agent_is_rejected_before_any_pull_or_artifact() {
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("artifact.ext4");
        let error = LocalOciImageMaterializer
            .materialize(OciMaterializationRequest {
                reference: "registry.invalid/example:latest",
                destination: &destination,
                guest_agent: &[],
            })
            .await
            .unwrap_err();

        assert!(matches!(error, OciMaterializationError::MissingGuestAgent));
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn existing_destination_is_preserved_without_pulling() {
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("artifact.ext4");
        std::fs::write(&destination, b"existing artifact").unwrap();

        let error = LocalOciImageMaterializer
            .materialize(OciMaterializationRequest {
                reference: "registry.invalid/example:latest",
                destination: &destination,
                guest_agent: b"AGENT",
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OciMaterializationError::Storage(husker_storage::StorageError::VolumeImage(_))
        ));
        assert_eq!(std::fs::read(destination).unwrap(), b"existing artifact");
    }

    #[test]
    fn runtime_injection_does_not_follow_symlinks() {
        let rootfs = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("usr/local")).unwrap();
        std::os::unix::fs::symlink(outside.path(), rootfs.path().join("usr/local/bin")).unwrap();

        inject_guest_runtime(
            rootfs.path(),
            b"AGENT",
            &husker_agent_proto::OciRuntimeConfig::default(),
        )
        .unwrap();

        assert!(!outside.path().join("husker-agent").exists());
        assert!(
            std::fs::symlink_metadata(rootfs.path().join("usr/local/bin"))
                .unwrap()
                .file_type()
                .is_dir()
        );
        assert_eq!(
            std::fs::read(rootfs.path().join("usr/local/bin/husker-agent")).unwrap(),
            b"AGENT"
        );
    }

    /// A merged-/usr image keeps `/sbin` as a link to `usr/sbin`. Replacing it
    /// with a real directory unmerges the image, and its package manager then
    /// refuses to install anything that requires the merge.
    #[test]
    fn runtime_injection_keeps_a_relative_merged_usr_link() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("usr/sbin")).unwrap();
        std::os::unix::fs::symlink("usr/sbin", rootfs.path().join("sbin")).unwrap();

        inject_guest_runtime(
            rootfs.path(),
            b"AGENT",
            &husker_agent_proto::OciRuntimeConfig::default(),
        )
        .unwrap();

        assert!(
            std::fs::symlink_metadata(rootfs.path().join("sbin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "/sbin must still link to usr/sbin"
        );
        assert_eq!(
            std::fs::read_link(rootfs.path().join("usr/sbin/init")).unwrap(),
            Path::new("/usr/local/bin/husker-agent")
        );
    }

    #[test]
    fn runtime_injection_keeps_an_absolute_merged_usr_link() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("usr/sbin")).unwrap();
        std::os::unix::fs::symlink("/usr/sbin", rootfs.path().join("sbin")).unwrap();

        inject_guest_runtime(
            rootfs.path(),
            b"AGENT",
            &husker_agent_proto::OciRuntimeConfig::default(),
        )
        .unwrap();

        assert!(
            std::fs::symlink_metadata(rootfs.path().join("sbin"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "an absolute /sbin link is image-relative, not a host path"
        );
        assert_eq!(
            std::fs::read_link(rootfs.path().join("usr/sbin/init")).unwrap(),
            Path::new("/usr/local/bin/husker-agent")
        );
    }

    /// The escape check must survive the merged-/usr fix: a link that climbs out
    /// of the image is still replaced rather than followed.
    #[test]
    fn runtime_injection_replaces_a_link_that_climbs_out_of_the_image() {
        let outside = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("image")).unwrap();
        let image = rootfs.path().join("image");
        std::os::unix::fs::symlink("../", image.join("sbin")).unwrap();

        inject_guest_runtime(
            &image,
            b"AGENT",
            &husker_agent_proto::OciRuntimeConfig::default(),
        )
        .unwrap();

        assert!(!outside.path().join("init").exists());
        assert!(!rootfs.path().join("init").exists());
        assert_eq!(
            std::fs::read_link(image.join("sbin/init")).unwrap(),
            Path::new("/usr/local/bin/husker-agent")
        );
    }

    #[test]
    fn runtime_injection_installs_agent_init_and_config() {
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(rootfs.path().join("sbin")).unwrap();
        std::os::unix::fs::symlink("/lib/systemd/systemd", rootfs.path().join("sbin/init"))
            .unwrap();
        let config = husker_agent_proto::OciRuntimeConfig {
            env: vec!["PATH=/usr/local/bin:/usr/bin".into()],
            working_dir: Some("/app".into()),
            entrypoint: vec!["/bin/server".into()],
            cmd: vec!["--listen".into()],
        };

        inject_guest_runtime(rootfs.path(), b"AGENT", &config).unwrap();

        assert_eq!(
            std::fs::read_link(rootfs.path().join("sbin/init")).unwrap(),
            Path::new("/usr/local/bin/husker-agent")
        );
        let written = std::fs::read(rootfs.path().join("etc/husker/oci-config.json")).unwrap();
        let parsed: husker_agent_proto::OciRuntimeConfig =
            serde_json::from_slice(&written).unwrap();
        assert_eq!(parsed, config);
    }

    #[tokio::test]
    async fn oversized_tree_is_rejected_before_destination_creation() {
        let rootfs = tempfile::tempdir().unwrap();
        let sparse = rootfs.path().join("oversized");
        let file = std::fs::File::create(&sparse).unwrap();
        file.set_len(MAX_ROOTFS_BYTES + 1).unwrap();
        let destination = rootfs.path().join("artifact.ext4");

        let error = materialize_flattened_rootfs(
            rootfs.path(),
            &destination,
            b"AGENT",
            husker_oci::ImageConfig::default(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            OciMaterializationError::RootfsTooLarge {
                actual,
                limit: MAX_ROOTFS_BYTES
            } if actual > MAX_ROOTFS_BYTES
        ));
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn flattened_tree_becomes_a_complete_ext4_artifact() {
        if std::process::Command::new("mkfs.ext4")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("skipping: mkfs.ext4 not available on this host");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let rootfs = work.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("app")).unwrap();
        std::fs::write(rootfs.join("app/data"), b"payload").unwrap();
        let destination = work.path().join("catalog/image.ext4");

        let artifact = materialize_flattened_rootfs(
            &rootfs,
            &destination,
            b"AGENT",
            husker_oci::ImageConfig {
                env: vec!["MODE=test".into()],
                working_dir: Some("/app".into()),
                entrypoint: vec!["/bin/example".into()],
                cmd: vec![],
            },
        )
        .await
        .unwrap();

        assert!(destination.is_file());
        assert_eq!(
            std::fs::metadata(&destination).unwrap().len(),
            artifact.size_bytes
        );
        assert!(artifact.size_bytes >= 512 * MIB);
    }
}
