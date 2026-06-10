use std::path::{Path, PathBuf};

#[cfg(all(target_os = "linux", feature = "linux-net"))]
pub mod firecracker;
pub mod images;

/// The guest agent binary embedded by `build.rs` (from the musl build output or
/// `HUSKER_EMBED_AGENT_BIN`). Empty when no agent was embedded at build time, in
/// which case cloud-image support errors clearly at runtime.
pub const EMBEDDED_AGENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/agent.bin"));

/// Whether a guest agent was embedded at build time.
pub fn agent_embedded() -> bool {
    !EMBEDDED_AGENT.is_empty()
}

/// Default source for `husker images pull`. The repo URL form triggers the
/// runtime resolver in `images::resolve_download_base`, which queries the
/// GitHub API for the most recent `images-YYYY-MM-DD` release. Users can
/// override `images_base_url` in config (or `HUSKER_IMAGES_BASE_URL`) with a
/// direct `…/releases/download/<tag>` URL to pin a specific image set.
pub const DEFAULT_IMAGES_BASE_URL: &str = "https://github.com/rvben/husker";

/// Default data directory.
///
/// macOS: always `$HOME/.local/share/husker`.
///
/// Linux: `/var/lib/husker` when the caller can write there (existing dir with
/// write access, or a missing path under a writable parent). Otherwise falls
/// back to the XDG data home (`$XDG_DATA_HOME/husker`, or `$HOME/.local/share/husker`)
/// so unprivileged users can `pip install husker && husker images pull` without sudo.
pub fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        return xdg_data_home().join("husker");
    }
    let system = PathBuf::from("/var/lib/husker");
    if can_write_to(&system) {
        return system;
    }
    xdg_data_home().join("husker")
}

fn xdg_data_home() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share");
    }
    PathBuf::from(".")
}

/// Writability probe used by `default_data_dir()`. Returns true if the path
/// exists and is writable, or if its nearest existing ancestor is writable
/// (so we can create it). Returns false on permission errors.
fn can_write_to(path: &Path) -> bool {
    let mut cursor: &Path = path;
    loop {
        match std::fs::metadata(cursor) {
            Ok(md) => return !md.permissions().readonly() && write_access(cursor),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match cursor.parent() {
                Some(parent) if parent != cursor => cursor = parent,
                _ => return false,
            },
            Err(_) => return false,
        }
    }
}

#[cfg(unix)]
fn write_access(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `access(2)` reads a NUL-terminated path and does not retain
    // the pointer past the call. `W_OK` is a well-defined libc constant.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
fn write_access(_path: &Path) -> bool {
    true
}

pub fn default_kernel_path() -> PathBuf {
    default_kernel_path_for(&default_data_dir())
}

pub fn default_kernel_path_for(data_dir: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        data_dir.join("kernels/Image-virt")
    } else {
        data_dir.join("kernels/vmlinux")
    }
}

pub fn default_rootfs_path() -> PathBuf {
    default_rootfs_path_for(&default_data_dir())
}

pub fn default_rootfs_path_for(data_dir: &Path) -> PathBuf {
    let name = if cfg!(target_arch = "aarch64") {
        "alpine-aarch64.ext4"
    } else {
        "alpine-x86_64.ext4"
    };
    data_dir.join("images").join(name)
}

/// Resolve a `husker run <rootfs>` argument against the images directory.
///
/// If the argument exists as given it is used unchanged. Otherwise, when a file
/// of that name exists under `<data_dir>/images`, that path is used, so a bare
/// image name from `husker images pull` (e.g. `alpine-x86_64.ext4`) is runnable
/// without spelling out the full path. When neither exists the original
/// argument is returned so the caller surfaces a clear "rootfs not found" error.
pub fn resolve_rootfs_arg(arg: PathBuf, data_dir: &Path) -> PathBuf {
    if arg.exists() {
        return arg;
    }
    let in_images = data_dir.join("images").join(&arg);
    if in_images.exists() {
        return in_images;
    }
    arg
}

pub fn default_initrd_path() -> PathBuf {
    default_initrd_path_for(&default_data_dir())
}

pub fn default_initrd_path_for(data_dir: &Path) -> PathBuf {
    let name = if cfg!(target_arch = "aarch64") {
        "initramfs-virt.gz"
    } else {
        "initramfs-x86_64-virt.gz"
    };
    data_dir.join("kernels").join(name)
}

pub fn default_images_base_url() -> String {
    DEFAULT_IMAGES_BASE_URL.to_string()
}

/// Parse a human disk size ("10G", "512M", "1024") into bytes (binary units).
pub fn parse_disk_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "disk size must not be empty");
    let (num, mult): (&str, u64) = match s.chars().last().unwrap() {
        'G' | 'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        'M' | 'm' => (&s[..s.len() - 1], 1024 * 1024),
        'K' | 'k' => (&s[..s.len() - 1], 1024),
        _ => (s, 1),
    };
    let value: f64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid disk size: {s:?}"))?;
    anyhow::ensure!(value >= 0.0, "disk size must not be negative: {s:?}");
    Ok((value * mult as f64) as u64)
}

/// Serde helper: wraps `default_initrd_path` in `Some` so `default_initrd`
/// in the CLI Config defaults to the computed initramfs path rather than
/// None. Users can explicitly set it to `null` in config to opt out.
pub fn default_initrd_some() -> Option<PathBuf> {
    Some(default_initrd_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_agent_const_is_accessible() {
        // On a normal dev/CI build the agent is absent, so this is empty; the point
        // is that the const + include_bytes! compile and the accessor is consistent.
        let _ = super::EMBEDDED_AGENT.len();
        assert_eq!(super::agent_embedded(), !super::EMBEDDED_AGENT.is_empty());
    }

    #[test]
    fn parse_disk_size_units() {
        assert_eq!(parse_disk_size("1024").unwrap(), 1024);
        assert_eq!(parse_disk_size("1K").unwrap(), 1024);
        assert_eq!(parse_disk_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_disk_size("10G").unwrap(), 10 * 1024 * 1024 * 1024);
        assert_eq!(parse_disk_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_disk_size("1.5G").unwrap(), 1_610_612_736);
        assert!(parse_disk_size("").is_err());
        assert!(parse_disk_size("ten").is_err());
        assert!(parse_disk_size("-5G").is_err());
    }

    #[test]
    fn resolve_rootfs_arg_resolves_bare_name_from_images_dir() {
        let data_dir = tempfile::tempdir().unwrap();
        let images = data_dir.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::write(images.join("alpine-x86_64.ext4"), b"img").unwrap();

        // A bare image name resolves to the images directory.
        let resolved = resolve_rootfs_arg(PathBuf::from("alpine-x86_64.ext4"), data_dir.path());
        assert_eq!(resolved, images.join("alpine-x86_64.ext4"));
    }

    #[test]
    fn resolve_rootfs_arg_prefers_an_existing_path_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let explicit = dir.path().join("custom.ext4");
        std::fs::write(&explicit, b"img").unwrap();

        // An existing path is used unchanged, even if a same-named image exists.
        let resolved = resolve_rootfs_arg(explicit.clone(), dir.path());
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_rootfs_arg_returns_input_when_unresolvable() {
        let data_dir = tempfile::tempdir().unwrap();
        // Neither the path nor an image of that name exists: return the input so
        // the caller can surface a clear "rootfs not found" error.
        let arg = PathBuf::from("does-not-exist.ext4");
        assert_eq!(resolve_rootfs_arg(arg.clone(), data_dir.path()), arg);
    }
}
