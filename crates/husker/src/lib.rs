use std::path::{Path, PathBuf};

#[cfg(all(target_os = "linux", feature = "linux-net"))]
pub mod firecracker;
pub mod images;

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

/// Serde helper: wraps `default_initrd_path` in `Some` so `default_initrd`
/// in the CLI Config defaults to the computed initramfs path rather than
/// None. Users can explicitly set it to `null` in config to opt out.
pub fn default_initrd_some() -> Option<PathBuf> {
    Some(default_initrd_path())
}
