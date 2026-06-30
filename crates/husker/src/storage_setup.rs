//! Generator for the one-time `husker setup storage` migration.

use std::path::PathBuf;

/// Filesystem for the reflink-capable loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupFs {
    Xfs,
    Btrfs,
}

impl SetupFs {
    fn name(self) -> &'static str {
        match self {
            SetupFs::Xfs => "xfs",
            SetupFs::Btrfs => "btrfs",
        }
    }
}

/// How the loopback mount is persisted across reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupPersist {
    Systemd,
    Fstab,
}

/// A fully resolved migration plan. Pure data; the render functions turn it
/// into the operator-run artifacts.
#[derive(Debug, Clone)]
pub struct StorageSetupPlan {
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub image_path: PathBuf,
    pub size: String,
    pub fs: SetupFs,
    pub persist: SetupPersist,
    pub thin: bool,
    pub config_file: PathBuf,
    pub api_addr: String,
}

/// systemd `.mount` unit body. The unit FILENAME is computed by the generated
/// script at run time via `systemd-escape -p --suffix=mount <data_dir>` (the
/// only correct name for the mountpoint), so we render only the content here.
pub fn render_systemd_mount_unit(plan: &StorageSetupPlan) -> String {
    format!(
        "[Unit]\n\
         Description=husker storage volume ({data})\n\n\
         [Mount]\n\
         What={image}\n\
         Where={data}\n\
         Type={fs}\n\
         Options=loop\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        data = plan.data_dir.display(),
        image = plan.image_path.display(),
        fs = plan.fs.name(),
    )
}

/// `/etc/fstab` line equivalent. `nofail` so a missing image never blocks boot
/// (the daemon mount guard catches an unmounted volume instead).
pub fn render_fstab_line(plan: &StorageSetupPlan) -> String {
    format!(
        "{image} {data} {fs} loop,nofail 0 0",
        image = plan.image_path.display(),
        data = plan.data_dir.display(),
        fs = plan.fs.name(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> StorageSetupPlan {
        StorageSetupPlan {
            data_dir: PathBuf::from("/var/lib/husker"),
            state_dir: PathBuf::from("/var/lib/husker-state"),
            image_path: PathBuf::from("/var/lib/husker.img"),
            size: "50G".into(),
            fs: SetupFs::Xfs,
            persist: SetupPersist::Systemd,
            thin: false,
            config_file: PathBuf::from("/etc/husker/config.toml"),
            api_addr: "127.0.0.1:7777".into(),
        }
    }

    #[test]
    fn systemd_mount_unit_has_loop_and_paths() {
        let u = render_systemd_mount_unit(&sample_plan());
        assert!(u.contains("What=/var/lib/husker.img"));
        assert!(u.contains("Where=/var/lib/husker"));
        assert!(u.contains("Type=xfs"));
        assert!(u.contains("Options=loop"));
        assert!(u.contains("[Mount]"));
    }

    #[test]
    fn fstab_line_is_loop_mount() {
        let line = render_fstab_line(&sample_plan());
        assert_eq!(
            line,
            "/var/lib/husker.img /var/lib/husker xfs loop,nofail 0 0"
        );
    }
}
