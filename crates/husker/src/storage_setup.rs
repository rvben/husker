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

const SCRIPT_TEMPLATE: &str = include_str!("templates/setup-storage.sh.tmpl");

/// Render the operator-run migration bash script from the plan.
pub fn render_migration_script(plan: &StorageSetupPlan) -> String {
    let alloc_line = if plan.thin {
        // Thin: sparse image. ENOSPC inside the volume becomes an XFS I/O error
        // on the backing fs, not a clean guest ENOSPC - hence the warning.
        "log \"WARNING: --thin loopback is sparse; if the backing fs fills, \
             the volume can hit I/O errors, not clean ENOSPC\"; truncate -s \"$SIZE\" \"$IMAGE_PATH\""
            .to_string()
    } else {
        "fallocate -l \"$SIZE\" \"$IMAGE_PATH\"".to_string()
    };
    // Render only the chosen mkfs so a btrfs script never mentions mkfs.xfs.
    let mkfs_line = match plan.fs {
        SetupFs::Xfs => "mkfs.xfs -q -m reflink=1 \"$IMAGE_PATH\"",
        SetupFs::Btrfs => "mkfs.btrfs -q \"$IMAGE_PATH\"",
    };
    SCRIPT_TEMPLATE
        .replace("{{DATA_DIR}}", &plan.data_dir.display().to_string())
        .replace("{{STATE_DIR}}", &plan.state_dir.display().to_string())
        .replace("{{IMAGE_PATH}}", &plan.image_path.display().to_string())
        .replace("{{SIZE}}", &plan.size)
        .replace("{{FS}}", plan.fs.name())
        .replace("{{CONFIG_FILE}}", &plan.config_file.display().to_string())
        .replace("{{API_ADDR}}", &plan.api_addr)
        .replace(
            "{{PERSIST}}",
            match plan.persist {
                SetupPersist::Systemd => "systemd",
                SetupPersist::Fstab => "fstab",
            },
        )
        .replace("{{ALLOC_LINE}}", &alloc_line)
        .replace("{{MKFS_LINE}}", mkfs_line)
        .replace("{{FSTAB_LINE}}", &render_fstab_line(plan))
        .replace("{{SYSTEMD_UNIT}}", render_systemd_mount_unit(plan).trim_end())
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

    #[test]
    fn migration_script_substitutes_and_orders_correctly() {
        let s = render_migration_script(&sample_plan());
        // tokens substituted
        assert!(s.contains("DATA_DIR=\"/var/lib/husker\""));
        assert!(s.contains("STATE_DIR=\"/var/lib/husker-state\""));
        assert!(s.contains("IMAGE_PATH=\"/var/lib/husker.img\""));
        assert!(!s.contains("{{"), "unsubstituted token remains");
        // safety-critical content
        assert!(s.contains("set -euo pipefail"));
        assert!(s.contains("rsync -aHAXS --numeric-ids"));
        assert!(s.contains("mkfs.xfs"));
        assert!(s.contains("systemd-escape -p --suffix=mount"));
        assert!(s.contains(".pre-reflink.bak"));
        assert!(s.contains(".husker-storage-volume")); // sentinel
        // ORDER: config write must precede the state relocate, which must precede
        // the destructive `mv` of the data dir.
        let cfg = s.find("STEP 2: write config").expect("step 2 present");
        let reloc = s.find("STEP 3: relocate state").expect("step 3 present");
        let swap = s.find("STEP 7: swap").expect("step 7 present");
        assert!(cfg < reloc && reloc < swap, "destructive steps out of order");
        // preallocated by default (not thin)
        assert!(s.contains("fallocate -l"));
    }

    #[test]
    fn migration_script_thin_uses_truncate_and_warns() {
        let mut plan = sample_plan();
        plan.thin = true;
        let s = render_migration_script(&plan);
        assert!(s.contains("truncate -s"));
        assert!(s.to_lowercase().contains("thin"));
    }

    #[test]
    fn migration_script_verify_is_failure_safe() {
        let s = render_migration_script(&sample_plan());
        // The verify must capture output (so a failing rsync is caught), not pipe
        // into grep (which conflates "rsync failed" with "no differences").
        assert!(s.contains("VERIFY_OUT="), "verify must capture rsync output");
        assert!(
            !s.contains("--checksum \"${DATA_DIR}/\" \"${STAGING}/\" | grep"),
            "verify must not pipe rsync into grep"
        );
    }

    #[test]
    fn migration_script_btrfs_uses_mkfs_btrfs() {
        let mut plan = sample_plan();
        plan.fs = SetupFs::Btrfs;
        let s = render_migration_script(&plan);
        assert!(s.contains("mkfs.btrfs"));
        assert!(!s.contains("mkfs.xfs"));
    }
}
