//! Generator for the one-time `husker setup storage` migration.

use std::path::{Path, PathBuf};

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

/// Caller-supplied options (from the CLI flags).
#[derive(Debug, Clone)]
pub struct StorageSetupOptions {
    pub state_dir: Option<PathBuf>,
    pub image_path: Option<PathBuf>,
    pub size: Option<String>,
    pub fs: SetupFs,
    pub persist: SetupPersist,
    pub thin: bool,
}

/// Host facts gathered by the caller (injected so the builder stays pure).
#[derive(Debug, Clone)]
pub struct StorageSetupHostFacts {
    pub reflink: husker_storage::ReflinkStatus,
    pub free_bytes: u64,
    pub bulk_usage_bytes: u64,
    pub mkfs_available: bool,
    pub rsync_available: bool,
    pub is_local_context: bool,
}

/// Result of planning: a no-op (already reflink) or a validated plan.
#[derive(Debug)]
pub enum SetupOutcome {
    AlreadyReflink,
    Plan(StorageSetupPlan),
}

/// Why a plan could not be built. Maps to a process exit code.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("setup storage runs on the daemon host; ssh to it and run there")]
    RemoteContext,
    #[error("required tool not found on PATH: {0}")]
    MissingTool(String),
    #[error("insufficient space: need >= {needed} bytes free, have {have}")]
    InsufficientSpace { needed: u64, have: u64 },
    #[error("{0} must not live under the data dir (the mount would hide it)")]
    PathUnderDataDir(PathBuf),
}

impl SetupError {
    pub fn exit_code(&self) -> i32 {
        // All generate-time refusals are GENERAL(1); the daemon-running CONFLICT
        // is enforced by the generated script at run time, not here.
        1
    }
}

/// Margin (bytes) required on top of the current bulk usage, since the
/// migration transiently holds the original bulk plus the loopback copy.
const SPACE_MARGIN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn human_size(bytes: u64) -> String {
    let gib = bytes.div_ceil(1024 * 1024 * 1024).max(1);
    format!("{gib}G")
}

/// Build a validated migration plan from config + flags + injected host facts.
pub fn build_storage_setup_plan(
    data_dir: &Path,
    config_file: &Path,
    api_addr: &str,
    opts: StorageSetupOptions,
    facts: &StorageSetupHostFacts,
) -> Result<SetupOutcome, SetupError> {
    if !facts.is_local_context {
        return Err(SetupError::RemoteContext);
    }
    if matches!(facts.reflink, husker_storage::ReflinkStatus::Supported) {
        return Ok(SetupOutcome::AlreadyReflink);
    }
    if !facts.mkfs_available {
        return Err(SetupError::MissingTool(match opts.fs {
            SetupFs::Xfs => "mkfs.xfs".into(),
            SetupFs::Btrfs => "mkfs.btrfs".into(),
        }));
    }
    if !facts.rsync_available {
        return Err(SetupError::MissingTool("rsync".into()));
    }

    let state_dir = opts
        .state_dir
        .unwrap_or_else(|| sibling(data_dir, "-state"));
    let image_path = opts
        .image_path
        .unwrap_or_else(|| sibling(data_dir, ".img"));
    if state_dir.starts_with(data_dir) {
        return Err(SetupError::PathUnderDataDir(state_dir));
    }
    if image_path.starts_with(data_dir) {
        return Err(SetupError::PathUnderDataDir(image_path));
    }

    let needed = facts.bulk_usage_bytes + SPACE_MARGIN_BYTES;
    if facts.free_bytes < needed {
        return Err(SetupError::InsufficientSpace {
            needed,
            have: facts.free_bytes,
        });
    }
    // Default loopback size: the current bulk plus a fixed headroom margin
    // (preallocated, so we keep it conservative; the operator sizes up with
    // --size if they expect growth). The precondition guarantees free >= needed.
    let size = opts.size.unwrap_or_else(|| human_size(needed));

    Ok(SetupOutcome::Plan(StorageSetupPlan {
        data_dir: data_dir.to_path_buf(),
        state_dir,
        image_path,
        size,
        fs: opts.fs,
        persist: opts.persist,
        thin: opts.thin,
        config_file: config_file.to_path_buf(),
        api_addr: api_addr.to_string(),
    }))
}

/// `<dir><suffix>` as a sibling path (e.g. `/var/lib/husker` + `-state`).
fn sibling(dir: &Path, suffix: &str) -> PathBuf {
    let mut s = dir.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
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

#[cfg(test)]
mod build_tests {
    use super::*;
    use husker_storage::ReflinkStatus;

    fn facts() -> StorageSetupHostFacts {
        StorageSetupHostFacts {
            reflink: ReflinkStatus::FullCopy,
            free_bytes: 100 * 1024 * 1024 * 1024,
            bulk_usage_bytes: 5 * 1024 * 1024 * 1024,
            mkfs_available: true,
            rsync_available: true,
            is_local_context: true,
        }
    }
    fn opts() -> StorageSetupOptions {
        StorageSetupOptions {
            state_dir: None,
            image_path: None,
            size: None,
            fs: SetupFs::Xfs,
            persist: SetupPersist::Systemd,
            thin: false,
        }
    }
    fn build(o: StorageSetupOptions, f: StorageSetupHostFacts) -> Result<SetupOutcome, SetupError> {
        build_storage_setup_plan(
            std::path::Path::new("/var/lib/husker"),
            std::path::Path::new("/etc/husker/config.toml"),
            "127.0.0.1:7777",
            o,
            &f,
        )
    }

    #[test]
    fn default_plan_uses_sibling_state_and_image() {
        let SetupOutcome::Plan(p) = build(opts(), facts()).unwrap() else {
            panic!("expected a plan");
        };
        assert_eq!(p.state_dir, std::path::PathBuf::from("/var/lib/husker-state"));
        assert_eq!(p.image_path, std::path::PathBuf::from("/var/lib/husker.img"));
        assert!(!p.thin);
    }

    #[test]
    fn already_reflink_is_a_noop() {
        let mut f = facts();
        f.reflink = ReflinkStatus::Supported;
        assert!(matches!(build(opts(), f).unwrap(), SetupOutcome::AlreadyReflink));
    }

    #[test]
    fn non_local_context_refused() {
        let mut f = facts();
        f.is_local_context = false;
        let e = build(opts(), f).unwrap_err();
        assert!(matches!(e, SetupError::RemoteContext));
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn missing_tools_refused() {
        let mut f = facts();
        f.mkfs_available = false;
        assert!(matches!(build(opts(), f).unwrap_err(), SetupError::MissingTool(_)));
    }

    #[test]
    fn insufficient_space_refused() {
        let mut f = facts();
        f.free_bytes = 1024 * 1024 * 1024; // 1 GiB, less than bulk + margin
        assert!(matches!(build(opts(), f).unwrap_err(), SetupError::InsufficientSpace { .. }));
    }

    #[test]
    fn state_dir_under_data_dir_refused() {
        let mut o = opts();
        o.state_dir = Some(std::path::PathBuf::from("/var/lib/husker/state"));
        assert!(matches!(build(o, facts()).unwrap_err(), SetupError::PathUnderDataDir(_)));
    }
}
