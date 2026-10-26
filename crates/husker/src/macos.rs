//! `husker macos`: install, list and provision macOS guest images in this
//! host's data dir.
//!
//! These commands run in the CLI process, not the daemon: installing drives
//! Virtualization.framework directly, and provisioning edits the guest disk
//! as root. The daemon only reads the finished bundles when booting a VM.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, Result, bail};
use husker_core::macos_guest::{MacOsImageRef, macos_images_dir, validate_macos_image_name};
use husker_vmm::macos_bundle::{BundleLock, MacOsBundle, MacOsBundleManifest};
use serde::Serialize;

use crate::cli::{MacosAction, OutputFormat};
use crate::cli_contract::{CliErrorKind, structured_output};
use crate::daemon_client::ApiFailure;

/// Where `macos provision` installs the agent inside the guest. `/usr/local`
/// is firmlinked to the Data volume, so the file survives the sealed System
/// volume.
const GUEST_AGENT_PATH: &str = "/usr/local/libexec/husker";
/// The guest LaunchDaemon that keeps `husker guest-agent` running.
const GUEST_AGENT_LABEL: &str = "dev.husker.guest-agent";

#[derive(Debug, Serialize)]
struct MacosImage {
    name: String,
    path: String,
    build: String,
    os_version: String,
    disk_size_bytes: u64,
    min_cpus: u32,
    min_memory_mib: u32,
    agent_provisioned: bool,
}

impl MacosImage {
    fn new(bundle: &MacOsBundle, manifest: MacOsBundleManifest) -> Self {
        Self {
            name: bundle
                .dir()
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: bundle.dir().display().to_string(),
            build: manifest.build,
            os_version: manifest.os_version,
            disk_size_bytes: manifest.disk_size_bytes,
            min_cpus: manifest.min_cpus,
            min_memory_mib: manifest.min_memory_mib,
            agent_provisioned: manifest.agent_provisioned,
        }
    }

    fn print_text(&self) {
        println!(
            "{}\tmacOS {} ({})\t{} GiB disk\tagent: {}\t{}",
            self.name,
            self.os_version,
            self.build,
            self.disk_size_bytes >> 30,
            if self.agent_provisioned {
                "provisioned"
            } else {
                "not provisioned"
            },
            self.path,
        );
    }
}

fn failure(kind: CliErrorKind, message: String, hint: Option<&str>) -> anyhow::Error {
    ApiFailure::with_kind(kind, message, hint.map(str::to_string)).into()
}

fn usage_failure(message: String) -> anyhow::Error {
    failure(CliErrorKind::InvalidUsage, message, None)
}

/// Check `--cpus`/`--memory` against the restore image before anything is
/// downloaded or created. A shape below the image's minimum is the caller's
/// request at fault, so it fails as invalid usage; a host that cannot run the
/// image at all stays a general failure.
#[cfg(target_os = "macos")]
fn require_install_shape(
    image: &husker_vmm::apple_vz_macos::RestoreImageInfo,
    cpus: Option<u32>,
    memory: Option<u32>,
) -> Result<()> {
    image.require_supported()?;
    image.require_shape(cpus, memory).map_err(|e| match e {
        husker_vmm::VmmError::InvalidConfig(msg) => usage_failure(msg),
        other => other.into(),
    })?;
    Ok(())
}

pub(crate) async fn command(
    data_dir: &Path,
    action: MacosAction,
    output: OutputFormat,
) -> Result<()> {
    match action {
        #[cfg(not(target_os = "macos"))]
        MacosAction::Install { .. } => bail!("{}", husker_vmm::MACOS_GUEST_UNSUPPORTED),
        #[cfg(target_os = "macos")]
        MacosAction::Install {
            name,
            ipsw,
            download_dir,
            keep_ipsw,
            disk_size,
            cpus,
            memory,
        } => {
            let source = match ipsw {
                Some(path) => IpswSource::Local(path),
                None => IpswSource::Download {
                    dir: download_dir,
                    keep: keep_ipsw,
                },
            };
            let request = InstallOptions {
                name,
                source,
                disk_size_bytes: husker::parse_disk_size(&disk_size)?,
                cpus,
                memory,
            };
            let image = install(data_dir, request, output).await?;
            print_action("install", &image, output)
        }
        MacosAction::List => list(data_dir, output),
        MacosAction::Provision { image } => {
            let image = provision(data_dir, &image)?;
            print_action("provision", &image, output)
        }
    }
}

fn print_action(action: &str, image: &MacosImage, output: OutputFormat) -> Result<()> {
    if output == OutputFormat::Json {
        let value = structured_output(
            &format!("macos {action}"),
            &serde_json::json!({"status": "ok", "action": action, "image": image}),
        )?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        image.print_text();
    }
    Ok(())
}

/// The complete bundles under the data dir's macOS image directory, by name.
/// Install staging dirs and downloads (dot-prefixed), stray files and
/// incomplete bundles are left out; an incomplete bundle is reported on
/// stderr so a half-finished install is not mistaken for a missing one.
fn installed_images(data_dir: &Path) -> Result<Vec<MacosImage>> {
    let dir = macos_images_dir(data_dir);
    let mut images = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if validate_macos_image_name(&name).is_err() || !entry.path().is_dir() {
            continue;
        }
        let bundle = MacOsBundle::new(entry.path());
        match bundle.validate() {
            Ok(manifest) => images.push(MacosImage::new(&bundle, manifest)),
            Err(e) => eprintln!("warning: skipping {}: {e}", entry.path().display()),
        }
    }
    images.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(images)
}

fn list(data_dir: &Path, output: OutputFormat) -> Result<()> {
    let images = installed_images(data_dir)?;
    if output == OutputFormat::Json {
        let value = structured_output(
            "macos list",
            &serde_json::json!({"status": "ok", "action": "list", "images": images}),
        )?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else if images.is_empty() {
        println!("No macOS images installed (install one with `husker macos install <name>`)");
    } else {
        for image in &images {
            image.print_text();
        }
    }
    Ok(())
}

/// Where `husker macos install` gets its restore image.
#[cfg(target_os = "macos")]
enum IpswSource {
    /// A restore image the user already has. It is read in place and never
    /// deleted.
    Local(PathBuf),
    /// The latest restore image this host supports, downloaded into `dir`
    /// (default `<data_dir>/macos/.downloads`). It is only needed during the
    /// install, so it is deleted afterwards unless `keep` is set.
    Download { dir: Option<PathBuf>, keep: bool },
}

#[cfg(target_os = "macos")]
struct InstallOptions {
    name: String,
    source: IpswSource,
    disk_size_bytes: u64,
    cpus: Option<u32>,
    memory: Option<u32>,
}

#[cfg(target_os = "macos")]
async fn install(
    data_dir: &Path,
    request: InstallOptions,
    output: OutputFormat,
) -> Result<MacosImage> {
    use husker_vmm::apple_vz_macos;

    let InstallOptions {
        name,
        source,
        disk_size_bytes,
        cpus,
        memory,
    } = request;
    let name = name.as_str();

    if let Err(e) = validate_macos_image_name(name) {
        return Err(usage_failure(e.to_string()));
    }
    // Checked here as well as by the installer, so a bad size fails before
    // a restore image is downloaded for it.
    if disk_size_bytes < apple_vz_macos::MIN_DISK_SIZE_BYTES {
        return Err(usage_failure(format!(
            "--disk-size: macOS needs a disk of at least {} GiB",
            apple_vz_macos::MIN_DISK_SIZE_BYTES >> 30
        )));
    }
    let images_dir = macos_images_dir(data_dir);
    std::fs::create_dir_all(&images_dir)
        .with_context(|| format!("creating {}", images_dir.display()))?;
    // Held for the whole install: a second install of the same name would
    // otherwise take this one's staging directory for a stale leftover and
    // delete it mid-install.
    let _install_lock = lock_or_conflict(
        &images_dir.join(format!(".{name}.lock")),
        &format!("another `husker macos install {name}` is in progress"),
    )?;
    let target = images_dir.join(name);
    if target.exists() {
        return Err(failure(
            CliErrorKind::Conflict,
            format!(
                "macOS image '{name}' already exists at {}",
                target.display()
            ),
            None,
        ));
    }

    // Install into a dot-prefixed staging dir and rename on success, so an
    // interrupted install never occupies the name. A leftover staging dir is
    // from an install that did not finish.
    let staging = images_dir.join(format!(".{name}.installing"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("removing stale {}", staging.display()))?;
    }

    // Held until the install is over, so a concurrent install of the same
    // build never starts from a restore image this one is about to delete.
    let mut _download_lock = None;
    let (ipsw, delete_after_install) = match source {
        IpswSource::Local(path) => {
            let image = apple_vz_macos::load_restore_image(&path).await?;
            require_install_shape(&image, cpus, memory)?;
            (path, false)
        }
        IpswSource::Download { dir, keep } => {
            let latest = apple_vz_macos::fetch_latest_restore_image().await?;
            require_install_shape(&latest, cpus, memory)?;
            let downloads = dir.unwrap_or_else(|| images_dir.join(".downloads"));
            std::fs::create_dir_all(&downloads)
                .with_context(|| format!("creating {}", downloads.display()))?;
            // Installs under different names share the download cache; the
            // lock keeps two of them from writing the same `.part` file.
            _download_lock = Some(lock_or_conflict(
                &downloads.join(format!("{}.lock", latest.build)),
                &format!(
                    "another install is downloading macOS {}; retry once it finishes",
                    latest.build
                ),
            )?);
            let dest = downloads.join(format!("{}.ipsw", latest.build));
            // A restore image already in the download directory may be one
            // the user kept or placed there, so only this run's own download
            // is deleted after the install.
            let reused = dest.is_file();
            if reused {
                eprintln!(
                    "Using downloaded macOS {} ({}), kept after the install: {}",
                    latest.os_version,
                    latest.build,
                    dest.display()
                );
            } else {
                eprintln!(
                    "Downloading macOS {} ({}) from {}",
                    latest.os_version, latest.build, latest.url
                );
                download(&latest.url, &dest, output).await?;
            }
            (dest, !keep && !reused)
        }
    };

    let text = output != OutputFormat::Json;
    let manifest = apple_vz_macos::install(
        apple_vz_macos::InstallRequest {
            bundle: staging.clone(),
            ipsw: ipsw.clone(),
            disk_size_bytes,
            vcpu_count: cpus,
            mem_size_mib: memory,
        },
        move |fraction| {
            if text {
                eprintln!("Installing macOS: {:.0}%", fraction * 100.0);
            }
        },
    )
    .await?;
    std::fs::rename(&staging, &target)
        .with_context(|| format!("renaming {} -> {}", staging.display(), target.display()))?;
    if delete_after_install {
        // The image is installed, so a failure here only leaves disk space
        // in use; it does not fail the install.
        match std::fs::remove_file(&ipsw) {
            Ok(()) => eprintln!(
                "Deleted the restore image {} (pass --keep-ipsw to keep it)",
                ipsw.display()
            ),
            Err(e) => eprintln!(
                "warning: could not delete the restore image {}: {e}",
                ipsw.display()
            ),
        }
    }
    eprintln!(
        "Installed macOS {}. Next: sudo husker macos provision {}",
        manifest.os_version,
        target.display()
    );
    Ok(MacosImage::new(&MacOsBundle::new(&target), manifest))
}

/// Take an exclusive lock at `path`, or fail with a `conflict` when another
/// process holds it.
#[cfg(target_os = "macos")]
fn lock_or_conflict(path: &Path, held_message: &str) -> Result<std::fs::File> {
    crate::daemon::try_lock_exclusive(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            failure(CliErrorKind::Conflict, held_message.into(), None)
        } else {
            anyhow::Error::new(e).context(format!("locking {}", path.display()))
        }
    })
}

/// Fail before a download that cannot fit, rather than filling the disk
/// partway through it.
#[cfg(target_os = "macos")]
fn ensure_free_space(dir: &Path, needed: u64) -> Result<()> {
    let available = available_bytes(dir)?;
    if available < needed {
        return Err(failure(
            CliErrorKind::Error,
            format!(
                "the restore image needs {} MiB but only {} MiB is free in {}",
                needed >> 20,
                available >> 20,
                dir.display()
            ),
            Some(
                "free disk space, download to another disk with --download-dir, or pass an existing restore image with --ipsw",
            ),
        ));
    }
    Ok(())
}

/// Bytes an unprivileged process can still write to the filesystem holding
/// `dir`.
#[cfg(target_os = "macos")]
fn available_bytes(dir: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .with_context(|| format!("invalid path {}", dir.display()))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` is a writable statvfs.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statvfs {}", dir.display()));
    }
    // SAFETY: statvfs returned 0, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    Ok(u64::from(stat.f_bavail) * stat.f_frsize)
}

/// Stream `url` to `dest` through a `.part` file, checking the length the
/// server announced. The restore image is validated again when it is loaded.
#[cfg(target_os = "macos")]
async fn download(url: &str, dest: &Path, output: OutputFormat) -> Result<()> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut resp = husker::http::client(husker::http::HttpTimeouts::default())?
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?;
    // Without a length a dropped connection is indistinguishable from a
    // finished download, and the truncated file would be cached for reuse.
    let total = resp
        .content_length()
        .with_context(|| format!("GET {url}: the server did not report the restore image size"))?;
    // A partial file from an interrupted earlier download would count against
    // the free space this one needs. The caller's download lock means no
    // other process is writing it.
    let part = dest.with_extension("ipsw.part");
    match tokio::fs::remove_file(&part).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", part.display())),
    }
    if let Some(parent) = dest.parent() {
        ensure_free_space(parent, total)?;
    }
    let result = write_download(&mut resp, &part, total, output).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&part).await;
    }
    result?;
    tokio::fs::rename(&part, dest)
        .await
        .with_context(|| format!("renaming {} -> {}", part.display(), dest.display()))
}

/// Stream the response body into `part`, checking it delivered `total` bytes.
#[cfg(target_os = "macos")]
async fn write_download(
    resp: &mut reqwest::Response,
    part: &Path,
    total: u64,
    output: OutputFormat,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(part)
        .await
        .with_context(|| format!("creating {}", part.display()))?;
    let mut written: u64 = 0;
    let mut reported_percent = None;
    while let Some(chunk) = resp.chunk().await.context("reading restore image")? {
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing {}", part.display()))?;
        written += chunk.len() as u64;
        if output != OutputFormat::Json {
            let percent = written * 100 / total.max(1);
            if reported_percent != Some(percent) {
                reported_percent = Some(percent);
                eprint!("\rDownloading: {percent}% of {} MiB", total >> 20);
            }
        }
    }
    file.sync_all().await.context("flushing restore image")?;
    if output != OutputFormat::Json {
        eprintln!();
    }
    if written != total {
        bail!("restore image download truncated: got {written} of {total} bytes");
    }
    Ok(())
}

/// Install the guest agent into a bundle's disk: the husker binary itself
/// (run as `husker guest-agent`), a root LaunchDaemon that starts it at boot,
/// and the marker that skips Setup Assistant so a headless guest boots
/// straight to a running system.
fn provision(data_dir: &Path, image: &str) -> Result<MacosImage> {
    let bundle = MacOsImageRef::parse(image)
        .map_err(|e| usage_failure(e.to_string()))?
        .resolve(data_dir)
        .map_err(|e| {
            failure(
                CliErrorKind::NotFound,
                e.to_string(),
                Some("under sudo, pass the bundle directory path; sudo may change HOME and with it the data dir"),
            )
        })?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(failure(
            CliErrorKind::PermissionDenied,
            "provisioning writes root-owned files into the guest disk and must run as root".into(),
            Some(&format!(
                "sudo husker macos provision {}",
                bundle.dir().display()
            )),
        ));
    }
    let agent = std::env::current_exe().context("locating the husker binary")?;
    let bundle_dir = bundle.try_lock(true)?.ok_or_else(|| {
        failure(
            CliErrorKind::Conflict,
            format!(
                "{} is in use: a VM is being created from it, or another provision is running",
                bundle.dir().display()
            ),
            Some("retry once it finishes"),
        )
    })?;
    let signals = DeferredSignals::install()?;
    // Validated under the lock, so another provision cannot change the
    // manifest in between. Every later root write goes through the locked
    // descriptor; the path must still name it, or the owner swapped it.
    let mut manifest = bundle.validate()?;
    {
        use std::os::unix::fs::MetadataExt;
        let locked = bundle_dir
            .dir()
            .metadata()
            .context("reading the locked bundle")?;
        let now = std::fs::symlink_metadata(bundle.dir())
            .with_context(|| format!("reading {}", bundle.dir().display()))?;
        if (locked.dev(), locked.ino()) != (now.dev(), now.ino()) {
            bail!(
                "{} changed while it was being provisioned",
                bundle.dir().display()
            );
        }
    }

    // A fresh 0700 directory, so no other local user can pre-create or
    // swap the Data volume's mount point inside it. Kept rather than
    // auto-deleted: a recursive delete of a mount root whose detach failed
    // would walk into the still-mounted guest disk.
    let mount_root = tempfile::Builder::new()
        .prefix("husker-provision-")
        .tempdir()
        .context("creating the provisioning mount directory")?
        .keep();
    // Marked unprovisioned while the disk is being written, so a provision
    // that fails part way (a truncated agent binary) leaves an image VMs
    // refuse to boot rather than one that looks ready.
    if manifest.agent_provisioned {
        manifest.agent_provisioned = false;
        bundle.write_manifest_in(&bundle_dir, &manifest)?;
    }
    let result = provision_disk(&bundle, &bundle_dir, &mount_root, &agent, &signals);
    let _ = std::fs::remove_dir(&mount_root);
    result?;
    signals.check()?;

    manifest.agent_provisioned = true;
    bundle.write_manifest_in(&bundle_dir, &manifest)?;
    Ok(MacosImage::new(&bundle, manifest))
}

fn provision_disk(
    bundle: &MacOsBundle,
    bundle_dir: &BundleLock,
    mount_root: &Path,
    agent: &Path,
    signals: &DeferredSignals,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // The image is attached as the bundle's owner, so the owner's own file
    // permissions decide which file is attached: a `disk.img` that links to
    // an image the owner cannot write never reaches a read-write root mount.
    let owner = bundle_dir
        .dir()
        .metadata()
        .with_context(|| format!("reading {}", bundle.dir().display()))?;
    let mut attached = AttachedDisk::attach(&bundle.disk_path(), owner.uid(), owner.gid())?;
    let data = attached.mount_data_volume(mount_root).with_context(|| {
        format!(
            "mounting the macOS Data volume of {}; is it a completed install?",
            bundle.disk_path().display()
        )
    })?;
    signals.check()?;
    install_agent_files(&data, agent)?;
    attached.detach()
}

/// Write the agent binary, its LaunchDaemon and the Setup Assistant marker
/// under a mounted Data volume root. Every file ends up owned by the caller
/// (root:wheel when provisioning) because launchd refuses daemon plists owned
/// by anyone else.
fn install_agent_files(data_root: &Path, agent: &Path) -> Result<()> {
    let binary = std::fs::read(agent).with_context(|| format!("reading {}", agent.display()))?;
    write_confined(data_root, GUEST_AGENT_PATH, &binary, 0o755)?;
    write_confined(
        data_root,
        &format!("/Library/LaunchDaemons/{GUEST_AGENT_LABEL}.plist"),
        launch_daemon_plist().as_bytes(),
        0o644,
    )?;
    write_confined(data_root, "/private/var/db/.AppleSetupDone", b"", 0o644)
}

/// Write `contents` to `guest_path` beneath `root` without following any
/// symlink on the way. The guest disk is guest-controlled and this runs as
/// root, so a symlinked component or destination must fail the write rather
/// than redirect it onto the host. Each component is opened relative to its
/// parent with `O_NOFOLLOW` and missing directories are created in place.
/// The file itself is written to a freshly created temporary name and renamed
/// over the destination, so an existing guest inode there (a FIFO or a device
/// node as much as a symlink) is replaced, never opened.
fn write_confined(root: &Path, guest_path: &str, contents: &[u8], mode: u32) -> Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let display = || {
        root.join(guest_path.trim_start_matches('/'))
            .display()
            .to_string()
    };
    let open_at = |dir: &OwnedFd, name: &str, flags: libc::c_int, mode: libc::c_uint| {
        let c_name = CString::new(name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `dir` is an open descriptor and `c_name` is NUL-terminated.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), c_name.as_ptr(), flags, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and is owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };

    let c_root = CString::new(root.as_os_str().as_bytes()).context("root contains a NUL byte")?;
    // SAFETY: `c_root` is NUL-terminated.
    let fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening {}", root.display()));
    }
    // SAFETY: `fd` was just returned by open and is owned by nobody else.
    let mut dir = unsafe { OwnedFd::from_raw_fd(fd) };

    let components: Vec<&str> = guest_path.split('/').filter(|c| !c.is_empty()).collect();
    let Some((file_name, parents)) = components.split_last() else {
        bail!("guest path {guest_path:?} names no file");
    };
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    for component in parents {
        if matches!(*component, "." | "..") {
            bail!("guest path {guest_path:?} must not contain . or ..");
        }
        let c_component = CString::new(*component).context("path component contains a NUL byte")?;
        // SAFETY: `dir` is an open descriptor and `c_component` is NUL-terminated.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), c_component.as_ptr(), 0o755) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(err).with_context(|| format!("creating {component} for {}", display()));
            }
        }
        dir = open_at(&dir, component, dir_flags, 0).with_context(|| {
            format!(
                "opening {component} for {} (a symlink is refused)",
                display()
            )
        })?;
    }

    if matches!(*file_name, "." | "..") {
        bail!("guest path {guest_path:?} names no file");
    }
    let tmp_name = format!(".{file_name}.husker-provision");
    let c_tmp = CString::new(tmp_name.as_str()).context("file name contains a NUL byte")?;
    let c_file = CString::new(*file_name).context("file name contains a NUL byte")?;
    // A leftover from an interrupted provision, or anything the guest put
    // there. unlinkat never follows a symlink.
    // SAFETY: `dir` is an open descriptor and `c_tmp` is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c_tmp.as_ptr(), 0) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).with_context(|| format!("clearing {tmp_name} for {}", display()));
        }
    }
    let file = open_at(
        &dir,
        &tmp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        mode as libc::c_uint,
    )
    .with_context(|| format!("creating a temporary file for {}", display()))?;
    // SAFETY: `file` is an open descriptor; geteuid and getegid have no
    // preconditions.
    if unsafe { libc::fchown(file.as_raw_fd(), libc::geteuid(), libc::getegid()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chown {}", display()));
    }
    // SAFETY: `file` is an open descriptor.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("chmod {}", display()));
    }
    let mut file = std::fs::File::from(file);
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", display()))?;
    // SAFETY: `dir` is an open descriptor and both names are NUL-terminated.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            c_tmp.as_ptr(),
            dir.as_raw_fd(),
            c_file.as_ptr(),
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlinkat(dir.as_raw_fd(), c_tmp.as_ptr(), 0) };
        return Err(err).with_context(|| format!("replacing {}", display()));
    }
    Ok(())
}

fn launch_daemon_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{GUEST_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{GUEST_AGENT_PATH}</string>
        <string>guest-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/husker-guest-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/husker-guest-agent.log</string>
</dict>
</plist>
"#
    )
}

/// The signal that interrupted a provision, or 0.
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn record_signal(signal: libc::c_int) {
    // A second signal means the user does not want to wait for the cleanup.
    if PENDING_SIGNAL.swap(signal, Ordering::SeqCst) != 0 {
        // SAFETY: signal and raise are async-signal-safe.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }
}

/// Holds SIGINT, SIGTERM, SIGHUP and SIGQUIT while provisioning has the
/// guest disk attached. Dying on one would leave the disk attached and its
/// Data volume mounted read-write, so a signal is only recorded and the
/// provision stops at the next [`Self::check`], after which the disk is
/// detached as on any other failure. A second signal terminates at once. A
/// signal the caller already ignores (`nohup`, a background job) stays
/// ignored. The previous handlers come back on drop.
struct DeferredSignals {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl DeferredSignals {
    const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

    fn install() -> Result<Self> {
        PENDING_SIGNAL.store(0, Ordering::SeqCst);
        let mut deferred = Self {
            previous: Vec::with_capacity(Self::SIGNALS.len()),
        };
        for signal in Self::SIGNALS {
            // SAFETY: an all-zero sigaction is a valid empty value, a null
            // new action only queries, and the handler only touches an
            // atomic and async-signal-safe calls.
            unsafe {
                let mut previous: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(signal, std::ptr::null(), &mut previous) != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("reading the provisioning signal handlers");
                }
                if previous.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = record_signal as extern "C" fn(libc::c_int) as usize;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("installing the provisioning signal handlers");
                }
                deferred.previous.push((signal, previous));
            }
        }
        Ok(deferred)
    }

    /// Fail if a signal arrived since [`Self::install`].
    fn check(&self) -> Result<()> {
        match PENDING_SIGNAL.load(Ordering::SeqCst) {
            0 => Ok(()),
            signal => bail!(
                "interrupted by signal {signal}; the guest disk was detached and the image left unprovisioned"
            ),
        }
    }
}

impl Drop for DeferredSignals {
    fn drop(&mut self) {
        for (signal, previous) in &self.previous {
            // SAFETY: restores a disposition sigaction returned earlier.
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
    }
}

/// A disk image attached with `hdiutil` and not mounted, plus the Data
/// volume mount made from it. Detached on drop if [`Self::detach`] was not
/// reached.
struct AttachedDisk {
    device: String,
    containers: Vec<String>,
    data_mount: Option<PathBuf>,
    detached: bool,
}

impl AttachedDisk {
    /// Attach `image` without mounting anything, running `hdiutil` as
    /// `uid`/`gid` so the attach is limited to what that user may open.
    fn attach(image: &Path, uid: u32, gid: u32) -> Result<Self> {
        let out = std::process::Command::new("/usr/bin/hdiutil")
            .args(["attach", "-nomount", "-nobrowse", "-imagekey"])
            .arg("diskimage-class=CRawDiskImage")
            .arg(image)
            .uid(uid)
            .gid(gid)
            .process_group(0)
            .output()
            .context("running hdiutil attach")?;
        if !out.status.success() {
            bail!(
                "hdiutil attach {} failed: {}",
                image.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let (device, containers) = parse_hdiutil_attach(&String::from_utf8_lossy(&out.stdout))
            .with_context(|| format!("unexpected hdiutil attach output for {}", image.display()))?;
        Ok(Self {
            device,
            containers,
            data_mount: None,
            detached: false,
        })
    }

    /// Mount the disk's Data volume at `<mount_root>/data`, owners honored.
    /// `mount_root` is root's private directory, so no other user can swap
    /// the path the agent files are then written through.
    fn mount_data_volume(&mut self, mount_root: &Path) -> Result<PathBuf> {
        let mut volumes = Vec::new();
        for container in &self.containers {
            volumes.extend(data_volumes(&apfs_list(container)?));
        }
        let [volume] = volumes.as_slice() else {
            bail!(
                "expected one APFS volume with the Data role in {:?}, found {volumes:?}",
                self.containers
            );
        };
        let mount = mount_root.join("data");
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(&mount)
            .with_context(|| format!("creating {}", mount.display()))?;
        self.data_mount = Some(mount.clone());
        let device = format!("/dev/{volume}");
        let out = std::process::Command::new("/sbin/mount_apfs")
            .arg(&device)
            .arg(&mount)
            .process_group(0)
            .output()
            .context("running mount_apfs")?;
        if !out.status.success() {
            bail!(
                "mount_apfs {device} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(mount)
    }

    /// Detach cleanly (which unmounts the Data volume). On failure the disk
    /// stays marked attached, so drop retries with `-force` instead of
    /// leaving the guest disk mounted.
    fn detach(mut self) -> Result<()> {
        detach_device(&self.device, false)?;
        self.detached = true;
        self.remove_mount_dir();
        Ok(())
    }

    /// Remove the (now empty) mount point. Never recursive: if the volume is
    /// somehow still mounted this fails instead of walking into the guest.
    fn remove_mount_dir(&self) {
        if let Some(mount) = &self.data_mount {
            let _ = std::fs::remove_dir(mount);
        }
    }
}

impl Drop for AttachedDisk {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        match detach_device(&self.device, true) {
            Ok(()) => self.remove_mount_dir(),
            Err(e) => eprintln!("warning: {e}"),
        }
    }
}

fn detach_device(device: &str, force: bool) -> Result<()> {
    let mut cmd = std::process::Command::new("/usr/bin/hdiutil");
    cmd.args(["detach", device]).process_group(0);
    if force {
        cmd.arg("-force");
    }
    let out = cmd.output().context("running hdiutil detach")?;
    if !out.status.success() {
        bail!(
            "hdiutil detach {device} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Parse `hdiutil attach -nomount` output: one tab-separated line per
/// device, the first being the whole disk. Returns that disk and the APFS
/// containers synthesized from it (whole-disk devices other than the first).
fn parse_hdiutil_attach(stdout: &str) -> Option<(String, Vec<String>)> {
    let mut devices = stdout.lines().filter_map(|line| {
        line.split('\t')
            .next()
            .map(str::trim)
            .and_then(|d| d.strip_prefix("/dev/"))
    });
    let device = devices.next()?;
    let containers = devices
        .filter(|d| {
            d.strip_prefix("disk")
                .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
        })
        .map(str::to_string)
        .collect();
    Some((format!("/dev/{device}"), containers))
}

/// `diskutil apfs list -plist <container>`, as JSON.
fn apfs_list(container: &str) -> Result<serde_json::Value> {
    use std::io::Write;
    let out = std::process::Command::new("/usr/sbin/diskutil")
        .args(["apfs", "list", "-plist", container])
        .process_group(0)
        .output()
        .context("running diskutil apfs list")?;
    if !out.status.success() {
        bail!(
            "diskutil apfs list {container} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut plutil = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "-"])
        .process_group(0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running plutil")?;
    plutil
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&out.stdout)
        .context("writing to plutil")?;
    let json = plutil.wait_with_output().context("running plutil")?;
    if !json.status.success() {
        bail!("plutil could not convert the diskutil output for {container}");
    }
    serde_json::from_slice(&json.stdout).context("parsing diskutil apfs list output")
}

/// Device identifiers of the volumes carrying the APFS `Data` role.
fn data_volumes(apfs_list: &serde_json::Value) -> Vec<String> {
    let containers = apfs_list["Containers"].as_array().into_iter().flatten();
    containers
        .flat_map(|c| c["Volumes"].as_array().into_iter().flatten())
        .filter(|v| {
            v["Roles"]
                .as_array()
                .is_some_and(|roles| roles.iter().any(|r| r == "Data"))
        })
        .filter_map(|v| v["DeviceIdentifier"].as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use husker_vmm::macos_bundle::MACOS_BUNDLE_FORMAT;

    /// Signal dispositions are process-wide, so the tests that change them
    /// run one at a time under a threaded test runner.
    static SIGNAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn manifest(build: &str, agent_provisioned: bool) -> MacOsBundleManifest {
        MacOsBundleManifest {
            format: MACOS_BUNDLE_FORMAT,
            build: build.into(),
            os_version: "26.0.1".into(),
            disk_size_bytes: 64 << 30,
            min_cpus: 2,
            min_memory_mib: 4096,
            agent_provisioned,
        }
    }

    /// Write a bundle named `name` under the data dir. `complete` adds the
    /// disk, auxiliary storage and hardware model a boot needs.
    fn write_bundle(
        data_dir: &Path,
        name: &str,
        manifest: &MacOsBundleManifest,
        complete: bool,
    ) -> MacOsBundle {
        let dir = macos_images_dir(data_dir).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = MacOsBundle::new(dir);
        bundle.write_manifest(manifest).unwrap();
        if complete {
            for p in [
                bundle.disk_path(),
                bundle.aux_path(),
                bundle.hardware_model_path(),
            ] {
                std::fs::write(p, b"x").unwrap();
            }
        }
        bundle
    }

    #[test]
    fn list_reports_complete_bundles_by_name_and_skips_everything_else() {
        let data = tempfile::tempdir().unwrap();
        assert!(
            installed_images(data.path()).unwrap().is_empty(),
            "no macos dir yet means no images, not an error"
        );

        let images = macos_images_dir(data.path());
        let provisioned = write_bundle(data.path(), "tahoe", &manifest("25A354", true), true);
        write_bundle(data.path(), "sequoia", &manifest("24G84", false), true);
        write_bundle(
            data.path(),
            "half-installed",
            &manifest("25A354", false),
            false,
        );
        write_bundle(
            data.path(),
            ".tahoe.installing",
            &manifest("25A354", true),
            true,
        );
        std::fs::write(images.join("restore.ipsw"), b"not a bundle").unwrap();

        let listed = installed_images(data.path()).unwrap();
        let names: Vec<&str> = listed.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["sequoia", "tahoe"]);

        let tahoe = &listed[1];
        assert_eq!(tahoe.path, provisioned.dir().display().to_string());
        assert_eq!(tahoe.build, "25A354");
        assert_eq!(tahoe.os_version, "26.0.1");
        assert_eq!(tahoe.disk_size_bytes, 64 << 30);
        assert_eq!((tahoe.min_cpus, tahoe.min_memory_mib), (2, 4096));
        assert!(tahoe.agent_provisioned);
        assert!(!listed[0].agent_provisioned);
    }

    #[test]
    fn provision_refuses_a_name_outside_the_rules_as_invalid_usage() {
        // A bad name is a usage error, not a missing bundle, so it gets neither
        // the not-found kind nor the sudo hint that explains a missing one.
        let data = tempfile::tempdir().unwrap();
        for name in ["d".repeat(65), ".hidden".into(), "..".into()] {
            let err = provision(data.path(), &name).unwrap_err();
            let failure = err
                .downcast_ref::<ApiFailure>()
                .expect("structured failure");
            assert_eq!(
                failure.kind,
                CliErrorKind::InvalidUsage,
                "{name:?}: {err:#}"
            );
            assert!(failure.message.contains("macOS image name"), "{err:#}");
            assert_eq!(failure.hint, None, "{err:#}");
        }
        assert!(!macos_images_dir(data.path()).exists());
    }

    #[test]
    fn provision_refuses_a_missing_image_and_a_non_root_caller() {
        let data = tempfile::tempdir().unwrap();
        let err = provision(data.path(), "missing").unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert_eq!(failure.kind, CliErrorKind::NotFound, "{err:#}");
        assert!(
            failure
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("sudo may change HOME")),
            "{err:#}"
        );

        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping the non-root half: running as root");
            return;
        }
        let bundle = write_bundle(data.path(), "tahoe", &manifest("25A354", false), true);
        let err = provision(data.path(), "tahoe").unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert_eq!(failure.kind, CliErrorKind::PermissionDenied, "{err:#}");
        assert_eq!(
            failure.hint.as_deref(),
            Some(format!("sudo husker macos provision {}", bundle.dir().display()).as_str()),
            "the hint names the bundle path, which survives sudo changing HOME"
        );
        assert_eq!(
            bundle.read_manifest().unwrap(),
            manifest("25A354", false),
            "a refused provision leaves the manifest alone"
        );
    }

    fn sighup_handler() -> usize {
        // SAFETY: a null new action only queries the current disposition.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut current),
                0
            );
            current.sa_sigaction
        }
    }

    #[test]
    fn a_deferred_signal_fails_the_next_check_and_the_old_handler_returns() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let before = sighup_handler();
        let signals = DeferredSignals::install().unwrap();
        signals.check().unwrap();
        // SAFETY: SIGHUP is caught by the deferred handler, which only
        // records it.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        let err = signals.check().unwrap_err().to_string();
        assert!(err.contains(&format!("signal {}", libc::SIGHUP)), "{err}");
        assert!(err.contains("left unprovisioned"), "{err}");
        drop(signals);
        assert_eq!(sighup_handler(), before);
        assert_ne!(before, record_signal as extern "C" fn(libc::c_int) as usize);
    }

    #[test]
    fn an_ignored_signal_stays_ignored_while_deferring() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        // SAFETY: only SIGHUP's disposition changes, and it is put back.
        let original = unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        let signals = DeferredSignals::install().unwrap();
        assert_eq!(sighup_handler(), libc::SIG_IGN);
        // SAFETY: SIGHUP is ignored, so raising it has no effect.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        signals.check().unwrap();
        drop(signals);
        assert_eq!(sighup_handler(), libc::SIG_IGN);
        // SAFETY: restores the disposition saved above.
        unsafe { libc::signal(libc::SIGHUP, original) };
    }

    /// Serve one HTTP response on a loopback port and return its URL.
    #[cfg(target_os = "macos")]
    async fn serve_once(response: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            sock.write_all(response).await.unwrap();
        });
        format!("http://{addr}/restore.ipsw")
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_download_without_a_length_is_refused_and_not_cached() {
        // Close-delimited body: a dropped connection would look complete.
        let url = serve_once(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b.ipsw");
        let err = download(&url, &dest, OutputFormat::Json).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("did not report the restore image size"),
            "{err:#}"
        );
        assert!(!dest.exists());
        assert!(!dest.with_extension("ipsw.part").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_download_shorter_than_its_length_is_refused_and_not_cached() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b.ipsw");
        assert!(download(&url, &dest, OutputFormat::Json).await.is_err());
        assert!(!dest.exists());
        assert!(!dest.with_extension("ipsw.part").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_stale_partial_download_is_replaced() {
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nipsw").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b.ipsw");
        std::fs::write(dest.with_extension("ipsw.part"), b"stale bytes from before").unwrap();
        download(&url, &dest, OutputFormat::Json).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"ipsw");
        assert!(!dest.with_extension("ipsw.part").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_complete_download_is_renamed_into_place() {
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nipsw").await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("b.ipsw");
        download(&url, &dest, OutputFormat::Json).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"ipsw");
        assert!(!dest.with_extension("ipsw.part").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_concurrent_install_of_the_same_name_leaves_the_running_one_alone() {
        let data = tempfile::tempdir().unwrap();
        let images = macos_images_dir(data.path());
        let staging = images.join(".a.installing");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("disk.img"), b"in progress").unwrap();
        let not_an_ipsw = data.path().join("x.ipsw");
        std::fs::write(&not_an_ipsw, b"not a restore image").unwrap();
        let run = || {
            install(
                data.path(),
                InstallOptions {
                    name: "a".into(),
                    source: IpswSource::Local(not_an_ipsw.clone()),
                    disk_size_bytes: 64 << 30,
                    cpus: None,
                    memory: None,
                },
                OutputFormat::Json,
            )
        };

        let held = crate::daemon::try_lock_exclusive(&images.join(".a.lock")).unwrap();
        let err = run().await.unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert_eq!(failure.kind, CliErrorKind::Conflict, "{err:#}");
        assert!(
            staging.join("disk.img").exists(),
            "running install untouched"
        );

        // Once the lock is free, the leftover is genuinely stale and is cleared
        // before the (here failing) install starts.
        drop(held);
        let err = run().await.unwrap_err();
        assert!(err.downcast_ref::<ApiFailure>().is_none(), "{err:#}");
        assert!(!staging.join("disk.img").exists(), "stale staging removed");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_name_outside_the_resource_rules_is_refused_before_any_download() {
        let data = tempfile::tempdir().unwrap();
        let downloads = data.path().join("downloads");
        let err = install(
            data.path(),
            InstallOptions {
                name: "s".repeat(65),
                source: IpswSource::Download {
                    dir: Some(downloads.clone()),
                    keep: false,
                },
                disk_size_bytes: 64 << 30,
                cpus: None,
                memory: None,
            },
            OutputFormat::Json,
        )
        .await
        .unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert_eq!(failure.kind, CliErrorKind::InvalidUsage, "{err:#}");
        assert!(
            failure.message.contains("exceeds maximum length"),
            "{}",
            failure.message
        );
        assert!(!downloads.exists(), "nothing was downloaded");
        assert!(!macos_images_dir(data.path()).exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_too_small_disk_is_refused_before_any_download() {
        let data = tempfile::tempdir().unwrap();
        let downloads = data.path().join("downloads");
        let err = install(
            data.path(),
            InstallOptions {
                name: "small".into(),
                source: IpswSource::Download {
                    dir: Some(downloads.clone()),
                    keep: false,
                },
                disk_size_bytes: 8 << 30,
                cpus: None,
                memory: None,
            },
            OutputFormat::Json,
        )
        .await
        .unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert_eq!(failure.kind, CliErrorKind::InvalidUsage, "{err:#}");
        assert!(format!("{err:#}").contains("at least 32 GiB"), "{err:#}");
        assert!(!downloads.exists(), "nothing was downloaded");
        assert!(!macos_images_dir(data.path()).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_download_larger_than_the_free_space_is_refused_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let available = available_bytes(dir.path()).unwrap();
        assert!(available > 0);
        ensure_free_space(dir.path(), available / 2).unwrap();

        let err = ensure_free_space(dir.path(), available.saturating_mul(4)).unwrap_err();
        let failure = err
            .downcast_ref::<ApiFailure>()
            .expect("structured failure");
        assert!(failure.message.contains("only"), "{}", failure.message);
        assert!(
            failure.hint.as_deref().unwrap().contains("--download-dir"),
            "{:?}",
            failure.hint
        );
    }

    #[test]
    fn hdiutil_output_yields_the_whole_disk_and_its_apfs_containers() {
        let stdout = "/dev/disk6          \tGUID_partition_scheme          \t\n\
                      /dev/disk6s1        \tApple_APFS_ISC                 \t\n\
                      /dev/disk6s2        \tApple_APFS                     \t\n\
                      /dev/disk7          \tEF57347C-0000-11AA-AA11-0030654\t\n\
                      /dev/disk7s1        \t41504653-0000-11AA-AA11-0030654\t\n\
                      /dev/disk9          \tEF57347C-0000-11AA-AA11-0030654\t\n\
                      /dev/disk9s5        \t41504653-0000-11AA-AA11-0030654\t\n";
        let (device, containers) = parse_hdiutil_attach(stdout).unwrap();
        assert_eq!(device, "/dev/disk6");
        assert_eq!(containers, ["disk7", "disk9"]);
    }

    #[test]
    fn hdiutil_output_without_devices_is_rejected() {
        assert_eq!(parse_hdiutil_attach("hdiutil: attach failed\n"), None);
    }

    #[test]
    fn the_data_volume_is_found_by_its_apfs_role() {
        // Shape of `diskutil apfs list -plist` for a macOS 27 guest disk.
        let list = serde_json::json!({"Containers": [{"Volumes": [
            {"DeviceIdentifier": "disk9s1", "Roles": ["System"], "Name": "Macintosh HD"},
            {"DeviceIdentifier": "disk9s2", "Roles": ["Preboot"]},
            {"DeviceIdentifier": "disk9s5", "Roles": ["Data"], "Name": "Data"},
        ]}]});
        assert_eq!(data_volumes(&list), ["disk9s5"]);
        let recovery = serde_json::json!({"Containers": [{"Volumes": [
            {"DeviceIdentifier": "disk7s4", "Roles": ["Recovery"]},
            {"DeviceIdentifier": "disk7s9", "Roles": []},
        ]}]});
        assert!(data_volumes(&recovery).is_empty());
        assert!(data_volumes(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn agent_files_land_at_their_guest_paths() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        let agent = data.path().join("husker-host-binary");
        std::fs::write(&agent, b"binary").unwrap();
        install_agent_files(data.path(), &agent).unwrap();

        let binary = data.path().join("usr/local/libexec/husker");
        assert_eq!(std::fs::read(&binary).unwrap(), b"binary");
        assert_eq!(
            std::fs::metadata(&binary).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let plist = data
            .path()
            .join("Library/LaunchDaemons/dev.husker.guest-agent.plist");
        let text = std::fs::read_to_string(&plist).unwrap();
        assert!(
            text.contains("<string>/usr/local/libexec/husker</string>"),
            "{text}"
        );
        assert!(text.contains("<string>guest-agent</string>"), "{text}");
        assert_eq!(
            text.matches("<string>/var/log/husker-guest-agent.log</string>")
                .count(),
            2,
            "stdout and stderr both go to the agent log: {text}"
        );
        assert_eq!(
            std::fs::metadata(&plist).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(data.path().join("private/var/db/.AppleSetupDone").is_file());
    }

    #[test]
    fn a_symlinked_directory_in_the_guest_disk_is_refused() {
        let data = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(data.path().join("private/var")).unwrap();
        std::os::unix::fs::symlink(host.path(), data.path().join("private/var/db")).unwrap();

        let err =
            write_confined(data.path(), "/private/var/db/.AppleSetupDone", b"", 0o644).unwrap_err();
        assert!(format!("{err:#}").contains("symlink is refused"), "{err:#}");
        assert!(!host.path().join(".AppleSetupDone").exists());
    }

    #[test]
    fn a_symlinked_destination_in_the_guest_disk_is_replaced_not_followed() {
        let data = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let victim = host.path().join("victim");
        std::fs::write(&victim, b"host data").unwrap();
        std::fs::create_dir_all(data.path().join("private/var/db")).unwrap();
        std::os::unix::fs::symlink(&victim, data.path().join("private/var/db/.AppleSetupDone"))
            .unwrap();

        write_confined(data.path(), "/private/var/db/.AppleSetupDone", b"", 0o644).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"host data");
        let dest =
            std::fs::symlink_metadata(data.path().join("private/var/db/.AppleSetupDone")).unwrap();
        assert!(dest.file_type().is_file(), "{dest:?}");
    }

    #[test]
    fn a_fifo_at_the_destination_is_replaced_without_being_opened() {
        use std::os::unix::ffi::OsStrExt;
        let data = tempfile::tempdir().unwrap();
        let dir = data.path().join("private/var/db");
        std::fs::create_dir_all(&dir).unwrap();
        let fifo =
            std::ffi::CString::new(dir.join(".AppleSetupDone").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

        // Opening the FIFO for writing would block forever with no reader.
        let (tx, rx) = std::sync::mpsc::channel();
        let root = data.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(write_confined(
                &root,
                "/private/var/db/.AppleSetupDone",
                b"",
                0o644,
            ));
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("write_confined blocked on the FIFO")
            .unwrap();
        let dest = std::fs::symlink_metadata(dir.join(".AppleSetupDone")).unwrap();
        assert!(dest.file_type().is_file(), "{dest:?}");
    }

    #[test]
    fn a_planted_temporary_name_is_cleared_not_followed() {
        let data = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let victim = host.path().join("victim");
        std::fs::write(&victim, b"host data").unwrap();
        let dir = data.path().join("private/var/db");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("..AppleSetupDone.husker-provision")).unwrap();

        write_confined(data.path(), "/private/var/db/.AppleSetupDone", b"", 0o644).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"host data");
        assert!(dir.join(".AppleSetupDone").is_file());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from(".AppleSetupDone")]);
    }

    #[test]
    fn an_existing_guest_file_is_replaced_with_the_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("usr/local/libexec/husker");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"an older and longer agent binary").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_confined(data.path(), "/usr/local/libexec/husker", b"new", 0o755).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn the_launch_daemon_plist_is_well_formed() {
        let out = std::process::Command::new("plutil")
            .args(["-lint", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        // plutil only exists on macOS; elsewhere the content test above covers it.
        let Ok(mut child) = out else { return };
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(launch_daemon_plist().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
