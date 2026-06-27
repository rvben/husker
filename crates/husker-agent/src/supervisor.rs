//! Guest init/supervisor: the minimal PID-1 duties that let an arbitrary OCI
//! rootfs boot in a husker microVM. This module covers the filesystem and device
//! setup; networking and child supervision are layered on top.
//!
//! These functions are only meaningful when the agent is PID 1 (see
//! [`crate::is_supervisor_mode`]) and use raw `libc` syscalls (matching the rest
//! of the codebase) because the rootfs may be distroless (no shell, no `mount`).

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;

use tracing::{error, info, warn};

/// A pseudo-filesystem the supervisor mounts during init.
pub struct MountSpec {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    /// A critical mount failing aborts init (the supervisor reboots the guest);
    /// a best-effort mount failing is logged and skipped.
    pub critical: bool,
}

/// The pseudo-filesystems to mount, in order. `/proc` and `/dev` are critical
/// (cmdline parsing and device nodes depend on them); the rest are best-effort.
pub fn mount_plan() -> Vec<MountSpec> {
    vec![
        MountSpec {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            critical: true,
        },
        MountSpec {
            source: "devtmpfs",
            target: "/dev",
            fstype: "devtmpfs",
            critical: true,
        },
        MountSpec {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            critical: false,
        },
        MountSpec {
            source: "devpts",
            target: "/dev/pts",
            fstype: "devpts",
            critical: false,
        },
        MountSpec {
            source: "tmpfs",
            target: "/tmp",
            fstype: "tmpfs",
            critical: false,
        },
        MountSpec {
            source: "tmpfs",
            target: "/run",
            fstype: "tmpfs",
            critical: false,
        },
        MountSpec {
            source: "cgroup2",
            target: "/sys/fs/cgroup",
            fstype: "cgroup2",
            critical: false,
        },
    ]
}

fn mount_one(spec: &MountSpec) -> io::Result<()> {
    // Create the mount point (a distroless rootfs may lack /proc, /sys, ...).
    let _ = std::fs::create_dir_all(spec.target);
    let source = CString::new(spec.source).expect("static source has no NUL");
    let target = CString::new(spec.target).expect("static target has no NUL");
    let fstype = CString::new(spec.fstype).expect("static fstype has no NUL");
    // SAFETY: all three pointers are valid CStrings held for the call; flags are
    // none and the data pointer is null (no fs-specific options).
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount `/proc` (best-effort). PID 1 starts with nothing mounted, so this must
/// run before reading `/proc/cmdline` to detect supervisor mode. Idempotent with
/// [`mount_all`] (a second mount returns EBUSY and is skipped).
pub fn mount_proc() {
    if let Err(e) = mount_one(&MountSpec {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        critical: false,
    }) {
        warn!("could not mount /proc early: {e}");
    }
}

/// Mount the pseudo-filesystems. Returns `Err` only when a *critical* mount fails
/// (other than "already mounted") so the caller can reboot; best-effort failures
/// are logged and skipped.
pub fn mount_all() -> io::Result<()> {
    for spec in mount_plan() {
        match mount_one(&spec) {
            Ok(()) => info!("mounted {} on {}", spec.fstype, spec.target),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                // Already mounted (e.g. the kernel mounted /proc) - fine.
            }
            Err(e) if spec.critical => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "critical mount {} on {} failed: {e}",
                        spec.fstype, spec.target
                    ),
                ));
            }
            Err(e) => warn!(
                "skipping best-effort mount {} on {}: {e}",
                spec.fstype, spec.target
            ),
        }
    }
    Ok(())
}

/// Core character device nodes as `(path, major, minor)`. devtmpfs normally
/// creates these; we backfill any missing so workloads and PTYs work even on a
/// rootfs that shipped a bare `/dev`.
const DEVICE_NODES: &[(&str, u32, u32)] = &[
    ("/dev/null", 1, 3),
    ("/dev/zero", 1, 5),
    ("/dev/full", 1, 7),
    ("/dev/random", 1, 8),
    ("/dev/urandom", 1, 9),
    ("/dev/tty", 5, 0),
    ("/dev/console", 5, 1),
];

/// Create any missing core character device nodes.
pub fn ensure_device_nodes() {
    for (path, major, minor) in DEVICE_NODES {
        if Path::new(path).exists() {
            continue;
        }
        let cpath = CString::new(*path).expect("static path has no NUL");
        let dev = libc::makedev(*major, *minor);
        let mode = libc::S_IFCHR | 0o666;
        // SAFETY: cpath is a valid CString held for the call; mode encodes a
        // character device with 0666 perms; dev is a valid device number.
        let rc = unsafe { libc::mknod(cpath.as_ptr(), mode, dev) };
        if rc != 0 {
            warn!("could not create {path}: {}", io::Error::last_os_error());
        }
    }
}

/// Kernel modules the agent needs, in dependency order. On the modular Alpine
/// `-virt` guest kernel these are `.ko` files the initramfs copies into
/// [`MODULES_DIR`]; on a monolithic kernel they are built in and the files are
/// simply absent. A distroless rootfs has no `modprobe`/`insmod`, so the
/// supervisor loads them directly via `finit_module`.
const REQUIRED_MODULES: &[&str] = &[
    // vsock transport - must be up before the agent child binds its socket.
    "vsock",
    "vmw_vsock_virtio_transport_common",
    "vmw_vsock_virtio_transport",
    // networking: virtio_net plus its failover deps, and af_packet (raw sockets).
    "af_packet",
    "failover",
    "net_failover",
    "virtio_net",
];

/// Directory the initramfs copies guest kernel modules into.
const MODULES_DIR: &str = "/lib/modules";

/// Load [`REQUIRED_MODULES`] from [`MODULES_DIR`] via `finit_module`.
/// Best-effort: an absent `.ko` (built into the kernel) or an already-loaded
/// module is skipped; other failures are logged. Returns how many were newly
/// loaded (for the boot log).
pub fn load_kernel_modules() -> usize {
    let mut loaded = 0;
    for name in REQUIRED_MODULES {
        match load_module(name) {
            Ok(true) => {
                loaded += 1;
                info!("loaded kernel module {name}");
            }
            Ok(false) => {} // built-in, absent, or already loaded
            Err(e) => warn!("could not load kernel module {name}: {e}"),
        }
    }
    loaded
}

/// Load a single named module from [`MODULES_DIR`]. `Ok(true)` if loaded now,
/// `Ok(false)` if absent (built-in) or already present.
fn load_module(name: &str) -> io::Result<bool> {
    let path = format!("{MODULES_DIR}/{name}.ko");
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let params = CString::new("").expect("empty params has no NUL");
    // SAFETY: file is held for the call so its fd is valid; params is a valid
    // C string; flags are 0. finit_module returns 0 on success, -1 on error.
    let rc = unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
    if rc == 0 {
        Ok(true)
    } else {
        let e = io::Error::last_os_error();
        // EEXIST: already loaded (e.g. built in, or pulled in as a dependency).
        if e.raw_os_error() == Some(libc::EEXIST) {
            Ok(false)
        } else {
            Err(e)
        }
    }
}

/// Static network configuration parsed from the kernel `ip=` parameter.
#[derive(Debug, PartialEq, Eq)]
pub struct NetConfig {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub iface: String,
}

/// Parse the kernel `ip=<client>::<gateway>:<netmask>::<iface>:<autoconf>` token
/// (the format husker-core sets for NAT/30 guests). Returns `None` when no `ip=`
/// is present. The dotted netmask is converted to a prefix length.
pub fn parse_ip_cmdline(cmdline: &str) -> Option<NetConfig> {
    let token = cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("ip="))?;
    let f: Vec<&str> = token.split(':').collect();
    // 0=client 1=server 2=gateway 3=netmask 4=hostname 5=iface 6=autoconf
    let addr: Ipv4Addr = f.first()?.parse().ok()?;
    let prefix = netmask_to_prefix(f.get(3)?)?;
    let gateway = f
        .get(2)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    let iface = f
        .get(5)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "eth0".to_string());
    Some(NetConfig {
        addr,
        prefix,
        gateway,
        iface,
    })
}

/// Convert a dotted IPv4 netmask (e.g. `255.255.255.252`) to a prefix length,
/// rejecting non-contiguous masks.
fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(|o| o.parse::<u8>().ok())
        .collect::<Option<_>>()?;
    if octets.len() != 4 {
        return None;
    }
    let bits = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let ones = bits.count_ones() as u8;
    // A valid netmask is contiguous leading ones.
    if bits.leading_ones() as u8 == ones {
        Some(ones)
    } else {
        None
    }
}

/// Bring up the static network from `cfg` and write a usable `/etc/resolv.conf`
/// and `/etc/hosts`. Returns `Err` (degraded network) if the netlink setup fails;
/// the caller logs it loudly rather than hanging silently. Uses netlink directly
/// (not `ip`), so it works on a distroless rootfs with no userspace tools.
pub fn configure_network(cfg: &NetConfig) -> io::Result<()> {
    crate::netlink::configure_static(&cfg.iface, cfg.addr, cfg.prefix, cfg.gateway)?;
    write_resolv_conf(cfg.gateway);
    ensure_hosts();
    Ok(())
}

/// Decide the `/etc/resolv.conf` contents to write, or `None` to keep the
/// existing file. A real file that already lists a `nameserver` was seeded by
/// the daemon (its configured `dns_servers`) and is preserved; a symlink
/// (Debian/Ubuntu point it into `/run`, an empty tmpfs here), a missing file, or
/// one with no nameserver is replaced with the gateway plus public resolvers.
fn resolv_conf_decision(existing: Option<&str>, gateway: Option<Ipv4Addr>) -> Option<String> {
    if let Some(content) = existing
        && content
            .lines()
            .any(|l| l.trim_start().starts_with("nameserver"))
    {
        return None; // preserve the daemon-seeded resolv.conf
    }
    let mut out = String::new();
    if let Some(gw) = gateway {
        out.push_str(&format!("nameserver {gw}\n"));
    }
    out.push_str("nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    Some(out)
}

/// Write `/etc/resolv.conf` unless the daemon already seeded one (see
/// [`resolv_conf_decision`]). The NAT gateway usually serves DNS; public
/// resolvers are a fallback.
pub fn write_resolv_conf(gateway: Option<Ipv4Addr>) {
    let path = Path::new("/etc/resolv.conf");
    let is_symlink = std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    // Only a real file can be a daemon-seeded config; a symlink points into the
    // empty /run tmpfs and is treated as absent.
    let existing = if is_symlink {
        None
    } else {
        std::fs::read_to_string(path).ok()
    };
    let Some(content) = resolv_conf_decision(existing.as_deref(), gateway) else {
        return; // preserve the seeded file
    };
    if is_symlink {
        let _ = std::fs::remove_file(path);
    }
    let _ = std::fs::create_dir_all("/etc");
    if let Err(e) = std::fs::write(path, content) {
        warn!("could not write /etc/resolv.conf: {e}");
    }
}

/// Ensure `/etc/hosts` has localhost entries (a distroless rootfs may lack it).
pub fn ensure_hosts() {
    let path = Path::new("/etc/hosts");
    if !path.exists() {
        let _ = std::fs::create_dir_all("/etc");
        let _ = std::fs::write(path, "127.0.0.1 localhost\n::1 localhost\n");
    }
}

/// Parse `husker.share=<tag>=<guest_path>[:ro]` tokens from the kernel cmdline.
/// Returns a vec of `(tag, guest_path, read_only)` triples, one per share.
pub fn parse_shares(cmdline: &str) -> Vec<(String, String, bool)> {
    cmdline
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("husker.share="))
        .filter_map(|v| {
            let (tag, rest) = v.split_once('=')?;
            let (path, ro) = match rest.strip_suffix(":ro") {
                Some(p) => (p, true),
                None => (rest, false),
            };
            Some((tag.to_string(), path.to_string(), ro))
        })
        .collect()
}

/// Mount a single virtiofs share. The `tag` is the virtiofs device tag exposed
/// by the host; `path` is the guest mount point. Creates the directory if
/// absent. Failures are logged but do not abort the guest.
fn mount_virtiofs(tag: &str, path: &str, ro: bool) -> io::Result<()> {
    let _ = std::fs::create_dir_all(path);
    let source = CString::new(tag)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tag contains NUL"))?;
    let target = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fstype = CString::new("virtiofs").expect("static fstype has no NUL");
    let flags: libc::c_ulong = if ro { libc::MS_RDONLY } else { 0 };
    // SAFETY: all three pointers are valid CStrings held for the call; flags
    // encode read-only when requested; data pointer is null (no fs-specific options).
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Reboot the guest immediately. Used when a critical init step fails: the host
/// observes the VM exit and reports it, rather than the guest half-booting and
/// accepting vsock while workloads mysteriously fail. Never returns.
pub fn reboot_now() -> ! {
    // SAFETY: sync() and reboot(RB_AUTOBOOT) take no pointers; reboot only
    // returns on error.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    // If reboot somehow returns, PID 1 must never exit - spin instead.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Run as the guest init/supervisor (PID 1): perform minimal init, then
/// supervise the agent as a restartable child. Never returns.
pub fn run(cmdline: &str) -> ! {
    info!("husker-agent running as the guest init/supervisor (husker.init=1)");

    // A critical mount failing means a half-booted guest; reboot rather than
    // serve in a broken state. Best-effort mounts are skipped inside.
    if let Err(e) = mount_all() {
        error!("fatal init failure: {e}; rebooting guest");
        reboot_now();
    }
    ensure_device_nodes();

    // Load the modules the agent needs: vsock (its own transport, required
    // before the child binds) and virtio_net (so the interface exists for the
    // network setup below). No-op on a monolithic kernel where they are built in.
    let n = load_kernel_modules();
    info!("loaded {n} kernel module(s)");

    // Static network from the kernel ip=. A failure is degraded (no outbound
    // network), not fatal: logged loudly so it is diagnosable, then serve anyway.
    match parse_ip_cmdline(cmdline) {
        Some(cfg) => match configure_network(&cfg) {
            Ok(()) => info!(
                "guest network up: {}/{} on {} (gw {:?})",
                cfg.addr, cfg.prefix, cfg.iface, cfg.gateway
            ),
            Err(e) => warn!("guest network setup degraded: {e}"),
        },
        None => info!("no ip= on cmdline; skipping static network setup"),
    }

    // Mount virtiofs shares declared in the kernel cmdline. A failure is
    // best-effort: logged and skipped so the workload still starts with reduced
    // access rather than not at all.
    for (tag, path, ro) in parse_shares(cmdline) {
        match mount_virtiofs(&tag, &path, ro) {
            Ok(()) => info!("mounted virtiofs share {tag} on {path}"),
            Err(e) => warn!("could not mount virtiofs share {tag} on {path}: {e}"),
        }
    }

    supervise()
}

extern "C" fn on_terminate(_sig: libc::c_int) {
    // PID 1 has no default signal dispositions; on stop, power the guest off.
    // sync + reboot are terminal, which is acceptable from a handler here.
    // SAFETY: both calls take no pointers; reboot does not return on success.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
}

fn install_term_handlers() {
    // SAFETY: installing a plain extern "C" handler for SIGTERM/SIGINT.
    let handler = on_terminate as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Supervise the agent: run it as a child (a re-exec of this binary, which is
/// not PID 1 so it serves normally), restart it if it exits, and reap any
/// re-parented orphans - PID 1's duty. Never returns.
fn supervise() -> ! {
    install_term_handlers();
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/local/bin/husker-agent"));
    const RESTART_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

    loop {
        let child = match std::process::Command::new(&exe).spawn() {
            Ok(c) => c.id() as libc::pid_t,
            Err(e) => {
                warn!("failed to spawn agent child: {e}; retrying");
                std::thread::sleep(RESTART_DELAY);
                continue;
            }
        };
        info!("agent child started (pid {child})");

        // Reap children until our agent child exits; orphans are reaped along
        // the way so they never linger as zombies.
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: status is a valid pointer for the duration of the call.
            let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
            if reaped == child {
                warn!("agent child {child} exited; restarting");
                break;
            }
            if reaped < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::ECHILD {
                    break; // no children remain; respawn the agent
                }
                // EINTR or transient: keep waiting.
            }
            // reaped > 0 && != child: an orphan was reaped; keep waiting.
        }
        std::thread::sleep(RESTART_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shares_reads_tag_path_ro() {
        let cl = "console=ttyS0 husker.init=1 husker.share=fs0=/work husker.share=fs1=/data:ro";
        assert_eq!(
            parse_shares(cl),
            vec![
                ("fs0".to_string(), "/work".to_string(), false),
                ("fs1".to_string(), "/data".to_string(), true),
            ]
        );
    }

    #[test]
    fn parse_shares_empty_when_no_shares() {
        assert!(
            parse_shares(
                "console=ttyS0 husker.init=1 ip=10.0.0.1::10.0.0.0:255.255.255.0::eth0:off"
            )
            .is_empty()
        );
    }

    #[test]
    fn mount_plan_marks_proc_and_dev_critical() {
        let plan = mount_plan();
        let critical: Vec<&str> = plan
            .iter()
            .filter(|m| m.critical)
            .map(|m| m.target)
            .collect();
        assert_eq!(critical, vec!["/proc", "/dev"]);
        assert!(
            plan.iter()
                .any(|m| m.target == "/run" && m.fstype == "tmpfs" && !m.critical),
            "/run is a best-effort tmpfs"
        );
        assert!(
            plan.iter()
                .any(|m| m.target == "/sys/fs/cgroup" && m.fstype == "cgroup2"),
            "cgroup2 is mounted"
        );
        assert!(
            plan.iter().all(|m| m.target.starts_with('/')),
            "mount targets are absolute"
        );
    }

    #[test]
    fn parse_ip_cmdline_parses_static_nat_config() {
        let cmd = "ro console=ttyS0 \
                   ip=172.20.0.2::172.20.0.1:255.255.255.252::eth0:off husker.init=1";
        let cfg = parse_ip_cmdline(cmd).expect("ip= present");
        assert_eq!(cfg.addr, "172.20.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cfg.prefix, 30);
        assert_eq!(cfg.gateway, Some("172.20.0.1".parse().unwrap()));
        assert_eq!(cfg.iface, "eth0");
    }

    #[test]
    fn parse_ip_cmdline_none_when_absent() {
        assert!(parse_ip_cmdline("ro console=ttyS0 quiet").is_none());
    }

    #[test]
    fn netmask_to_prefix_converts_and_rejects_noncontiguous() {
        assert_eq!(netmask_to_prefix("255.255.255.252"), Some(30));
        assert_eq!(netmask_to_prefix("255.255.255.0"), Some(24));
        assert_eq!(netmask_to_prefix("0.0.0.0"), Some(0));
        assert_eq!(netmask_to_prefix("255.255.255.255"), Some(32));
        // Non-contiguous mask is rejected.
        assert_eq!(netmask_to_prefix("255.0.255.0"), None);
        assert_eq!(netmask_to_prefix("255.255.255"), None);
    }

    #[test]
    fn resolv_conf_decision_preserves_seeded_dns() {
        let gw = Some("192.0.2.1".parse::<Ipv4Addr>().unwrap());
        // A daemon-seeded file with a nameserver is preserved.
        assert_eq!(
            resolv_conf_decision(Some("nameserver 198.51.100.53\n"), gw),
            None
        );
        // A file without a nameserver (or empty) is replaced with the default.
        let written = resolv_conf_decision(Some("# comment only\n"), gw).unwrap();
        assert!(written.contains("nameserver 192.0.2.1"));
        assert!(written.contains("nameserver 1.1.1.1"));
        // Missing file -> default written (gateway first, then public).
        let written = resolv_conf_decision(None, gw).unwrap();
        assert!(written.starts_with("nameserver 192.0.2.1\n"));
        // No gateway -> public resolvers only.
        let written = resolv_conf_decision(None, None).unwrap();
        assert_eq!(written, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }
}
