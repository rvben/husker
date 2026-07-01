//! cgroup v2 resource limits for the Linux VMM process (Firecracker/QEMU).
//! Opt-in; a no-op when disabled. See
//! docs/superpowers/specs/2026-07-01-husker-cgroup-resource-limits-design.md.

use std::path::{Path, PathBuf};

/// Default host-memory margin over the guest RAM, covering the VMM's own
/// anonymous memory. Firecracker-safe; QEMU with large VMs may need more.
pub const DEFAULT_MEMORY_OVERHEAD_MIB: u32 = 256;

/// cgroup v2 CPU accounting period (microseconds).
const CPU_PERIOD_US: u32 = 100_000;

/// Resource-limit configuration resolved from the daemon config.
#[derive(Clone, Debug)]
pub struct CgroupConfig {
    pub enabled: bool,
    pub memory_overhead_mib: u32,
    pub cpu_limit: bool,
}

/// `memory.max` value in bytes: guest RAM plus the VMM overhead margin.
fn memory_max_bytes(mem_size_mib: u32, overhead_mib: u32) -> u64 {
    (mem_size_mib as u64 + overhead_mib as u64) * 1024 * 1024
}

/// `cpu.max` line ("<quota> <period>") capping the VM to `vcpu_count` cores.
fn cpu_max_line(vcpu_count: u32) -> String {
    format!("{} {}", vcpu_count.max(1) * CPU_PERIOD_US, CPU_PERIOD_US)
}

/// Extract the cgroup v2 path from `/proc/self/cgroup` (the `0::<path>` line).
fn parse_self_cgroup_path(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        .filter(|p| !p.is_empty())
}

/// Per-VM cgroup directory name under the delegated subtree.
fn vm_cgroup_dir_name(id: uuid::Uuid) -> String {
    format!("vm-{id}")
}

/// Where cgroup v2 is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("cgroup resource limits unavailable: {0}")]
    Unavailable(String),
    #[error("cgroup io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn write_file(path: &Path, contents: &str) -> Result<(), CgroupError> {
    std::fs::write(path, contents).map_err(|source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

pub struct CgroupSupervisor {
    /// Directory under which per-VM cgroups are created. `None` = disabled.
    base: Option<PathBuf>,
    config: CgroupConfig,
}

impl CgroupSupervisor {
    pub fn disabled() -> Self {
        Self {
            base: None,
            config: CgroupConfig {
                enabled: false,
                memory_overhead_mib: DEFAULT_MEMORY_OVERHEAD_MIB,
                cpu_limit: false,
            },
        }
    }

    #[cfg(test)]
    pub fn with_base_for_test(base: PathBuf, config: CgroupConfig) -> Self {
        Self {
            base: Some(base),
            config,
        }
    }

    /// Set up the delegated topology and return a live supervisor. Errors if the
    /// delegated subtree / controllers are unavailable (never silently disables).
    pub fn init(config: CgroupConfig) -> Result<Self, CgroupError> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        // 1. Our own v2 cgroup path.
        let self_cg = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| CgroupError::Unavailable(format!("read /proc/self/cgroup: {e}")))?;
        let rel = parse_self_cgroup_path(&self_cg).ok_or_else(|| {
            CgroupError::Unavailable("not on a cgroup v2 unified hierarchy".into())
        })?;
        let svc = PathBuf::from(CGROUP_ROOT).join(rel.trim_start_matches('/'));

        // 2. Move ourselves to a leaf so the parent can hold child cgroups.
        let supervisor = svc.join("supervisor");
        std::fs::create_dir_all(&supervisor).map_err(|e| CgroupError::Io {
            path: supervisor.clone(),
            source: e,
        })?;
        write_file(
            &supervisor.join("cgroup.procs"),
            &format!("{}\n", std::process::id()),
        )?;

        // 3. Enable controllers in the parent, then verify by read-back.
        write_file(&svc.join("cgroup.subtree_control"), "+memory +cpu\n")?;
        let probe = svc.join("vm-probe");
        std::fs::create_dir_all(&probe).map_err(|e| CgroupError::Io {
            path: probe.clone(),
            source: e,
        })?;
        let controllers =
            std::fs::read_to_string(probe.join("cgroup.controllers")).unwrap_or_default();
        let _ = std::fs::remove_dir(&probe);
        for c in ["memory", "cpu"] {
            if !controllers.split_whitespace().any(|t| t == c) {
                return Err(CgroupError::Unavailable(format!(
                    "the '{c}' controller is not delegated to husker.service - \
                     add Delegate=yes to the unit and ensure the parent slice exposes it"
                )));
            }
        }

        // 4. Sweep orphan vm-* cgroups from a prior crash.
        if let Ok(rd) = std::fs::read_dir(&svc) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("vm-") {
                    Self::kill_and_rmdir(&entry.path());
                }
            }
        }
        Ok(Self {
            base: Some(svc),
            config,
        })
    }

    pub fn create_vm_cgroup(
        &self,
        id: uuid::Uuid,
        vcpu_count: u32,
        mem_size_mib: u32,
    ) -> Result<VmCgroup, CgroupError> {
        let Some(base) = &self.base else {
            return Ok(VmCgroup { dir: None });
        };
        let dir = base.join(vm_cgroup_dir_name(id));
        std::fs::create_dir_all(&dir).map_err(|e| CgroupError::Io {
            path: dir.clone(),
            source: e,
        })?;
        write_file(
            &dir.join("memory.max"),
            &memory_max_bytes(mem_size_mib, self.config.memory_overhead_mib).to_string(),
        )?;
        write_file(&dir.join("memory.swap.max"), "0")?;
        write_file(&dir.join("memory.oom.group"), "1")?;
        if self.config.cpu_limit {
            write_file(&dir.join("cpu.max"), &cpu_max_line(vcpu_count))?;
        }
        Ok(VmCgroup { dir: Some(dir) })
    }

    /// SIGKILL any pids in a cgroup, then rmdir it. Best-effort.
    fn kill_and_rmdir(dir: &Path) {
        if let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            for pid in procs
                .split_whitespace()
                .filter_map(|p| p.parse::<i32>().ok())
            {
                // SAFETY: kill(2) with a pid + SIGKILL; harmless if the pid is gone.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        // Real cgroup pseudo-files cannot be unlinked; rmdir works once all
        // tasks have exited. In tests we use a tempdir with regular files, so
        // we remove_dir_all to simulate the same "dir is gone" postcondition.
        std::thread::sleep(std::time::Duration::from_millis(50));
        #[cfg(not(test))]
        let _ = std::fs::remove_dir(dir);
        #[cfg(test)]
        let _ = std::fs::remove_dir_all(dir);
    }
}

pub struct VmCgroup {
    dir: Option<PathBuf>,
}

impl VmCgroup {
    pub fn place(&self, pid: u32) -> Result<(), CgroupError> {
        let Some(dir) = &self.dir else { return Ok(()) };
        write_file(&dir.join("cgroup.procs"), &format!("{pid}\n"))
    }

    pub fn remove(&mut self) {
        if let Some(dir) = self.dir.take() {
            CgroupSupervisor::kill_and_rmdir(&dir);
        }
    }
}

impl Drop for VmCgroup {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            CgroupSupervisor::kill_and_rmdir(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Build a CgroupSupervisor rooted at a temp dir (no real kernel cgroups),
    // so we can assert the files it writes. Enforcement is a gated e2e (Task 5).
    fn temp_supervisor(cpu: bool) -> (tempfile::TempDir, CgroupSupervisor) {
        let dir = tempfile::tempdir().unwrap();
        let sup = CgroupSupervisor::with_base_for_test(
            dir.path().to_path_buf(),
            CgroupConfig {
                enabled: true,
                memory_overhead_mib: 256,
                cpu_limit: cpu,
            },
        );
        (dir, sup)
    }

    #[tokio::test]
    async fn create_vm_cgroup_writes_memory_swap_and_oom_group() {
        let (dir, sup) = temp_supervisor(false);
        let id = uuid::Uuid::from_u128(1);
        let mut vc = sup.create_vm_cgroup(id, 2, 512).unwrap();
        let d = dir.path().join(format!("vm-{id}"));
        assert_eq!(
            fs::read_to_string(d.join("memory.max")).unwrap().trim(),
            (768u64 * 1024 * 1024).to_string()
        );
        assert_eq!(
            fs::read_to_string(d.join("memory.swap.max"))
                .unwrap()
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(d.join("memory.oom.group"))
                .unwrap()
                .trim(),
            "1"
        );
        assert!(
            !d.join("cpu.max").exists(),
            "cpu.max only when cpu_limit=true"
        );
        vc.remove();
        assert!(!d.exists(), "remove() rmdirs the cgroup");
    }

    #[tokio::test]
    async fn create_vm_cgroup_writes_cpu_max_when_enabled() {
        let (dir, sup) = temp_supervisor(true);
        let id = uuid::Uuid::from_u128(2);
        let _vc = sup.create_vm_cgroup(id, 4, 1024).unwrap();
        let d = dir.path().join(format!("vm-{id}"));
        assert_eq!(
            fs::read_to_string(d.join("cpu.max")).unwrap().trim(),
            "400000 100000"
        );
    }

    #[tokio::test]
    async fn place_writes_pid_to_cgroup_procs() {
        let (dir, sup) = temp_supervisor(false);
        let id = uuid::Uuid::from_u128(3);
        let vc = sup.create_vm_cgroup(id, 1, 128).unwrap();
        vc.place(4242).unwrap();
        let procs = dir.path().join(format!("vm-{id}")).join("cgroup.procs");
        assert_eq!(fs::read_to_string(procs).unwrap().trim(), "4242");
    }

    #[test]
    fn disabled_supervisor_produces_noop_cgroups() {
        let sup = CgroupSupervisor::disabled();
        let mut vc = sup.create_vm_cgroup(uuid::Uuid::nil(), 1, 128).unwrap();
        vc.place(1).unwrap(); // no-op, no error
        vc.remove(); // no-op
    }

    #[test]
    fn drop_removes_the_cgroup() {
        let (dir, sup) = temp_supervisor(false);
        let id = uuid::Uuid::from_u128(9);
        let d = dir.path().join(format!("vm-{id}"));
        {
            let _vc = sup.create_vm_cgroup(id, 1, 128).unwrap();
            assert!(d.exists());
        } // _vc drops here → Drop rmdirs
        assert!(!d.exists(), "Drop removes the cgroup dir");
    }

    #[test]
    fn memory_max_is_guest_plus_overhead_in_bytes() {
        // 512 MiB guest + 256 MiB margin = 768 MiB.
        assert_eq!(memory_max_bytes(512, 256), 768 * 1024 * 1024);
        assert_eq!(memory_max_bytes(0, 256), 256 * 1024 * 1024);
    }

    #[test]
    fn cpu_max_line_caps_to_vcpu_cores() {
        // 2 vCPUs at the 100000us period => "200000 100000".
        assert_eq!(cpu_max_line(2), "200000 100000");
        assert_eq!(cpu_max_line(1), "100000 100000");
    }

    #[test]
    fn parse_self_cgroup_takes_the_v2_line() {
        let content = "0::/system.slice/husker.service\n";
        assert_eq!(
            parse_self_cgroup_path(content).as_deref(),
            Some("/system.slice/husker.service")
        );
        // A v1-only cgroup file has no `0::` line.
        assert_eq!(parse_self_cgroup_path("1:cpu:/foo\n"), None);
    }

    #[test]
    fn vm_cgroup_dir_name_is_prefixed() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            vm_cgroup_dir_name(id),
            "vm-00000000-0000-0000-0000-000000000000"
        );
    }
}
