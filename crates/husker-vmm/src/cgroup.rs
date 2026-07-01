//! cgroup v2 resource limits for the Linux VMM process (Firecracker/QEMU).
//! Opt-in; a no-op when disabled. See
//! docs/superpowers/specs/2026-07-01-husker-cgroup-resource-limits-design.md.

/// Default host-memory margin over the guest RAM, covering the VMM's own
/// anonymous memory. Firecracker-safe; QEMU with large VMs may need more.
pub const DEFAULT_MEMORY_OVERHEAD_MIB: u32 = 256;

/// cgroup v2 CPU accounting period (microseconds).
#[cfg_attr(not(test), allow(dead_code))]
const CPU_PERIOD_US: u32 = 100_000;

/// Resource-limit configuration resolved from the daemon config.
#[derive(Clone, Debug)]
pub struct CgroupConfig {
    pub enabled: bool,
    pub memory_overhead_mib: u32,
    pub cpu_limit: bool,
}

/// `memory.max` value in bytes: guest RAM plus the VMM overhead margin.
#[cfg_attr(not(test), allow(dead_code))]
fn memory_max_bytes(mem_size_mib: u32, overhead_mib: u32) -> u64 {
    (mem_size_mib as u64 + overhead_mib as u64) * 1024 * 1024
}

/// `cpu.max` line ("<quota> <period>") capping the VM to `vcpu_count` cores.
#[cfg_attr(not(test), allow(dead_code))]
fn cpu_max_line(vcpu_count: u32) -> String {
    format!("{} {}", vcpu_count.max(1) * CPU_PERIOD_US, CPU_PERIOD_US)
}

/// Extract the cgroup v2 path from `/proc/self/cgroup` (the `0::<path>` line).
#[cfg_attr(not(test), allow(dead_code))]
fn parse_self_cgroup_path(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        .filter(|p| !p.is_empty())
}

/// Per-VM cgroup directory name under the delegated subtree.
#[cfg_attr(not(test), allow(dead_code))]
fn vm_cgroup_dir_name(id: uuid::Uuid) -> String {
    format!("vm-{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(vm_cgroup_dir_name(id), "vm-00000000-0000-0000-0000-000000000000");
    }
}
