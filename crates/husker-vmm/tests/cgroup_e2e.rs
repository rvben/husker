//! Real-cgroup enforcement. Gated: needs a delegated cgroup v2 subtree.
//! Run on a Linux host (e.g. husker-dev) with:
//!   HUSKER_RUN_CGROUP_E2E=1 cargo test -p husker-vmm --test cgroup_e2e
//!
//! The test creates a per-VM cgroup with a fixed UUID, asserts that
//! memory.max / memory.swap.max / memory.oom.group / cpu.max are written
//! correctly, places a child process into the cgroup, confirms it appears in
//! cgroup.procs, and verifies the cgroup directory is gone after remove().
#![cfg(target_os = "linux")]

#[tokio::test]
async fn cgroup_enforces_memory_max_and_removes_on_drop() {
    if std::env::var("HUSKER_RUN_CGROUP_E2E").is_err() {
        eprintln!(
            "skipping cgroup_e2e: set HUSKER_RUN_CGROUP_E2E=1 on a host with \
             a delegated cgroup v2 subtree"
        );
        return;
    }

    // Read the base cgroup path before init so we can find the vm dir later.
    // init() moves the current process to a `supervisor` leaf, which changes
    // /proc/self/cgroup; snapshot it now to get the parent's path.
    let self_cg = std::fs::read_to_string("/proc/self/cgroup")
        .expect("/proc/self/cgroup must be readable");
    let rel = self_cg
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        .expect("must run on a cgroup v2 unified hierarchy (0:: line missing)");
    let cgroup_base = std::path::PathBuf::from("/sys/fs/cgroup")
        .join(rel.trim_start_matches('/'));

    let sup = husker_vmm::cgroup::CgroupSupervisor::init(husker_vmm::cgroup::CgroupConfig {
        enabled: true,
        memory_overhead_mib: 256,
        cpu_limit: true,
    })
    .unwrap_or_else(|e| {
        panic!(
            "CgroupSupervisor::init failed: {e}\n\
             Ensure Delegate=yes is set in the husker.service unit and the \
             parent slice exposes memory + cpu controllers."
        )
    });

    let vm_id = uuid::Uuid::from_u128(0xE2E);
    let mut vc = sup.create_vm_cgroup(vm_id, 2, 128).unwrap();

    let vm_dir = cgroup_base.join(format!("vm-{vm_id}"));
    assert!(vm_dir.exists(), "vm cgroup dir must exist: {}", vm_dir.display());

    // memory.max = (128 + 256) * 1024 * 1024 = 402653184
    let expected_mem: u64 = (128 + 256) * 1024 * 1024;
    assert_eq!(
        std::fs::read_to_string(vm_dir.join("memory.max"))
            .unwrap()
            .trim(),
        expected_mem.to_string(),
        "memory.max mismatch"
    );
    assert_eq!(
        std::fs::read_to_string(vm_dir.join("memory.swap.max"))
            .unwrap()
            .trim(),
        "0",
        "memory.swap.max must be 0"
    );
    assert_eq!(
        std::fs::read_to_string(vm_dir.join("memory.oom.group"))
            .unwrap()
            .trim(),
        "1",
        "memory.oom.group must be 1"
    );
    // 2 vCPUs * 100000 us period = "200000 100000"
    assert_eq!(
        std::fs::read_to_string(vm_dir.join("cpu.max"))
            .unwrap()
            .trim(),
        "200000 100000",
        "cpu.max mismatch"
    );

    // Spawn a child and place it in the cgroup; verify it appears in cgroup.procs.
    let mut child = tokio::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("failed to spawn `sleep 300`");
    let child_pid = child.id().expect("child must have a pid");

    vc.place(child_pid).expect("place must succeed");

    let procs = std::fs::read_to_string(vm_dir.join("cgroup.procs"))
        .expect("cgroup.procs must be readable after place");
    let pids: Vec<u32> = procs
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect();
    assert!(
        pids.contains(&child_pid),
        "child pid {child_pid} must appear in cgroup.procs; got: {procs:?}"
    );

    // Tear down: kill the child, remove the cgroup, assert the dir is gone.
    child.kill().await.ok();
    child.wait().await.ok();
    vc.remove();

    assert!(
        !vm_dir.exists(),
        "vm cgroup dir must be removed after remove(): {}",
        vm_dir.display()
    );
}
