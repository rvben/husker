use std::path::Path;

#[test]
fn configure_self_cgroup_creates_leaf_and_writes_limits() {
    let root = tempfile::tempdir().unwrap();
    husker_agent::configure_self_cgroup(root.path(), 64 * 1024 * 1024).unwrap();

    let leaf = root.path().join("husker-agent");
    assert!(leaf.is_dir());
    assert_eq!(
        std::fs::read_to_string(leaf.join("memory.high")).unwrap(),
        (64u64 * 1024 * 1024).to_string()
    );
    assert_eq!(
        std::fs::read_to_string(leaf.join("cgroup.procs")).unwrap(),
        std::process::id().to_string()
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap(),
        "+memory"
    );
}

#[test]
fn configure_self_cgroup_errors_on_unwritable_root() {
    let result = husker_agent::configure_self_cgroup(
        Path::new("/nonexistent-husker-cgroup-test-root"),
        64 * 1024 * 1024,
    );
    assert!(result.is_err());
}
