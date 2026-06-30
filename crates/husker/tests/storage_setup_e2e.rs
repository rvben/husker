//! Real loopback round-trip for `husker setup storage`. The body only runs with
//! HUSKER_RUN_PRIVILEGED_E2E=1 on Linux with sudo (loop devices + mount); the
//! file compiles on every platform and the test skips (early return) otherwise.

use std::path::Path;
use std::process::Command;

fn gated() -> bool {
    std::env::var("HUSKER_RUN_PRIVILEGED_E2E").as_deref() == Ok("1")
}

#[test]
fn generated_script_migrates_and_data_survives() {
    if !gated() {
        eprintln!("skipping: set HUSKER_RUN_PRIVILEGED_E2E=1 (Linux+sudo) to run");
        return;
    }
    // Lay out a fake data dir with images/, vms/, a marker file, and a fake DB.
    let root = tempfile::tempdir().unwrap();
    let data_dir = root.path().join("data");
    std::fs::create_dir_all(data_dir.join("images")).unwrap();
    std::fs::create_dir_all(data_dir.join("vms")).unwrap();
    std::fs::write(data_dir.join("husker.db"), b"fake-sqlite").unwrap();
    std::fs::write(data_dir.join("images/base.ext4"), vec![7u8; 1024 * 1024]).unwrap();

    // Build a plan pointed at the temp layout and render the script.
    let plan = husker::storage_setup::StorageSetupPlan {
        data_dir: data_dir.clone(),
        state_dir: root.path().join("state"),
        image_path: root.path().join("vol.img"),
        size: "256M".into(),
        fs: husker::storage_setup::SetupFs::Xfs,
        persist: husker::storage_setup::SetupPersist::Fstab, // avoid touching real systemd
        thin: false,
        config_file: root.path().join("config.toml"),
        api_addr: "127.0.0.1:59999".into(), // nothing listening
    };
    let script = husker::storage_setup::render_migration_script(&plan);
    let script_path = root.path().join("migrate.sh");
    std::fs::write(&script_path, &script).unwrap();

    // The fstab branch appends to /etc/fstab; run with a redirected fstab by
    // bind-mounting a temp file is complex - instead assert the migration up to
    // the mount succeeds and the data survived. Run under sudo.
    let out = Command::new("sudo")
        .arg("bash")
        .arg(&script_path)
        .output()
        .expect("run script");
    assert!(
        out.status.success(),
        "script failed:\nSTDOUT {}\nSTDERR {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The data dir is now a mounted reflink volume; the base image survived.
    assert!(data_dir.join("images/base.ext4").exists(), "migrated data missing");
    assert!(
        is_reflink_capable(&data_dir.join("images"), &data_dir.join("vms")),
        "migrated data dir is not reflink-capable"
    );
    // Original kept as backup.
    let backup = format!("{}.pre-reflink.bak", data_dir.display());
    assert!(Path::new(&backup).exists(), "original backup missing");

    // Cleanup: unmount + remove (best-effort).
    let _ = Command::new("sudo").args(["umount", data_dir.to_str().unwrap()]).status();
}

fn is_reflink_capable(images: &Path, vms: &Path) -> bool {
    matches!(
        husker_storage::probe_reflink(images, vms),
        Ok(husker_storage::ReflinkStatus::Supported)
    )
}
