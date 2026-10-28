use anyhow::Result;
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    info!("husker-agent starting");

    // The factory image performs its strict offline mount setup in /sbin/init.
    // Reuse only PID-1 child supervision: OCI networking, shares and volume
    // discovery must never run on this path.
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.iter().any(|arg| arg == "--factory-supervisor") {
        anyhow::ensure!(
            arguments.len() == 1,
            "factory supervisor accepts no extra arguments"
        );
        #[cfg(target_os = "linux")]
        return husker_agent::supervisor::run_factory();
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("factory supervisor requires a Linux guest PID 1; refusing host execution");
    }

    // Guest init/supervisor mode: when booted as PID 1 with the husker.init=1
    // marker (set by import-oci images), the agent becomes a minimal init - it
    // performs mounts/network/device setup and then supervises itself as a
    // restartable child, never returning. Otherwise (normal agent, or the
    // supervisor's own child) it serves requests. No image sets husker.init=1
    // until the import-oci boot_init flip, so production boot is unchanged.
    #[cfg(target_os = "linux")]
    {
        let is_pid1 = std::process::id() == 1;
        // As PID 1 nothing is mounted yet, so /proc/cmdline is unreadable until we
        // mount /proc. Do it first (idempotent with the supervisor's own mounts)
        // so supervisor mode can actually be detected.
        if is_pid1 {
            husker_agent::supervisor::mount_proc();
        }
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if husker_agent::is_supervisor_mode(is_pid1, &cmdline) {
            husker_agent::supervisor::run(&cmdline);
        }
    }

    husker_agent::serve::run_agent()
}
