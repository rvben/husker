//! Internal opt-in worker entry point, not a supported daemon or job CLI.
#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(
        args.len() == 3,
        "usage: husker-vz-worker PRIVATE_RUNTIME_DIR VM_UUID DEADLINE_EPOCH (inherited parent pipe required)"
    );
    let id_text = args[1]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("VM UUID must be UTF-8"))?;
    let id: uuid::Uuid = id_text.parse()?;
    anyhow::ensure!(
        !id.is_nil() && id.to_string() == id_text,
        "canonical nonnil VM UUID required"
    );
    let deadline: u64 = args[2]
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("deadline must be UTF-8"))?
        .parse()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(husker_vmm::vz_worker::serve(
        std::path::Path::new(&args[0]),
        id,
        deadline,
    ))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("VZ worker requires macOS; refusing execution on this host");
    std::process::exit(2);
}
