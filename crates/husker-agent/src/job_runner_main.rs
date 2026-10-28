//! Trusted entry point launched by a durable host-owned factory session.
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--prepare" {
        return husker_agent::job_runner::prepare(&args[2], &args[3]);
    }
    anyhow::ensure!(
        args.len() == 3,
        "usage: husker-job-runner [--prepare] JOB_UUID SPEC_SHA256"
    );
    tokio::runtime::Runtime::new()?.block_on(husker_agent::job_runner::run(&args[1], &args[2]))
}
