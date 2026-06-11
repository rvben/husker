//! Stage the guest agent for embedding into the daemon.
//!
//! The agent binary is copied to `OUT_DIR/agent.bin` so `src/lib.rs` can
//! `include_bytes!` it for cloud-image seeds. The target architecture is
//! inferred from the build target: Apple Silicon (`aarch64-apple-darwin`) daemons
//! embed the aarch64-musl agent (Apple VZ cloud images); all other targets default
//! to the x86_64-musl agent (Firecracker/QEMU cloud images). Intel macOS builds
//! will not find a pre-built x86_64-musl agent on a Mac, staging an empty blob
//! and producing a runtime error if cloud-image is attempted - which is expected.
//!
//! If the agent is absent, an empty blob is staged so normal builds (the
//! microVM path) still compile; cloud-image then errors clearly at runtime.

use std::path::PathBuf;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let dest = PathBuf::from(&out_dir).join("agent.bin");

    let env_path = std::env::var("HUSKER_EMBED_AGENT_BIN").ok();
    let candidate = match &env_path {
        Some(p) => PathBuf::from(p),
        None => {
            let manifest = PathBuf::from(
                std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
            );
            // Target-aware conventional agent path: Apple Silicon daemons embed the
            // aarch64-musl agent (VZ cloud images), all other targets embed x86_64-musl.
            let target = std::env::var("TARGET").unwrap_or_default();
            let rel = if target == "aarch64-apple-darwin" {
                "../../target/aarch64-unknown-linux-musl/agent/husker-agent"
            } else {
                "../../target/x86_64-unknown-linux-musl/agent/husker-agent"
            };
            manifest.join(rel)
        }
    };

    if candidate.exists() {
        std::fs::copy(&candidate, &dest).expect("copy embedded agent");
        println!("cargo:rerun-if-changed={}", candidate.display());
    } else {
        // Stage an empty blob so normal builds compile. Cloud-image is opt-in;
        // warn only when the agent path was explicitly requested but does not exist.
        std::fs::write(&dest, b"").expect("write empty agent placeholder");
        if let Some(p) = &env_path {
            println!(
                "cargo:warning=husker: HUSKER_EMBED_AGENT_BIN={p} does not exist - cloud-image agent not embedded"
            );
        }
    }
    println!("cargo:rerun-if-env-changed=HUSKER_EMBED_AGENT_BIN");
}
