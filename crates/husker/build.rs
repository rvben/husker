//! Stage the guest agent for embedding into the daemon.
//!
//! The agent (x86_64-musl, built by `make build-agent`) is copied to
//! `OUT_DIR/agent.bin` so `src/lib.rs` can `include_bytes!` it for cloud-image
//! seeds. If the agent is absent, an empty blob is staged so normal builds (the
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
            // crates/husker -> workspace root -> conventional musl agent output.
            manifest.join("../../target/x86_64-unknown-linux-musl/agent/husker-agent")
        }
    };

    if candidate.exists() {
        std::fs::copy(&candidate, &dest).expect("copy embedded agent");
        println!("cargo:rerun-if-changed={}", candidate.display());
    } else {
        // Stage an empty blob so normal builds compile. Stay silent for the common
        // "did not run make build-agent" case; cloud-image is opt-in and Linux-only.
        // Warn only when the agent path was explicitly requested but does not exist.
        std::fs::write(&dest, b"").expect("write empty agent placeholder");
        if let Some(p) = &env_path {
            println!(
                "cargo:warning=husker: HUSKER_EMBED_AGENT_BIN={p} does not exist - cloud-image agent not embedded"
            );
        }
    }
    println!("cargo:rerun-if-env-changed=HUSKER_EMBED_AGENT_BIN");
}
