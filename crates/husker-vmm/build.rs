mod build_source;

fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap().parent().unwrap();
    // Published standalone library packages do not contain the whole workspace.
    // Preserve their ordinary backends, but do not claim a workspace pairing.
    let (digest, files) = if root.join("Cargo.toml").is_file() && root.join("crates").is_dir() {
        build_source::source_digest(root).expect("digest workspace Rust sources")
    } else {
        ("unavailable".into(), vec![manifest.join("Cargo.toml")])
    };
    println!("cargo:rustc-env=HUSKER_WORKSPACE_RUST_SOURCE_SHA256={digest}");
    println!(
        "cargo:rustc-env=HUSKER_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    // Directory tracking also notices newly added/removed Rust source files.
    println!("cargo:rerun-if-changed={}", root.join("crates").display());
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
