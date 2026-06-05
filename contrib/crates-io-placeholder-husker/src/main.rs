fn main() {
    eprintln!("husker is distributed as a prebuilt binary, not via crates.io.");
    eprintln!();
    eprintln!("Install it with one of:");
    eprintln!("    pip install husker");
    eprintln!("    brew install rvben/tap/husker");
    eprintln!("    download from https://github.com/rvben/husker/releases");
    eprintln!();
    eprintln!("This crate only reserves the name. Docs: https://github.com/rvben/husker");
    std::process::exit(1);
}
