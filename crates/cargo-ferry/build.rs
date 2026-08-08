//! Mark binaries compiled from Cargo-packaged source for registry-runtime reporting.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("Cargo must provide CARGO_MANIFEST_DIR to build scripts"),
    );
    let packaged_source = manifest_dir.join(".cargo_vcs_info.json").is_file();
    println!(
        "cargo:rustc-env=RUSTFERRY_PACKAGED_SOURCE={}",
        u8::from(packaged_source)
    );
}
