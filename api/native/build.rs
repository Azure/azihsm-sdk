// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Get the output directory and pass it to CMake
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = std::path::PathBuf::from(&out_dir);

    // Navigate up to find the target directory: OUT_DIR is in target/profile/build/crate-hash/out
    // We need to go up 3 levels to get to target/profile/
    if let Some(target_dir) = out_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
    {
        println!("cargo:rustc-env=AZIHSM_TARGET_DIR={}", target_dir.display());
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
