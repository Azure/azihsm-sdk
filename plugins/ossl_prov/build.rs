// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    let mut features = Vec::new();

    if env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }

    // Calculate the target directory for passing to CMake
    // OUT_DIR is in target/profile/build/crate-hash/out, so we go up 3 levels
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let target_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Could not determine target directory");

    let mut cmake_cfg = cmake::Config::new(".");
    cmake_cfg
        .define("AZIHSM_CARGO_FEATURES", features.join(" "))
        .define(
            "AZIHSM_TARGET_DIR",
            target_dir.to_string_lossy().to_string(),
        );

    // Forward OPENSSL_DIR to CMake so find_package(OpenSSL) discovers the
    // same OpenSSL that the Rust openssl-sys crate links against.
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        cmake_cfg.define("OPENSSL_ROOT_DIR", &openssl_dir);
    }

    cmake_cfg.build();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
