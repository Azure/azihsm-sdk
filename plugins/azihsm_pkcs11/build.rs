// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Drives the CMake build of the C PKCS#11 module. Mirrors
// plugins/ossl_prov/build.rs: it forwards the enabled cargo features and the
// cargo target directory to CMake so the resulting shared object is copied
// alongside the other build artifacts.

#[cfg(target_os = "linux")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    let mut features = Vec::new();
    if env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }

    // OUT_DIR is target/<profile>/build/<crate-hash>/out; go up 3 to <profile>.
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

    // Forward OPENSSL_DIR if set (azihsm_api_native links openssl-sys via the
    // crypto crate); harmless if unset (system OpenSSL is discovered).
    if let Ok(openssl_dir) = env::var("OPENSSL_DIR") {
        cmake_cfg.define("OPENSSL_ROOT_DIR", &openssl_dir);
    }

    cmake_cfg.build();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
