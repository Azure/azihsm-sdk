// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-env-changed=RUSTC_WORKSPACE_WRAPPER");

    // Skip the CMake/Corrosion build when running under clippy/check.
    // They only need to type-check Rust source — they don't link, so the
    // C++ test binary isn't needed.  Building it via Corrosion would
    // recompile the FFI crate + transitive deps into a separate target
    // dir, doubling lint-job time on slow runners.
    let is_clippy = std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|w| w.contains("clippy"))
        .unwrap_or(false);
    if is_clippy {
        println!("cargo:warning=azihsm_api_tests: skipping CMake build for clippy");
        return;
    }

    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let mut config = cmake::Config::new("cpp");
    config.define("TEST_FEATURES", features.join(" "));

    // The cmake crate auto-detects the generator, but does not support
    // newer toolsets (e.g. "Visual Studio 18 2026"). On Windows, force the
    // VS 2022 generator unless CMAKE_GENERATOR is explicitly set.
    // Tried Ninja but it was producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if std::env::var("CMAKE_GENERATOR").is_err() {
        config.generator("Visual Studio 17 2022");
    }

    // CMake invokes Corrosion which spawns a nested `cargo rustc
    // --print=native-static-libs` to probe required native libs.  That
    // inner cargo inherits CARGO_TARGET_DIR from our environment — same
    // target dir as the outer cargo build → flock() deadlock on
    // <target>/<profile>/.cargo-lock.
    //
    // Redirect the inner cargo's target dir to an isolated sub-path so
    // the outer cargo's lock is not contended.  Linux-only because the
    // deadlock has only been observed there and Windows MSBuild's cargo
    // integration may differ.
    #[cfg(not(target_os = "windows"))]
    {
        use std::path::PathBuf;
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
        config.env("CARGO_TARGET_DIR", out_dir.join("corrosion-target"));
    }

    let _dst = config.build();
}
