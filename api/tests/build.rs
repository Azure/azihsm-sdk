// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
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

    let _dst = config.build();
}
