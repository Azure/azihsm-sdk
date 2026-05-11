// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let mut config = cmake::Config::new("cpp");
    config.define("TEST_FEATURES", features.join(" "));

    // On Windows, force the VS 2026 generator unless CMAKE_GENERATOR is set.
    // Tried Ninja but it was producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if std::env::var("CMAKE_GENERATOR").is_err() {
        config.generator("Visual Studio 18 2026");
    }

    let _dst = config.build();
}
