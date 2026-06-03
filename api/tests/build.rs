// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let mut config = cmake::Config::new("cpp");
    config.define("TEST_FEATURES", features.join(" "));

    // Run 'cmake -E capabilities' command to gather JSON output of CMake capabilities.
    let capabilities_output = std::process::Command::new("cmake")
        .args(&["-E", "capabilities"])
        .output()
        .expect("Failed to execute 'cmake -E capabilities' command");
    if !capabilities_output.status.success() {
        panic!("'cmake -E capabilities' command failed with status: {}", capabilities_output.status);
    }
    let capabilities_json = String::from_utf8(capabilities_output.stdout)
        .expect("Failed to parse 'cmake -E capabilities' output as UTF-8");
    let capabilities: jzon::JsonValue = jzon::parse(&capabilities_json)
        .expect("Failed to parse 'cmake -E capabilities' output as JSON");

    // use jzon to parse the JSON output and extract the list of available CMake generators.
    let mut generator_names = Vec::new();

    if let Some(generators) = capabilities["generators"].members().next().map(|_| capabilities["generators"].members()) {
        for generator in generators {
            if let Some(name) = generator["name"].as_str() {
                generator_names.push(name.to_string());
            }
        }
    }


    // On Windows, force the VS 2026 generator unless CMAKE_GENERATOR is set.
    // Tried Ninja but it was producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if std::env::var("CMAKE_GENERATOR").is_err() {
        // check is VS2026 generator is available
        let vs2026_available = generator_names.iter().any(|name| name == "Visual Studio 18 2026");
        if vs2026_available {
            config.generator("Visual Studio 18 2026");
        }
        else {
            // fall back to VS2022 if VS2026 is not available
            config.generator("Visual Studio 17 2022");
        }
    }

    let _dst = config.build();
}
