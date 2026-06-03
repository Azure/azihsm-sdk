// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use jzon::parse;
use xshell::cmd;

const VS2026_GEN_NAME: &str = "Visual Studio 18 2026";
const VS2022_GEN_NAME: &str = "Visual Studio 17 2022";

fn main() {
    env_logger::init();

    if let Err(e) = try_main() {
        log::error!("Error: {:#}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let mut config = cmake::Config::new("cpp");
    config.define("TEST_FEATURES", features.join(" "));

    let sh = xshell::Shell::new()?;

    // Run 'cmake -E capabilities' command to gather JSON output of CMake capabilities.
    let capabilities_output = cmd!(sh, "cmake -E capabilities").quiet().output()?;
    if !capabilities_output.status.success() {
        panic!(
            "'cmake -E capabilities' command failed with status: {}",
            capabilities_output.status
        );
    }
    let capabilities_json = String::from_utf8(capabilities_output.stdout)?;
    let capabilities = parse(&capabilities_json)?;

    // parse the JSON output and extract the list of available generators.
    let mut gen_names = Vec::new();
    if let Some(gen_objs) = capabilities["generators"]
        .members()
        .next()
        .map(|_| capabilities["generators"].members())
    {
        for gen_obj in gen_objs {
            if let Some(name) = gen_obj["name"].as_str() {
                gen_names.push(name.to_string());
            }
        }
    }

    // On Windows, force the VS 2026 generator unless CMAKE_GENERATOR is set.
    // Tried Ninja but it was producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if std::env::var("CMAKE_GENERATOR").is_err() {
        // check if VS2026 generator is available
        let vs2026_available = gen_names.iter().any(|name| name == VS2026_GEN_NAME);
        if vs2026_available {
            config.generator(VS2026_GEN_NAME);
        } else {
            // fall back to VS2022 if VS2026 is not available
            config.generator(VS2022_GEN_NAME);
        }
    }

    let _dst = config.build();
    Ok(())
}
