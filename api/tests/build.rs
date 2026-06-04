// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::process;

#[cfg(target_os = "windows")]
use xshell::Shell;
#[cfg(target_os = "windows")]
use xshell::cmd;

#[cfg(target_os = "windows")]
const VS2026_GEN_NAME: &str = "Visual Studio 18 2026";
#[cfg(target_os = "windows")]
const VS2022_GEN_NAME: &str = "Visual Studio 17 2022";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MOCK");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
    println!("cargo:rerun-if-env-changed=ProgramFiles(x86)");
    println!("cargo:rerun-if-env-changed=ProgramFiles");

    env_logger::init();

    if let Err(e) = try_main() {
        log::error!("Error: {:#}", e);
        process::exit(1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let mut features = Vec::new();
    if env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }
    let mut config = cmake::Config::new("cpp");
    config.define("TEST_FEATURES", features.join(" "));

    // On Windows, use vswhere.exe to detect installed Visual Studio versions and
    // select the appropriate CMake generator unless CMAKE_GENERATOR is already set.
    // Tried Ninja but it was producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if env::var("CMAKE_GENERATOR").is_err() {
        // default to VS2022 generator
        config.generator(VS2022_GEN_NAME);

        // locate and run vswhere tool to detect VS2026
        let vswhere_dir = env::var("ProgramFiles(x86)")
            .or_else(|_| env::var("ProgramFiles"))
            .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
        let vswhere = Path::new(&vswhere_dir)
            .join("Microsoft Visual Studio")
            .join("Installer")
            .join("vswhere.exe");
        if vswhere.exists() {
            let sh = Shell::new()?;
            let output = cmd!(
                sh,
                "{vswhere} -products * -property installationVersion -prerelease"
            )
            .quiet()
            .output()?;
            if output.status.success() {
                let stdout = String::from_utf8(output.stdout)?;
                let has_vs2026 = stdout.lines().any(|v| v.trim().starts_with("18."));
                if has_vs2026 {
                    config.generator(VS2026_GEN_NAME);
                }
            }
        }
    }

    let _dst = config.build();
    Ok(())
}
