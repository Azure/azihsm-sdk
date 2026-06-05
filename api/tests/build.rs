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
    // Instruct Cargo to re-run this build script if any of the following env
    // vars changed since they impact the CMake configuration.
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

    // On Windows, use get_vs_gen helper method to select the appropriate CMake
    // generator unless CMAKE_GENERATOR is already set. Tried Ninja but it was
    // producing invalid paths on Windows.
    #[cfg(target_os = "windows")]
    if env::var("CMAKE_GENERATOR").is_err() {
        config.generator(&get_vs_gen()?);
    }

    let _dst = config.build();
    Ok(())
}

// Windows-specific helper method to use vswhere.exe to detect installed Visual
// Studio versions.
#[cfg(target_os = "windows")]
fn get_vs_gen() -> anyhow::Result<String> {
    // locate and run vswhere tool to detect VS2026
    let vswhere_dir = env::var("ProgramFiles(x86)")
        .or_else(|_| env::var("ProgramFiles"))
        .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
    let vswhere = Path::new(&vswhere_dir)
        .join("Microsoft Visual Studio")
        .join("Installer")
        .join("vswhere.exe");
    if vswhere.try_exists()? {
        let sh = Shell::new()?;
        let output = cmd!(
            sh,
            "{vswhere} -products * -property installationVersion -prerelease"
        )
        .quiet()
        .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "vswhere.exe failed ({}): {}",
                output.status,
                stderr.trim()
            ));
        }

        let stdout = String::from_utf8(output.stdout)?;
        let has_vs2026 = stdout.lines().any(|v| v.trim().starts_with("18."));
        let has_vs2022 = stdout.lines().any(|v| v.trim().starts_with("17."));
        if has_vs2026 {
            return Ok(VS2026_GEN_NAME.to_string());
        } else if has_vs2022 {
            return Ok(VS2022_GEN_NAME.to_string());
        } else {
            return Err(anyhow::anyhow!(
                "Neither Visual Studio 2026 nor 2022 was detected by vswhere.exe"
            ));
        }
    }
    Err(anyhow::anyhow!(
        "vswhere.exe not found, cannot detect installed Visual Studio versions"
    ))
}
