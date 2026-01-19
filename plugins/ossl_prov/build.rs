// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(target_os = "linux")]
fn main() {
    let mut features = Vec::new();
    let provider_feature_enabled = std::env::var("CARGO_FEATURE_PROVIDER").is_ok();

    if std::env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }

    cmake::Config::new(".")
        .define("AZIHSM_CARGO_FEATURES", features.join(" "))
        .build();

    // If provider feature is enabled, copy the .so to target directory
    if provider_feature_enabled {
        if let Err(e) = copy_provider_so() {
            println!("cargo:warning=Failed to copy provider .so: {}", e);
        }
    }
}

#[cfg(target_os = "linux")]
fn copy_provider_so() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::PathBuf;
    use std::time::SystemTime;

    // Get profile (debug or release)
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    // Get build directory
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    // Navigate from OUT_DIR (target/debug/build/azishm_ossl_provider-<hash>/out)
    // Ancestors: 0=out, 1=HASH, 2=build, 3=debug, 4=target, 5=project_root
    let root = out_dir
        .ancestors()
        .nth(5)
        .ok_or("Could not find project root from OUT_DIR")?;

    let build_parent = root.join("target").join("debug").join("build");

    // Find all azihsm_provider.so files
    let mut so_files = Vec::new();

    if let Ok(entries) = fs::read_dir(&build_parent) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && path.file_name().map_or(false, |n| {
                    n.to_string_lossy().starts_with("azishm_ossl_provider-")
                })
            {
                let so_path = path.join("out").join("build").join("azihsm_provider.so");
                if so_path.exists() {
                    so_files.push(so_path);
                }
            }
        }
    }

    // Find the most recently modified .so
    let latest_so = so_files.into_iter().max_by_key(|path| {
        path.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });

    if let Some(source) = latest_so {
        let dest = root
            .join("target")
            .join(&profile)
            .join("azihsm_provider.so");

        // Ensure destination directory exists
        if let Some(dest_dir) = dest.parent() {
            fs::create_dir_all(dest_dir)?;
        }

        fs::copy(&source, &dest)?;
        println!(
            "cargo:warning=Copied azihsm_provider.so to target/{}/",
            profile
        );
        Ok(())
    } else {
        Err("Could not find azihsm_provider.so in CMake build output".into())
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
