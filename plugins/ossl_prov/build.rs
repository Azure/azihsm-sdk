// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    // Cargo should re-run this script when these env vars change so that
    // switching OpenSSL versions correctly invalidates the build.
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");

    let mut features = Vec::new();

    if env::var("CARGO_FEATURE_MOCK").is_ok() {
        features.push("mock");
    }

    // Derive the cargo profile directory (e.g., target/<profile>) for CMake.
    // OUT_DIR is in <target>/<profile>/build/<crate-hash>/out, so 3 parents up.
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Could not determine profile directory");

    // The actual target dir is one more level up; its leaf encodes the ABI.
    let target_dir = profile_dir
        .parent()
        .expect("Could not determine target directory");

    // The provider must be built in an ABI-versioned target directory so that
    // artifacts compiled against different OpenSSL ABI versions never share a
    // build tree.  This avoids silent version mismatches between the linked
    // libcrypto and the openssl binary used at test time.
    //
    // Expected target dir name: ossl-abi-<major>-<minor>  (e.g., ossl-abi-3-0)
    //
    // The default is set in .cargo/config.toml; override via:
    //   - cargo xtask <cmd> --openssl-version <ver>
    //   - CARGO_TARGET_DIR=target/ossl-abi-<major>-<minor> cargo ...
    let leaf = target_dir
        .file_name()
        .and_then(|s| s.to_str())
        .expect("target directory has no name");

    let abi = leaf.strip_prefix("ossl-abi-").unwrap_or_else(|| {
        panic!(
            "azihsm_ossl_provider must be built in an OpenSSL ABI-versioned target dir.\n\
             Expected CARGO_TARGET_DIR to end with /ossl-abi-<major>-<minor>/, got: {}\n\
             Use `cargo xtask <cmd> --openssl-version <ver>` (recommended), or set \
             CARGO_TARGET_DIR=target/ossl-abi-<major>-<minor> explicitly.",
            target_dir.display()
        );
    });

    // Validate the format: <major>-<minor> with numeric components.
    let parts: Vec<&str> = abi.split('-').collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()))
    {
        panic!(
            "CARGO_TARGET_DIR leaf must follow pattern ossl-abi-<major>-<minor> with numeric \
             components, got: ossl-abi-{abi}"
        );
    }

    // Supported ABI versions.  Keep in sync with xtask/src/openssl_install.rs.
    if !matches!(abi, "3-0" | "3-5") {
        panic!(
            "Unsupported OpenSSL ABI {abi}; supported: 3-0, 3-5. \
             Add it to SUPPORTED_VERSIONS in xtask/src/openssl_install.rs."
        );
    }

    // Derive OPENSSL_DIR from the target dir unless explicitly overridden.
    // The xtask installs OpenSSL to <target_dir>/openssl by convention.
    let openssl_dir = match env::var("OPENSSL_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => target_dir.join("openssl"),
    };

    // AZIHSM_TARGET_DIR is used by CMake to copy the .so into the cargo
    // profile dir (e.g., target/ossl-abi-3-0/debug/), so pass profile_dir.
    let mut cmake_cfg = cmake::Config::new(".");
    cmake_cfg
        .define("AZIHSM_CARGO_FEATURES", features.join(" "))
        .define(
            "AZIHSM_TARGET_DIR",
            profile_dir.to_string_lossy().to_string(),
        )
        .define("OPENSSL_ROOT_DIR", openssl_dir);

    // CMake invokes Corrosion which spawns `cargo rustc --print=native-static-libs`
    // to probe required native libs.  That inner cargo inherits CARGO_TARGET_DIR
    // from our environment — pointing at the same target dir as the outer cargo
    // build → flock() deadlock on <target>/<profile>/.cargo-lock.
    //
    // Redirect the inner cargo's target dir to an isolated sub-path so the
    // outer cargo's lock is not contended.
    cmake_cfg.env("CARGO_TARGET_DIR", out_dir.join("corrosion-target"));

    cmake_cfg.build();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
