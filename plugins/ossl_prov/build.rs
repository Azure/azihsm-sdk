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
    println!("cargo:rerun-if-env-changed=RUSTC_WORKSPACE_WRAPPER");

    // Skip the heavy CMake/Corrosion build when running under `cargo clippy`.
    // Clippy only needs the Rust source to lint, not the linked artifacts.
    // Building the C provider here would compile azihsm_api_native and its
    // full dep tree into a Corrosion-private target dir, doubling the clippy
    // job time on slow runners.
    //
    // Cargo sets RUSTC_WORKSPACE_WRAPPER to clippy-driver when running
    // clippy; we detect that as the only reliable signal.  `cargo check`
    // alone is not detected — there's no clean env-var indicator for it —
    // but the cost there is the same as a real build, so it's an explicit
    // user action (no scheduled CI step uses bare `cargo check`).
    //
    // We still validate CARGO_TARGET_DIR below so misconfigurations get
    // surfaced even in clippy mode.
    let is_clippy = env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|w| w.contains("clippy"))
        .unwrap_or(false);

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
    // Expected path: contains a segment named ossl-abi-<major>-<minor>
    //   - target/ossl-abi-3-0/                       (plain cargo build)
    //   - target/ossl-abi-3-0/llvm-cov-target/       (cargo llvm-cov wraps the dir)
    //
    // The default is set in .cargo/config.toml; override via:
    //   - cargo xtask <cmd> --openssl-version <ver>
    //   - CARGO_TARGET_DIR=target/ossl-abi-<major>-<minor> cargo ...
    let abi_dir = target_dir
        .ancestors()
        .find(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|leaf| leaf.starts_with("ossl-abi-"))
        })
        .unwrap_or_else(|| {
            panic!(
                "azihsm_ossl_provider must be built in an OpenSSL ABI-versioned target dir.\n\
                 Expected path to contain a segment named ossl-abi-<major>-<minor>, got: {}\n\
                 Use `cargo xtask <cmd> --openssl-version <ver>` (recommended), or set \
                 CARGO_TARGET_DIR=target/ossl-abi-<major>-<minor> explicitly.",
                target_dir.display()
            );
        });

    let abi = abi_dir
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|leaf| leaf.strip_prefix("ossl-abi-"))
        .expect("checked above");

    // Validate the format: <major>-<minor> with numeric components.
    let parts: Vec<&str> = abi.split('-').collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()))
    {
        panic!(
            "ABI directory must follow pattern ossl-abi-<major>-<minor> with numeric \
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

    // Derive OPENSSL_DIR from the ABI dir unless explicitly overridden.
    // The xtask installs OpenSSL to <abi_dir>/openssl by convention; this
    // works regardless of whether the build sits directly in abi_dir or
    // inside a sub-tree like llvm-cov-target.
    let openssl_dir = match env::var("OPENSSL_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => abi_dir.join("openssl"),
    };

    // Skip the C/CMake build when running under clippy/check — see comment
    // at top of main().  Clippy still gets accurate CARGO_TARGET_DIR
    // validation above; it just doesn't pay for the linked artifact.
    if is_clippy {
        println!(
            "cargo:warning=skipping CMake build for clippy (ABI {abi}, target {})",
            target_dir.display()
        );
        return;
    }

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
