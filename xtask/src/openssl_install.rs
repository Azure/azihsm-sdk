// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Helper to resolve an OpenSSL installation, building one if necessary.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
#[cfg(target_os = "linux")]
use xshell::cmd;
#[cfg(target_os = "linux")]
use xshell::Shell;

/// Supported OpenSSL versions and their tarball SHA-256 hashes. The version
/// string is interpolated into paths and download URLs, so we restrict to
/// known-good values.
#[cfg(target_os = "linux")]
const SUPPORTED_VERSIONS: &[(&str, &str)] = &[
    (
        "3.0.3",
        "ee0078adcef1de5f003c62c80cc96527721609c6f3bb42b7795df31f8b558c0b",
    ),
    (
        "3.5.0",
        "344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0",
    ),
];

/// Returns the expected SHA-256 hash for a supported version, or an error
/// if the version is not in the allowlist.
#[cfg(target_os = "linux")]
fn sha256_for(version: &str) -> anyhow::Result<&'static str> {
    SUPPORTED_VERSIONS
        .iter()
        .find(|(v, _)| *v == version)
        .map(|(_, hash)| *hash)
        .ok_or_else(|| {
            let supported: Vec<&str> = SUPPORTED_VERSIONS.iter().map(|(v, _)| *v).collect();
            anyhow::anyhow!(
                "unsupported OpenSSL version {version:?}. \
                 Supported versions: {}. \
                 Set OPENSSL_DIR to use a custom installation.",
                supported.join(", ")
            )
        })
}

/// Returns the default install directory for a given version, rooted in the
/// Cargo target directory (or `./target` when `CARGO_TARGET_DIR` is unset).
#[cfg(target_os = "linux")]
fn default_install_dir(version: &str) -> anyhow::Result<PathBuf> {
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir()?.join("target"),
    };
    Ok(target_dir.join(format!("openssl-{version}")))
}

/// Checks whether an OpenSSL installation is available, without installing.
///
/// Resolution order:
/// 1. `OPENSSL_DIR` env var — if set, returned as-is.
/// 2. `target/openssl-{version}` — if it already exists.
///
/// Returns an error if neither is available. The caller must then run
/// `ensure_openssl_version` (or `cargo xtask setup`) to install.
#[cfg(target_os = "linux")]
pub fn check_openssl(version: &str) -> anyhow::Result<PathBuf> {
    match std::env::var("OPENSSL_DIR") {
        Ok(val) if val.trim().is_empty() => {
            anyhow::bail!(
                "OPENSSL_DIR is set but empty. \
                 Set it to an OpenSSL 3.x installation prefix."
            );
        }
        Ok(ref val) if !std::path::Path::new(val).is_dir() => {
            anyhow::bail!("OPENSSL_DIR={val:?} does not point to an existing directory.");
        }
        Ok(val) => {
            log::info!("using OPENSSL_DIR={val}");
            return Ok(PathBuf::from(val));
        }
        Err(_) => {}
    }

    let install_dir = default_install_dir(version)?;
    if install_dir.is_dir() {
        log::info!("using cached OpenSSL at {}", install_dir.display());
        return Ok(install_dir);
    }

    anyhow::bail!(
        "OpenSSL installation not found at {}. \
         Run 'cargo xtask setup' first, or set OPENSSL_DIR to an existing OpenSSL 3.x prefix.",
        install_dir.display()
    );
}

/// Resolves an OpenSSL installation, building from source if necessary.
///
/// Honours `OPENSSL_DIR` strictly when set. Otherwise installs to
/// `target/openssl-{version}` if not already present.
#[cfg(target_os = "linux")]
pub fn ensure_openssl_version(version: &str) -> anyhow::Result<PathBuf> {
    let expected_hash = sha256_for(version)?;

    // If OPENSSL_DIR is explicitly set, honour it strictly (never fall through to build).
    if std::env::var("OPENSSL_DIR").is_ok() {
        return check_openssl(version);
    }

    if let Ok(path) = check_openssl(version) {
        return Ok(path);
    }

    let install_dir = default_install_dir(version)?;
    let prefix = install_dir.display();

    log::info!("OPENSSL_DIR not set — building OpenSSL {version} into {prefix}");

    // Preflight: check required tools before starting a long build.
    let sh = Shell::new()?;
    for tool in ["curl", "sha256sum", "make", "cc", "perl"] {
        if cmd!(sh, "which {tool}").quiet().run().is_err() {
            anyhow::bail!(
                "required tool `{tool}` not found. \
                 Install build prerequisites: sudo apt-get install build-essential coreutils curl perl"
            );
        }
    }

    let url = format!(
        "https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz"
    );
    let tarball = format!("/tmp/openssl-{version}.tar.gz");
    let src_dir = format!("/tmp/openssl-{version}");

    log::info!("downloading OpenSSL {version}...");
    cmd!(sh, "curl -fsSL -o {tarball} {url}").run()?;

    let checksum_output = cmd!(sh, "sha256sum {tarball}").read()?;
    let actual_hash = checksum_output
        .split_whitespace()
        .next()
        .context("failed to parse sha256sum output")?;
    anyhow::ensure!(
        actual_hash == expected_hash,
        "SHA-256 mismatch for {tarball}: expected {expected_hash}, got {actual_hash}"
    );

    cmd!(sh, "rm -rf {src_dir}").run()?;
    cmd!(sh, "tar xz -C /tmp -f {tarball}").run()?;

    sh.change_dir(&src_dir);
    cmd!(sh, "./Configure --prefix={install_dir} --libdir=lib").run()?;

    let nproc = cmd!(sh, "nproc").read()?;
    let nproc = nproc.trim();
    cmd!(sh, "make -j{nproc}").run()?;
    cmd!(sh, "make install_sw").run()?;

    log::info!("OpenSSL {version} installed to {prefix}");
    Ok(install_dir)
}
