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

#[cfg(target_os = "linux")]
const OPENSSL_VERSION: &str = "3.0.3";
#[cfg(target_os = "linux")]
const OPENSSL_SHA256: &str = "ee0078adcef1de5f003c62c80cc96527721609c6f3bb42b7795df31f8b558c0b";

#[cfg(target_os = "linux")]
fn default_install_dir() -> anyhow::Result<PathBuf> {
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir()?.join("target"),
    };
    Ok(target_dir.join(format!("openssl-{OPENSSL_VERSION}")))
}

/// Checks whether an OpenSSL installation is available, without installing.
#[cfg(target_os = "linux")]
pub fn check_openssl() -> anyhow::Result<PathBuf> {
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

    let install_dir = default_install_dir()?;
    if install_dir.is_dir() {
        log::info!("using cached OpenSSL at {}", install_dir.display());
        return Ok(install_dir);
    }

    anyhow::bail!(
        "OpenSSL installation not found. \
         Run 'cargo xtask setup' first, or set OPENSSL_DIR to an existing OpenSSL 3.x prefix."
    );
}

/// Resolves an OpenSSL installation, building from source if necessary.
#[cfg(target_os = "linux")]
pub fn ensure_openssl() -> anyhow::Result<PathBuf> {
    // If OPENSSL_DIR is explicitly set, honour it strictly (never fall through to build).
    if std::env::var("OPENSSL_DIR").is_ok() {
        return check_openssl();
    }

    if let Ok(path) = check_openssl() {
        return Ok(path);
    }

    let install_dir = default_install_dir()?;
    let prefix = install_dir.display();

    // Download and build (mirrors CI exactly)
    log::info!("OPENSSL_DIR not set — building OpenSSL {OPENSSL_VERSION} into {prefix}");

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
        "https://github.com/openssl/openssl/releases/download/openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz"
    );
    let tarball = format!("/tmp/openssl-{OPENSSL_VERSION}.tar.gz");
    let src_dir = format!("/tmp/openssl-{OPENSSL_VERSION}");

    log::info!("downloading OpenSSL {OPENSSL_VERSION}...");
    cmd!(sh, "curl -fsSL -o {tarball} {url}").run()?;

    let checksum_output = cmd!(sh, "sha256sum {tarball}").read()?;
    let actual_hash = checksum_output
        .split_whitespace()
        .next()
        .context("failed to parse sha256sum output")?;
    anyhow::ensure!(
        actual_hash == OPENSSL_SHA256,
        "SHA-256 mismatch for {tarball}: expected {OPENSSL_SHA256}, got {actual_hash}"
    );

    cmd!(sh, "rm -rf {src_dir}").run()?;
    cmd!(sh, "tar xz -C /tmp -f {tarball}").run()?;

    sh.change_dir(&src_dir);
    cmd!(sh, "./Configure --prefix={install_dir} --libdir=lib").run()?;

    let nproc = cmd!(sh, "nproc").read()?;
    let nproc = nproc.trim();
    cmd!(sh, "make -j{nproc}").run()?;
    cmd!(sh, "make install_sw").run()?;

    log::info!("OpenSSL {OPENSSL_VERSION} installed to {prefix}");
    Ok(install_dir)
}
