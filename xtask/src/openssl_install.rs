// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Helper to resolve an OpenSSL installation, building one if necessary.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use xshell::cmd;
#[cfg(target_os = "linux")]
use xshell::Shell;

#[cfg(target_os = "linux")]
const OPENSSL_VERSION: &str = "3.0.3";

#[cfg(target_os = "linux")]
const OPENSSL_INSTALL_DIR: &str = "/opt/openssl-3.0.3";

/// Resolves an OpenSSL installation, building one if necessary.
///
/// Resolution order:
/// 1. `OPENSSL_DIR` env var — if set, checked (must be an existing directory),
///    and returned as-is. No deep validation of contents is performed; downstream
///    build scripts and test harnesses will report specific missing-file errors.
/// 2. `/opt/openssl-3.0.3` — if it already exists (local equivalent of the CI cache).
/// 3. Download, build, and install OpenSSL 3.0.3 to `/opt/openssl-3.0.3`,
///    using the same commands as CI. Requires `curl`, `make`, a C compiler,
///    and `sudo` (system path). The installation persists across `cargo clean`
///    and `cargo xtask clean`.
///
/// Only supported on Linux; returns an error on other platforms.
#[cfg(not(target_os = "linux"))]
pub fn ensure_openssl() -> anyhow::Result<PathBuf> {
    anyhow::bail!("OpenSSL auto-install is only supported on Linux");
}

/// Resolves an OpenSSL installation, building one if necessary.
///
/// Resolution order:
/// 1. `OPENSSL_DIR` env var — if set, checked (must be an existing directory),
///    and returned as-is. No deep validation of contents is performed; downstream
///    build scripts and test harnesses will report specific missing-file errors.
/// 2. `/opt/openssl-3.0.3` — if it already exists (local equivalent of the CI cache).
/// 3. Download, build, and install OpenSSL 3.0.3 to `/opt/openssl-3.0.3`,
///    using the same commands as CI. Requires `curl`, `make`, a C compiler,
///    and `sudo` (system path). The installation persists across `cargo clean`
///    and `cargo xtask clean`.
#[cfg(target_os = "linux")]
pub fn ensure_openssl() -> anyhow::Result<PathBuf> {
    // 1. Honour explicit OPENSSL_DIR
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

    let install_dir = PathBuf::from(OPENSSL_INSTALL_DIR);

    // 2. Local cache: already installed to /opt
    if install_dir.is_dir() {
        log::info!("using cached OpenSSL at {OPENSSL_INSTALL_DIR}");
        return Ok(install_dir);
    }

    // 3. Download and build (mirrors CI exactly)
    log::info!(
        "OPENSSL_DIR not set — building OpenSSL {OPENSSL_VERSION} into {OPENSSL_INSTALL_DIR}"
    );

    // Preflight: check required tools before starting a long build.
    let sh = Shell::new()?;
    for tool in ["curl", "make", "cc"] {
        if cmd!(sh, "which {tool}").quiet().run().is_err() {
            anyhow::bail!(
                "required tool `{tool}` not found. \
                 Install build prerequisites: sudo apt-get install build-essential curl"
            );
        }
    }
    if cmd!(sh, "sudo -n true").quiet().run().is_err() {
        anyhow::bail!(
            "sudo access required to install OpenSSL into {OPENSSL_INSTALL_DIR}. \
             Either run with sudo or set OPENSSL_DIR to a user-writable installation."
        );
    }

    let url = format!(
        "https://github.com/openssl/openssl/releases/download/openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz"
    );
    let tarball = format!("/tmp/openssl-{OPENSSL_VERSION}.tar.gz");
    let src_dir = format!("/tmp/openssl-{OPENSSL_VERSION}");

    log::info!("downloading OpenSSL {OPENSSL_VERSION}...");
    cmd!(sh, "curl -fsSL -o {tarball} {url}").run()?;
    cmd!(sh, "tar xz -C /tmp -f {tarball}").run()?;

    sh.change_dir(&src_dir);
    cmd!(
        sh,
        "./Configure --prefix={OPENSSL_INSTALL_DIR} --libdir=lib"
    )
    .run()?;

    let nproc = cmd!(sh, "nproc").read()?;
    let nproc = nproc.trim();
    cmd!(sh, "make -j{nproc}").run()?;
    cmd!(sh, "sudo make install_sw").run()?;

    log::info!("OpenSSL {OPENSSL_VERSION} installed to {OPENSSL_INSTALL_DIR}");
    Ok(install_dir)
}
