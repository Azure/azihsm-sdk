// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Build a specific OpenSSL 3.x release into a workspace-local prefix.
//!
//! This command is a **temporary bridge** for the period where the SDK has
//! to be tested against OpenSSL versions that aren't yet available as the
//! system OpenSSL on any Ubuntu LTS we target (notably 3.5.x).  Once the
//! desired version ships as the container's system OpenSSL, the relevant
//! CI step (and the `OPENSSL_DIR` export that follows it) can be deleted
//! and `host_openssl::check_openssl` will fall through to the well-known
//! prefix scan.
//!
//! Output layout:
//!
//! ```text
//! target/openssl-custom/<version>/
//!     bin/openssl
//!     include/openssl/opensslv.h
//!     lib/libcrypto.so.3
//!     lib/libssl.so.3
//!     ssl/openssl.cnf
//! ```
//!
//! The directory tree is entirely self-contained; nothing is installed
//! into system paths (no `sudo install`, no `ldconfig`).  Callers point
//! `OPENSSL_DIR` at the printed prefix to make `host_openssl` honour it.

use std::path::PathBuf;

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

/// Tarball download URL template (interpolates `{version}` twice).
#[cfg(target_os = "linux")]
const TARBALL_URL_TEMPLATE: &str =
    "https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz";

/// Supported OpenSSL versions and their official tarball SHA-256 hashes.
/// Add new entries here as new versions are needed for CI.
#[cfg(target_os = "linux")]
const SUPPORTED_VERSIONS: &[(&str, &str)] = &[
    (
        "3.0.13",
        "88525753f79d3bec27d2fa7c66aa0b92b3aa9498dafd93d7cfa4b3780cdae313",
    ),
    (
        "3.5.4",
        "967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99",
    ),
];

/// Install a pinned OpenSSL release into `target/openssl-custom/<version>/`.
///
/// Idempotent: if the install directory already contains a matching
/// `opensslv.h`, the command exits without rebuilding.  Use `--force` to
/// rebuild anyway.
///
/// Linux-only.  On other platforms the command is a no-op that logs a
/// skip notice.
#[derive(Parser)]
#[clap(about = "Build a pinned OpenSSL release into target/openssl-custom/<version>")]
pub struct CustomOpenssl {
    /// OpenSSL version to install (e.g., "3.0.13", "3.5.4").  Must be on
    /// the supported-versions allowlist.
    #[clap(long)]
    pub version: String,

    /// Override the install prefix.  Defaults to
    /// `<workspace>/target/openssl-custom/<version>/`.
    #[clap(long)]
    pub prefix: Option<PathBuf>,

    /// Rebuild even if the install directory already exists with a
    /// matching `opensslv.h`.
    #[clap(long)]
    pub force: bool,
}

impl Xtask for CustomOpenssl {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            log::warn!(
                "skipping custom-openssl: only supported on Linux (got {})",
                std::env::consts::OS
            );
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            install(&self.version, self.prefix.as_deref(), self.force, &_ctx)
        }
    }
}

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
                 Supported versions: {}.  Add a new (version, sha256) tuple to \
                 SUPPORTED_VERSIONS in xtask/src/custom_openssl.rs.",
                supported.join(", ")
            )
        })
}

#[cfg(target_os = "linux")]
fn default_prefix(version: &str, ctx: &XtaskCtx) -> PathBuf {
    ctx.root.join("target").join("openssl-custom").join(version)
}

/// Returns true when the install dir already contains an `opensslv.h`
/// whose `OPENSSL_VERSION_STR` matches `expected_version` (e.g., `"3.5.4"`).
/// Used to skip the build under `actions/cache` hits where the cache
/// restoration leaves a complete prefix on disk.
#[cfg(target_os = "linux")]
fn already_installed(prefix: &std::path::Path, expected_version: &str) -> bool {
    let header = prefix.join("include/openssl/opensslv.h");
    let Ok(contents) = std::fs::read_to_string(&header) else {
        return false;
    };
    // Looking for: `# define OPENSSL_VERSION_STR "3.5.4"`
    for line in contents.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("OPENSSL_VERSION_STR") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        return &rest[..end] == expected_version;
    }
    false
}

#[cfg(target_os = "linux")]
fn install(
    version: &str,
    prefix_override: Option<&std::path::Path>,
    force: bool,
    ctx: &XtaskCtx,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use xshell::cmd;
    use xshell::Shell;

    let expected_hash = sha256_for(version)?;

    let install_dir = match prefix_override {
        Some(p) => p.to_path_buf(),
        None => default_prefix(version, ctx),
    };

    if !force && already_installed(&install_dir, version) {
        log::info!(
            "OpenSSL {version} already installed at {} (skipping build)",
            install_dir.display(),
        );
        // Still print the path so callers always have a stable contract.
        println!("{}", install_dir.display());
        return Ok(());
    }

    let prefix = install_dir.display();
    log::info!("building OpenSSL {version} into {prefix}");

    // Preflight: check required tools before starting a long build.
    let sh = Shell::new()?;
    for tool in ["curl", "sha256sum", "tar", "make", "cc", "perl"] {
        if cmd!(sh, "which {tool}").quiet().run().is_err() {
            anyhow::bail!(
                "required tool `{tool}` not found.  Install build prerequisites: \
                 sudo apt-get install build-essential coreutils curl perl tar"
            );
        }
    }

    let url = TARBALL_URL_TEMPLATE.replace("{version}", version);
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

    // Wipe any partial previous install to avoid mixed-version state.
    if install_dir.exists() {
        std::fs::remove_dir_all(&install_dir)
            .with_context(|| format!("failed to remove existing {}", install_dir.display()))?;
    }
    if let Some(parent) = install_dir.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create install parent {}", parent.display()))?;
    }

    sh.change_dir(&src_dir);
    cmd!(sh, "./Configure --prefix={install_dir} --libdir=lib").run()?;

    let nproc = cmd!(sh, "nproc").read()?;
    let nproc = nproc.trim();
    cmd!(sh, "make -j{nproc}").run()?;
    cmd!(sh, "make install_sw").run()?;

    log::info!("OpenSSL {version} installed to {prefix}");
    // Print the absolute install path on the last stdout line so scripted
    // callers (CI workflows, makefiles) can capture it without parsing logs.
    println!("{}", install_dir.display());
    Ok(())
}
