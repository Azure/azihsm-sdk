// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Discover the host's OpenSSL 3.x installation prefix for use by the
//! OpenSSL provider integration tests.
//!
//! The previous flow downloaded and built OpenSSL 3.0.3 into
//! `target/openssl-3.0.3/`. That was reproducible but slow, version-stale,
//! and forced every consumer to set `LD_LIBRARY_PATH` to the bundled libs.
//! The provider source has only one OpenSSL-3.0-specific code path
//! (a polyfill gated by `#if OPENSSL_VERSION_MINOR == 0`); everything else
//! is ABI-stable across the OpenSSL 3.x line, so a host install works.
//!
//! Resolution order:
//!
//! 1. `OPENSSL_DIR` env var, if set and pointing at an existing directory.
//! 2. `pkg-config --variable=prefix openssl`, when `pkg-config` is on PATH.
//! 3. A small set of well-known distro prefixes (`/usr`, `/usr/local`,
//!    `/opt/homebrew`).
//!
//! All resolution steps verify that `openssl/opensslv.h` exists under
//! `<prefix>/include` before returning success, so that downstream callers
//! never see a phantom prefix that can't actually be linked against.

#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
const WELL_KNOWN_PREFIXES: &[&str] = &["/usr", "/usr/local", "/opt/homebrew"];

/// Returns `true` if `<prefix>/include/openssl/opensslv.h` exists.
#[cfg(target_os = "linux")]
fn has_openssl_headers(prefix: &Path) -> bool {
    prefix.join("include/openssl/opensslv.h").is_file()
}

/// Returns the OpenSSL prefix exposed by `pkg-config --variable=prefix openssl`,
/// if `pkg-config` is available and the openssl package is registered.
#[cfg(target_os = "linux")]
fn pkg_config_prefix() -> Option<PathBuf> {
    let output = Command::new("pkg-config")
        .args(["--variable=prefix", "openssl"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if prefix.is_empty() {
        return None;
    }
    let path = PathBuf::from(prefix);
    has_openssl_headers(&path).then_some(path)
}

/// Discovers the host's OpenSSL 3.x installation prefix.
///
/// Honours `OPENSSL_DIR` if set; otherwise falls back to `pkg-config` and
/// a handful of well-known distro prefixes. Returns an error with concrete
/// remediation guidance if nothing is found.
#[cfg(target_os = "linux")]
pub fn check_openssl() -> anyhow::Result<PathBuf> {
    if let Ok(val) = std::env::var("OPENSSL_DIR") {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "OPENSSL_DIR is set but empty. \
                 Either unset it (to use host OpenSSL) or point it at an OpenSSL 3.x prefix."
            );
        }
        let path = PathBuf::from(trimmed);
        if !path.is_dir() {
            anyhow::bail!("OPENSSL_DIR={trimmed:?} does not point to an existing directory.");
        }
        if !has_openssl_headers(&path) {
            anyhow::bail!(
                "OPENSSL_DIR={trimmed:?} does not contain include/openssl/opensslv.h. \
                 Point it at an OpenSSL 3.x install prefix (e.g. /usr or /usr/local)."
            );
        }
        log::info!("using OPENSSL_DIR={trimmed}");
        return Ok(path);
    }

    if let Some(prefix) = pkg_config_prefix() {
        log::info!("using OpenSSL from pkg-config at {}", prefix.display());
        return Ok(prefix);
    }

    for candidate in WELL_KNOWN_PREFIXES {
        let path = PathBuf::from(candidate);
        if has_openssl_headers(&path) {
            log::info!("using OpenSSL from {candidate}");
            return Ok(path);
        }
    }

    anyhow::bail!(
        "No OpenSSL 3.x installation found. Either:\n  \
           - set OPENSSL_DIR to a prefix containing include/openssl/opensslv.h, or\n  \
           - install your distro's OpenSSL development package (e.g. `apt install libssl-dev` \
             or `dnf install openssl-devel`).\n\
         The azihsm OpenSSL provider supports any OpenSSL 3.x version."
    );
}
