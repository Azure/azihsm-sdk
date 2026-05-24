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

/// Parse `OPENSSL_VERSION_MAJOR` from `<prefix>/include/openssl/opensslv.h`,
/// if the file is present and the macro can be read.
#[cfg(target_os = "linux")]
fn openssl_version_major(prefix: &Path) -> Option<u32> {
    let header = prefix.join("include/openssl/opensslv.h");
    let contents = std::fs::read_to_string(&header).ok()?;
    for line in contents.lines() {
        // Looking for: `# define OPENSSL_VERSION_MAJOR  3`
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("define") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix("OPENSSL_VERSION_MAJOR") else {
            continue;
        };
        // Must be followed by whitespace (so we don't match
        // OPENSSL_VERSION_MAJORXYZ) and then the integer literal.
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        return rest.split_whitespace().next()?.parse::<u32>().ok();
    }
    None
}

/// Validate that the prefix points at an OpenSSL 3.x install: headers must
/// be present, and `OPENSSL_VERSION_MAJOR` must be at least 3. Returns an
/// error with concrete remediation guidance otherwise.
#[cfg(target_os = "linux")]
fn validate_prefix(prefix: &Path) -> anyhow::Result<()> {
    if !has_openssl_headers(prefix) {
        anyhow::bail!(
            "{:?} does not contain include/openssl/opensslv.h",
            prefix.display()
        );
    }
    match openssl_version_major(prefix) {
        Some(major) if major >= 3 => Ok(()),
        Some(major) => anyhow::bail!(
            "OpenSSL at {} is version {major}.x; the azihsm OpenSSL provider \
             requires OpenSSL 3.x. Install a 3.x development package or \
             point OPENSSL_DIR at a 3.x prefix.",
            prefix.display(),
        ),
        None => anyhow::bail!(
            "could not parse OPENSSL_VERSION_MAJOR from {}/include/openssl/opensslv.h",
            prefix.display(),
        ),
    }
}

/// Returns the OpenSSL prefix exposed by `pkg-config --variable=prefix openssl`,
/// if `pkg-config` is available and the resolved prefix is OpenSSL 3.x.
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
    validate_prefix(&path).ok().map(|_| path)
}

/// Discovers the host's OpenSSL 3.x installation prefix.
///
/// Honours `OPENSSL_DIR` if set; otherwise falls back to `pkg-config` and
/// a handful of well-known distro prefixes. Each candidate is validated
/// to contain OpenSSL ≥ 3.0 headers; 1.x installs (or any non-3.x
/// `opensslv.h`) are rejected with a clear error message. Returns an
/// error with concrete remediation guidance if nothing is found.
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
        validate_prefix(&path)?;
        log::info!("using OPENSSL_DIR={trimmed}");
        return Ok(path);
    }

    if let Some(prefix) = pkg_config_prefix() {
        log::info!("using OpenSSL from pkg-config at {}", prefix.display());
        return Ok(prefix);
    }

    for candidate in WELL_KNOWN_PREFIXES {
        let path = PathBuf::from(candidate);
        if validate_prefix(&path).is_ok() {
            log::info!("using OpenSSL from {candidate}");
            return Ok(path);
        }
    }

    anyhow::bail!(
        "No OpenSSL 3.x installation found. Either:\n  \
           - set OPENSSL_DIR to a prefix containing include/openssl/opensslv.h \
             with OPENSSL_VERSION_MAJOR >= 3, or\n  \
           - install your distro's OpenSSL 3.x development package (e.g. \
             `apt install libssl-dev` or `dnf install openssl-devel`).\n\
         The azihsm OpenSSL provider supports any OpenSSL 3.x version."
    );
}
