// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration tests for the OpenSSL 1.1.x engine, driven by `lit`.
//!
//! Each `.sh` script loads a key through the real `ENGINE_load_private_key`
//! path — `openssl … -engine azihsm -inform engine -in azihsm://…` — the load
//! path the in-crate unit tests (which call `keyload::load_key` directly)
//! bypass, and drives crypto through the loaded key (e.g. `dgst -sign`).
//!
//! Requires (set by `xtask integration-tests` / the engine matrix):
//! - `OPENSSL_BIN`     — the OpenSSL 1.1.x `openssl` binary
//! - `ENGINE_SO`       — path to `libazihsm_ossl_engine.so`
//! - `MASKED_KEYGEN`   — path to the `masked-keygen` helper that stages a blob
//!
//! `testfiles/env.sh` provisions the shared keymat + `openssl.cnf` each script
//! sources.

#![cfg(feature = "integration")]

use std::path::PathBuf;

use serial_test::serial;

/// Absolute path to a `testfiles` subdir, anchored at the crate manifest dir so
/// it is independent of the process working directory.
fn search_path(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    path.to_str().expect("path is not valid UTF-8").to_owned()
}

/// Run one testfiles suite with its own keymat directory.
///
/// Each test gets `<base>/<name>` (base = `AZIHSM_ENGINE_TEST_KEYDIR` or the
/// env.sh default): `#[serial]` serializes only within a process, and nextest
/// runs every test in its own process, so suites sharing one keydir race
/// env.sh's keymat creation (torn OBK/POTA files, seen as ASN1 parse errors).
/// Per-test dirs remove the shared state entirely — each openssl process
/// re-initializes the mock from its own dir's persisted MOBK.
///
/// The directory reaches the scripts as their first positional argument (the
/// `@keydir` constant in the RUN lines, preferred by env.sh over the plain
/// env var) — never by mutating this process's environment, which would be
/// unsound with any concurrent env reader.
fn run_cli_suite(name: &str, testfiles: &str) {
    let base = std::env::var("AZIHSM_ENGINE_TEST_KEYDIR").unwrap_or_else(|_| {
        let cwd = std::env::current_dir().expect("cwd");
        format!("{}/target/test-keymat/engine-cli", cwd.display())
    });
    let keydir = format!("{base}/{name}");

    lit::run::tests(lit::event_handler::Default::default(), |config| {
        config.add_search_path(search_path(testfiles));
        config.add_extension("sh");
        config
            .constants
            .insert("bash".to_owned(), "/bin/bash".to_string());
        config.constants.insert("keydir".to_owned(), keydir.clone());
    })
    .expect("lit CLI test failed");
}

#[test]
#[serial]
fn load_ec_key_via_engine() {
    run_cli_suite("load", "testfiles/load");
}

#[test]
#[serial]
fn create_ec_key_via_engine() {
    run_cli_suite("create_key", "testfiles/create_key");
}

#[test]
#[serial]
fn sign_ec_key_via_engine() {
    run_cli_suite("sign", "testfiles/sign");
}

#[test]
#[serial]
fn derive_ec_key_via_engine() {
    run_cli_suite("derive", "testfiles/derive");
}
