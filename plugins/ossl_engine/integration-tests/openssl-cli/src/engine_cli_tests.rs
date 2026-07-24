// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration tests for the OpenSSL 1.1.x engine, driven by `lit`.
//!
//! Each `.sh` script loads a key through the real `ENGINE_load_private_key`
//! path — `openssl … -engine azihsm -inform engine -in azihsm://…` — against a
//! dynamically loaded engine `.so`, exercising callback registration, the C
//! trampoline, engine ex_data lookup, and ownership transfer that the in-crate
//! unit tests (which call `keyload::load_key` directly) bypass.
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

// Serial: the scripts share the process-global mock HSM state and a keymat dir.
#[test]
#[serial]
fn load_ec_key_via_engine() {
    lit::run::tests(lit::event_handler::Default::default(), |config| {
        config.add_search_path(search_path("testfiles/load"));
        config.add_extension("sh");
        config
            .constants
            .insert("bash".to_owned(), "/bin/bash".to_string());
    })
    .expect("lit CLI test failed");
}
