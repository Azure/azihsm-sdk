// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for the OpenSSL C API provider integration tests.
//!
//! Compiles the C++ GoogleTest test binary via CMake only when the
//! `integration` feature is active. This avoids downloading/building
//! googletest during normal `cargo build` or `cargo clippy` workspace runs.
//!
//! When `integration` is enabled, `OPENSSL_DIR` must point to an OpenSSL 3.x
//! installation prefix (e.g. `/opt/openssl-3.0.3`).

fn main() {
    println!("cargo::rerun-if-env-changed=OPENSSL_DIR");

    if std::env::var("CARGO_FEATURE_INTEGRATION").is_err() {
        return;
    }

    let openssl_dir = std::env::var("OPENSSL_DIR").unwrap_or_else(|_| {
        panic!(
            "OPENSSL_DIR must be set when building with the `integration` feature. \
             Point it to your OpenSSL 3.x install prefix."
        );
    });

    cmake::Config::new("cpp")
        .define("OPENSSL_ROOT_DIR", &openssl_dir)
        .build();
}
