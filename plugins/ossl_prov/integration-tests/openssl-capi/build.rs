// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for the OpenSSL C API provider integration tests.
//!
//! Compiles the C++ GoogleTest test binary via CMake. Requires `OPENSSL_DIR`
//! to be set, pointing to an OpenSSL 3.0.3 installation prefix (e.g.
//! `/opt/openssl-3.0.3`). The system OpenSSL is never used.
//!
//! When `OPENSSL_DIR` is not set the cmake build is skipped so that
//! `cargo clippy --all-targets` can check the Rust source without requiring
//! an OpenSSL installation.

fn main() {
    println!("cargo::rerun-if-env-changed=OPENSSL_DIR");

    let openssl_dir = match std::env::var("OPENSSL_DIR") {
        Ok(dir) => dir,
        Err(_) => {
            println!(
                "cargo:warning=OPENSSL_DIR is not set — skipping C++ test build. \
                 Set OPENSSL_DIR to an OpenSSL 3.x installation prefix to build the gtest binary."
            );
            return;
        }
    };

    cmake::Config::new("cpp")
        .define("OPENSSL_ROOT_DIR", &openssl_dir)
        .build();
}
