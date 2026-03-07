// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for the OpenSSL C API provider integration tests.
//!
//! Compiles the C++ GoogleTest test binary via CMake. Requires `OPENSSL_DIR`
//! to be set, pointing to an OpenSSL 3.0.3 installation prefix (e.g.
//! `/opt/openssl-3.0.3`). The system OpenSSL is never used.

fn main() {
    let openssl_dir = std::env::var("OPENSSL_DIR").expect(
        "\n\
         ERROR: OPENSSL_DIR is not set.\n\
         \n\
         Required environment variables for provider-integration-tests-capi:\n\
           OPENSSL_DIR    OpenSSL 3.x installation prefix (required at build time)\n\
                          e.g. export OPENSSL_DIR=/opt/openssl-3.0.3\n\
         \n\
         Optional (have sensible defaults):\n\
           PROVIDER_PATH  Dir containing azihsm_provider.so (default: target/debug)\n\
         \n\
         The system OpenSSL is intentionally not used so that tests link\n\
         against the exact same version the provider was built with.\n",
    );

    cmake::Config::new("cpp")
        .define("OPENSSL_ROOT_DIR", &openssl_dir)
        .build();
}
