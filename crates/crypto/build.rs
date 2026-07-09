// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Emits `cfg(ossl300)` when building against OpenSSL 3.0+ so the crate can
//! select 3.x-only backends or OpenSSL 1.1.x-compatible code. `openssl-sys` is
//! a direct dependency declaring `links = "openssl"`, so cargo exposes the
//! detected version here as `DEP_OPENSSL_VERSION_NUMBER` (hex `MNNFFPPS`).

/// OpenSSL 3.0.0 as the packed `DEP_OPENSSL_VERSION_NUMBER` value.
const OPENSSL_3_0_0: u64 = 0x3000_0000;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ossl300)");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");
    if let Ok(v) = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
        && let Ok(n) = u64::from_str_radix(&v, 16)
        && n >= OPENSSL_3_0_0
    {
        println!("cargo::rustc-cfg=ossl300");
    }
}
