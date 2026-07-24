// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate a masked EC P-384 key blob for the engine integration tests.
//!
//! Opens the mock HSM from the ambient `AZIHSM_*` environment — the same
//! environment the engine-loading `openssl` process uses — generates a
//! persistent EC key, and writes its masked blob to the path given as the first
//! argument. Because both processes share the resiliency storage dir (the
//! persisted BMK), the OBK, and the POTA keypair, the engine can later unmask
//! this blob via `ENGINE_load_private_key`.

#[cfg(feature = "integration")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let out = std::env::args()
        .nth(1)
        .ok_or("usage: masked-keygen <output-blob-path>")?;
    let blob = azihsm_ossl_engine::generate_masked_ec_p384_from_env()?;
    // Owner-only: the blob is key material.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&out)?;
    f.write_all(&blob)?;
    Ok(())
}

#[cfg(not(feature = "integration"))]
fn main() {
    eprintln!("masked-keygen must be built with --features integration");
    std::process::exit(2);
}
