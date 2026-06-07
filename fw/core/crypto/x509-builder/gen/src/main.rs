// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 template generator for AZIHSM.
//!
//! Generates DER TBS (To-Be-Signed) templates for Root CA and Leaf
//! certificates, and a PKCS#10 CSR. Output is written as Rust source
//! files to the runtime crate's `src/` directory (`root_cert.rs`,
//! `leaf_cert.rs`, `csr.rs`). An intermediate CA is constructed
//! internally only to act as the leaf's issuer; no `intermediate_cert.rs`
//! is emitted.
//!
//! # How It Works
//!
//! 1. For each certificate type, OpenSSL creates a valid certificate with
//!    known "needle" byte patterns for every variable field.
//! 2. The DER encoding is parsed to extract just the TBS portion.
//! 3. Needle patterns are located by byte search to determine field offsets.
//! 4. Needle bytes are replaced with placeholder byte `0x5F`.
//! 5. A Rust source file is emitted with the sanitized template as a
//!    `const [u8; N]` and named offset/length constants.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p azihsm_fw_core_crypto_x509_builder_gen
//! ```
//!
//! This tool requires OpenSSL and **only builds on Linux**.

#[cfg(target_os = "linux")]
mod cert;
#[cfg(target_os = "linux")]
mod code_gen;
#[cfg(target_os = "linux")]
mod csr;
#[cfg(target_os = "linux")]
mod tbs;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("azihsm_fw_core_crypto_x509_builder_gen requires OpenSSL and only runs on Linux.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use std::fs;

    let out_dir = output_dir();
    fs::create_dir_all(&out_dir).expect("create output directory");

    println!("Generating X509 templates to {}", out_dir.display());

    // Root CA
    println!("  Generating Root CA template...");
    let root = cert::build_root_cert();
    let root_src = code_gen::emit_template_module(
        "Root CA certificate TBS template (auto-generated).",
        &root.tbs,
        &root.fields,
    );
    fs::write(out_dir.join("root_cert.rs"), root_src).expect("write root_cert.rs");
    println!(
        "    TBS size: {} bytes, {} variable fields",
        root.tbs.len(),
        root.fields.len()
    );

    // Leaf
    println!("  Generating Leaf certificate template...");
    let leaf = cert::build_leaf_cert();
    let leaf_src = code_gen::emit_template_module(
        "Leaf certificate TBS template (auto-generated).",
        &leaf.tbs,
        &leaf.fields,
    );
    fs::write(out_dir.join("leaf_cert.rs"), leaf_src).expect("write leaf_cert.rs");
    println!(
        "    TBS size: {} bytes, {} variable fields",
        leaf.tbs.len(),
        leaf.fields.len()
    );

    // CSR (PKCS#10) — used for the Partition Trust Anchor today.
    println!("  Generating CSR template...");
    let pta = csr::build_csr();
    let pta_src = code_gen::emit_template_module(
        "CSR (PKCS#10) TBS template (auto-generated).",
        &pta.tbs,
        &pta.fields,
    );
    fs::write(out_dir.join("csr.rs"), pta_src).expect("write csr.rs");
    println!(
        "    TBS size: {} bytes, {} variable fields",
        pta.tbs.len(),
        pta.fields.len()
    );

    println!("Done! Generated 3 template files.");
}

/// Determine the output directory (runtime crate's `src/` directory).
///
/// The generator lives at `fw/core/crypto/x509-builder/gen/`; templates
/// are written to `fw/core/crypto/x509-builder/src/`.
#[cfg(target_os = "linux")]
fn output_dir() -> std::path::PathBuf {
    // The generator is at fw/core/crypto/x509-builder/gen/
    // Output goes to fw/core/crypto/x509-builder/src/
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::PathBuf::from(manifest_dir)
        .parent()
        .expect("parent dir")
        .join("src")
}
