// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 template generator for AZIHSM.
//!
//! Generates DER TBS (To-Be-Signed) templates for Root CA, Intermediate CA,
//! Leaf certificates, and PKCS#10 CSRs. Output is written as Rust source
//! files to the `azihsm_crypto` `src/x509_builder/` directory.
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
//! cargo run -p azihsm_crypto_x509_builder_gen
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
    eprintln!("azihsm_crypto_x509_builder_gen requires OpenSSL and only runs on Linux.");
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

    // Intermediate CA
    println!("  Generating Intermediate CA template...");
    let inter = cert::build_intermediate_cert();
    let inter_src = code_gen::emit_template_module(
        "Intermediate CA certificate TBS template (auto-generated).",
        &inter.tbs,
        &inter.fields,
    );
    fs::write(out_dir.join("intermediate_cert.rs"), inter_src).expect("write intermediate_cert.rs");
    println!(
        "    TBS size: {} bytes, {} variable fields",
        inter.tbs.len(),
        inter.fields.len()
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

    // Device CSR
    println!("  Generating Device CSR template...");
    let csr = csr::build_device_csr();
    let csr_src = code_gen::emit_template_module(
        "Device CSR (PKCS#10) TBS template (auto-generated).",
        &csr.tbs,
        &csr.fields,
    );
    fs::write(out_dir.join("device_csr.rs"), csr_src).expect("write device_csr.rs");
    println!(
        "    TBS size: {} bytes, {} variable fields",
        csr.tbs.len(),
        csr.fields.len()
    );

    println!("Done! Generated 4 template files.");
}

/// Determine the output directory (the `azihsm_crypto` x509_builder module).
///
/// The generator lives at `crates/crypto/x509_builder/gen/`; templates are
/// written to `crates/crypto/src/x509_builder/`.
#[cfg(target_os = "linux")]
fn output_dir() -> std::path::PathBuf {
    // gen dir -> crates/crypto/x509_builder -> crates/crypto, then src/x509_builder.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("parent dirs")
        .join("src/x509_builder")
}
