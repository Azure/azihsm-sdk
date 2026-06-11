// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PTA CSR (PKCS#10) template builder using OpenSSL.
//!
//! Builds a valid PKCS#10 CertificationRequest with the fixed PTA
//! subject Common Name (`"Azure Integrated HSM PTA"`), a 32-character
//! hex placeholder for the PTAID-derived serialNumber, and a P-384
//! public key needle. The TBS portion is extracted, needle-matched,
//! and sanitized to produce a reusable template that the runtime
//! [`build_csr`](crate::csr_builder::build_csr) function patches.

use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509Name;
use openssl::x509::X509ReqBuilder;

use crate::tbs::FieldOffset;
use crate::tbs::{self};

/// Result of building a CSR template.
pub struct CsrTemplateResult {
    /// Sanitized TBS bytes with placeholder (`0x5F`) at variable positions.
    pub tbs: Vec<u8>,
    /// Variable field descriptors for code generation.
    pub fields: Vec<FieldOffset>,
}

/// Length of uncompressed P-384 public key point (`0x04 || x[48] || y[48]`).
const P384_PUBKEY_LEN: usize = 97;

/// Length of the CSR subject Common Name field in bytes
/// (space-padded ASCII).  Matches
/// `azihsm_fw_core_crypto_x509_builder::csr::SUBJECT_CN_LEN`.
const PTA_CN_LEN: usize = 32;

/// Length of the CSR subject serialNumber field in bytes
/// (32 ASCII hex chars for the truncated PTAID).  Matches
/// `azihsm_fw_core_crypto_x509_builder::csr::SUBJECT_SN_LEN`.
const PTA_SN_LEN: usize = 32;

/// Fixed PTA subject Common Name.  Encoded as a 32-byte field, with
/// trailing spaces patched in by the runtime padding helper.  Kept
/// here to seed a CN needle of the same byte length so OpenSSL emits
/// a TBS we can patch without re-encoding the DN length.
fn subject_cn_needle() -> String {
    // 32 chars: "Azure Integrated HSM PTA" (24) + 8 spaces.
    "Azure Integrated HSM PTA        ".to_string()
}

/// Needle string for the PTA subject serialNumber — a unique 32-char
/// hex pattern embedded in the CSR's subject DN, then located in the
/// DER to determine the SN field offset.
fn subject_sn_needle() -> String {
    "F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFF0".to_string()
}

/// Build the PTA CSR template.
///
/// Generates a valid PKCS#10 CSR with the PTA subject DN
/// (CN = `"Azure Integrated HSM PTA"`, serialNumber = 32-hex-char
/// needle) using OpenSSL, extracts the CertificationRequestInfo
/// (TBS), locates variable fields by needle matching, and sanitizes
/// the template.
///
/// # Returns
/// A [`CsrTemplateResult`] containing the sanitized TBS and field
/// offsets, ready to be emitted as a Rust source file by
/// [`crate::code_gen::emit_template_module`].
pub fn build_csr() -> CsrTemplateResult {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("P-384 curve");
    let ec_key = EcKey::generate(&group).expect("generate EC key");
    let pubkey_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().expect("bn ctx"),
        )
        .expect("pubkey to bytes");
    assert_eq!(pubkey_bytes.len(), P384_PUBKEY_LEN);
    let pkey = PKey::from_ec_key(ec_key).expect("PKey from EC");

    let subject_cn = subject_cn_needle();
    let subject_sn = subject_sn_needle();
    let mut name_builder = X509Name::builder().expect("name builder");
    name_builder
        .append_entry_by_text("CN", &subject_cn)
        .expect("CN");
    name_builder
        .append_entry_by_text("serialNumber", &subject_sn)
        .expect("serialNumber");
    let subject = name_builder.build();

    let mut builder = X509ReqBuilder::new().expect("X509ReqBuilder");
    builder.set_version(0).expect("set version"); // v1
    builder.set_subject_name(&subject).expect("set subject");
    builder.set_pubkey(&pkey).expect("set pubkey");
    builder
        .sign(&pkey, MessageDigest::sha384())
        .expect("sign CSR");

    let csr = builder.build();
    let csr_der = csr.to_der().expect("CSR to DER");

    let mut tbs_bytes = tbs::extract_csr_tbs(&csr_der);

    let fields = vec![
        FieldOffset {
            name: "PUBLIC_KEY",
            offset: tbs::find_needle(&tbs_bytes, &pubkey_bytes, "PUBLIC_KEY"),
            len: P384_PUBKEY_LEN,
        },
        FieldOffset {
            name: "SUBJECT_CN",
            offset: tbs::find_needle(&tbs_bytes, subject_cn.as_bytes(), "SUBJECT_CN"),
            len: PTA_CN_LEN,
        },
        FieldOffset {
            name: "SUBJECT_SN",
            offset: tbs::find_needle(&tbs_bytes, subject_sn.as_bytes(), "SUBJECT_SN"),
            len: PTA_SN_LEN,
        },
    ];

    tbs::sanitize_tbs(&mut tbs_bytes, &fields);

    CsrTemplateResult {
        tbs: tbs_bytes,
        fields,
    }
}
