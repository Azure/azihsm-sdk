// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CSR (PKCS#10) template builder using OpenSSL.
//!
//! Builds a valid PKCS#10 CertificationRequest with P-384 key and known
//! needle values for CN and serialNumber. The TBS portion is extracted,
//! needle-matched, and sanitized to produce a reusable template.

use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509Name;
use openssl::x509::X509ReqBuilder;

use crate::tbs::FieldOffset;
use crate::tbs::{self};

/// Length of uncompressed P-384 public key point (`0x04 || x[48] || y[48]`).
const P384_PUBKEY_LEN: usize = 97;

/// Length of Common Name field in bytes (space-padded to fixed size).
const CN_LEN: usize = 32;

/// Length of serialNumber DN attribute (hex-encoded, 64 chars).
const SN_LEN: usize = 64;

/// Needle string for subject CN — a unique 32-char ASCII pattern
/// that the generator embeds in the CSR's subject DN, then locates
/// in the DER to determine the CN field offset.
fn subject_cn_needle() -> String {
    "SubjectCNNeedle AAAAAAAAAAAAAAAA".to_string()
}

/// Needle string for subject serialNumber — a unique 64-char hex
/// pattern embedded in the CSR's subject DN.
fn subject_sn_needle() -> String {
    "C1C2C3C4C5C6C7C8C9CACBCCCDCECFC0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFCE".to_string()
}

/// Result of building a CSR template.
pub struct CsrTemplateResult {
    /// Sanitized TBS bytes with placeholder (`0x5F`) at variable positions.
    pub tbs: Vec<u8>,
    /// Variable field descriptors for code generation.
    pub fields: Vec<FieldOffset>,
}

/// Build a device CSR template.
///
/// Generates a valid PKCS#10 CSR using OpenSSL, extracts the
/// CertificationRequestInfo (TBS), locates variable fields by needle
/// matching, and sanitizes the template.
///
/// # Returns
/// A [`CsrTemplateResult`] containing the sanitized TBS and field offsets.
pub fn build_device_csr() -> CsrTemplateResult {
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
            len: CN_LEN,
        },
        FieldOffset {
            name: "SUBJECT_SN",
            offset: tbs::find_needle(&tbs_bytes, subject_sn.as_bytes(), "SUBJECT_SN"),
            len: SN_LEN,
        },
    ];

    tbs::sanitize_tbs(&mut tbs_bytes, &fields);

    CsrTemplateResult {
        tbs: tbs_bytes,
        fields,
    }
}
