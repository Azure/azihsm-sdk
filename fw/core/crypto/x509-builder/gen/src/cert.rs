// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate template builder using OpenSSL.
//!
//! Creates valid X.509v3 certificates (Root CA, Leaf) with
//! known "needle" values for every variable field. After DER serialization,
//! the TBS is extracted, needles are located by byte search, and the
//! template is sanitized by replacing needle bytes with `0x5F` placeholders.
//!
//! # Needle Strategy
//!
//! Each variable field has a unique needle pattern:
//! - **Public key**: a randomly generated P-384 key (97 bytes).
//! - **Serial number**: a deterministic 20-byte pattern starting with `0x7E`.
//! - **CN** / **SN**: unique fixed-length ASCII strings.
//! - **Validity dates**: unique `GeneralizedTime` strings.
//! - **SKI** / **AKI**: SHA-1 hashes computed from the needle public keys.
//!
//! For the self-signed Root CA, CN and SN appear twice (issuer = subject);
//! [`find_all_needles`](crate::tbs::find_all_needles) is used with the
//! convention that the first occurrence is the issuer and the second is
//! the subject (DER order).

use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Builder;
use openssl::x509::X509Name;

use crate::tbs::FieldOffset;
use crate::tbs::{self};

/// Length of uncompressed P-384 public key point (`0x04 || x[48] || y[48]`).
const P384_PUBKEY_LEN: usize = 97;

/// Length of X.509 certificate serial number in bytes.
const SERIAL_NUMBER_LEN: usize = 20;

/// Length of Subject Key Identifier (SHA-1 hash, 20 bytes).
const SKI_LEN: usize = 20;

/// Length of Authority Key Identifier (SHA-1 hash, 20 bytes).
const AKI_LEN: usize = 20;

/// Length of GeneralizedTime encoding (`"YYYYMMDDHHMMSSZ"`, 15 bytes).
const GENERALIZED_TIME_LEN: usize = 15;

/// Length of Common Name field in bytes (space-padded to fixed size).
const CN_LEN: usize = 32;

/// Length of serialNumber DN attribute (hex-encoded string, 64 chars).
const SN_LEN: usize = 64;

/// Needle bytes for serial number — a deterministic 20-byte pattern.
///
/// First byte is `0x7E` (bit 7 = 0, ensuring a positive DER INTEGER).
/// Remaining bytes cycle through `0xB0..0xBF`.
fn serial_needle() -> [u8; SERIAL_NUMBER_LEN] {
    let mut needle = [0u8; SERIAL_NUMBER_LEN];
    // First byte must have bit 7 = 0 (positive DER INTEGER)
    needle[0] = 0x7E;
    for (i, byte) in needle.iter_mut().enumerate().skip(1) {
        *byte = (0xB0 + (i % 16)) as u8;
    }
    needle
}

/// Needle string for subject CN — a unique 32-char ASCII pattern.
///
/// Used in the subject DN. For non-self-signed certs, this appears once;
/// for the self-signed root, it appears twice (issuer = subject).
fn subject_cn_needle() -> String {
    "SubjectCNNeedle AAAAAAAAAAAAAAAA".to_string()
}

/// Needle string for issuer CN — a unique 32-char ASCII pattern
/// distinct from the subject CN needle.
///
/// Used in the helper signer cert's subject DN so the target cert's
/// issuer DN contains a locatable pattern.
fn issuer_cn_needle() -> String {
    "IssuerCNNeedle  BBBBBBBBBBBBBBBB".to_string()
}

/// Needle string for subject serialNumber — a unique 64-char hex pattern.
fn subject_sn_needle() -> String {
    "C1C2C3C4C5C6C7C8C9CACBCCCDCECFC0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFCE".to_string()
}

/// Needle string for issuer serialNumber — a unique 64-char hex pattern
/// distinct from the subject SN needle.
fn issuer_sn_needle() -> String {
    "E1E2E3E4E5E6E7E8E9EAEBECEDEEEFE0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFA1".to_string()
}

/// GeneralizedTime needle for NOT_BEFORE (`"20991231235959Z"`).
///
/// Chosen to be a unique, easily recognizable date that won't collide
/// with other date values.
fn not_before_needle() -> &'static str {
    "20991231235959Z"
}

/// GeneralizedTime needle for NOT_AFTER (`"20991230235959Z"`).
///
/// One day before NOT_BEFORE to ensure the two needles are distinct.
fn not_after_needle() -> &'static str {
    "20991230235959Z"
}

/// Result of building a certificate template.
pub struct CertTemplateResult {
    /// Sanitized TBS bytes with placeholder (`0x5F`) at variable positions.
    pub tbs: Vec<u8>,
    /// Variable field descriptors for code generation.
    pub fields: Vec<FieldOffset>,
}

/// Generate a random P-384 EC key pair.
///
/// # Returns
/// `(private_key, uncompressed_public_key_bytes)` where the public key
/// is 97 bytes: `0x04 || x[48] || y[48]`.
fn generate_p384_keypair() -> (PKey<openssl::pkey::Private>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("P-384 curve");
    let ec_key = EcKey::generate(&group).expect("generate EC key");
    let mut bn_ctx = openssl::bn::BigNumContext::new().expect("bn ctx");
    let pubkey_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )
        .expect("pubkey to bytes");
    assert_eq!(pubkey_bytes.len(), P384_PUBKEY_LEN);
    let pkey = PKey::from_ec_key(ec_key).expect("PKey from EC");
    (pkey, pubkey_bytes)
}

/// Build an X.509 Name (DN) with Common Name and serialNumber attributes.
///
/// # Arguments
/// * `cn` — Common Name string (must be exactly [`CN_LEN`] bytes).
/// * `serial_number_hex` — serialNumber attribute (must be exactly [`SN_LEN`] bytes).
///
/// # Panics
/// Panics if the string lengths don't match the expected constants.
fn build_name(cn: &str, serial_number_hex: &str) -> X509Name {
    assert_eq!(cn.len(), CN_LEN, "CN must be exactly {CN_LEN} bytes");
    assert_eq!(
        serial_number_hex.len(),
        SN_LEN,
        "serialNumber must be exactly {SN_LEN} hex chars"
    );
    let mut builder = X509Name::builder().expect("X509Name builder");
    builder.append_entry_by_text("CN", cn).expect("append CN");
    builder
        .append_entry_by_text("serialNumber", serial_number_hex)
        .expect("append serialNumber");
    builder.build()
}

/// Set the serial number on an X.509 builder from raw big-endian bytes.
fn set_serial(builder: &mut X509Builder, serial_bytes: &[u8]) {
    let bn = BigNum::from_slice(serial_bytes).expect("BigNum from serial");
    let asn1_int = Asn1Integer::from_bn(&bn).expect("Asn1Integer from BigNum");
    builder.set_serial_number(&asn1_int).expect("set serial");
}

/// Compute Subject Key Identifier (SHA-1 hash of the uncompressed public key point).
///
/// Per RFC 5280 §4.2.1.2 method (1): the 160-bit SHA-1 hash of the
/// BIT STRING value of the subjectPublicKey (excluding tag and length).
fn compute_ski(pubkey_uncompressed: &[u8]) -> [u8; 20] {
    use openssl::hash::hash;
    use openssl::hash::MessageDigest;
    let digest = hash(MessageDigest::sha1(), pubkey_uncompressed).expect("SHA-1");
    let mut result = [0u8; 20];
    result.copy_from_slice(&digest);
    result
}

/// Helper: add BasicConstraints (CA:TRUE), KeyUsage (keyCertSign + cRLSign), and
/// SubjectKeyIdentifier extensions to a certificate builder.
///
/// # Arguments
/// * `builder` — The X.509 builder to add extensions to.
/// * `issuer` — Optional issuer cert reference (for SKI context; `None` for self-signed).
/// * `pathlen` — Optional path length constraint (omitted if `None`).
fn add_ca_extensions(
    builder: &mut X509Builder,
    issuer: Option<&openssl::x509::X509Ref>,
    pathlen: Option<u32>,
) {
    let mut bc = BasicConstraints::new();
    bc.critical().ca();
    if let Some(pl) = pathlen {
        bc.pathlen(pl);
    }
    builder
        .append_extension(bc.build().expect("bc"))
        .expect("append bc");

    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("ku"),
        )
        .expect("append ku");

    let ctx = builder.x509v3_context(issuer, None);
    builder
        .append_extension(SubjectKeyIdentifier::new().build(&ctx).expect("ski"))
        .expect("append ski");
}

/// Helper: add Authority Key Identifier extension referencing the issuer's key.
fn add_aki(builder: &mut X509Builder, issuer: &openssl::x509::X509Ref) {
    let ctx = builder.x509v3_context(Some(issuer), None);
    builder
        .append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&ctx)
                .expect("aki"),
        )
        .expect("append aki");
}

/// Build a self-signed Root CA certificate template.
///
/// CN and SN needles appear twice in the TBS (issuer = subject). The first
/// occurrence in DER order is the issuer, the second is the subject.
///
/// # Returns
/// A [`CertTemplateResult`] with 9 variable fields: PUBLIC_KEY, SERIAL_NUMBER,
/// NOT_BEFORE, NOT_AFTER, ISSUER_CN, SUBJECT_CN, ISSUER_SN, SUBJECT_SN,
/// SUBJECT_KEY_ID.
pub fn build_root_cert() -> CertTemplateResult {
    let (key, pubkey_bytes) = generate_p384_keypair();
    let serial = serial_needle();
    let subject_cn = subject_cn_needle();
    let subject_sn = subject_sn_needle();
    let subject = build_name(&subject_cn, &subject_sn);

    let mut builder = X509Builder::new().expect("X509Builder");
    builder.set_version(2).expect("set version"); // v3
    set_serial(&mut builder, &serial);
    builder.set_subject_name(&subject).expect("set subject");
    builder.set_issuer_name(&subject).expect("set issuer"); // self-signed

    let not_before = Asn1Time::from_str_x509(not_before_needle()).expect("not_before");
    let not_after = Asn1Time::from_str_x509(not_after_needle()).expect("not_after");
    builder.set_not_before(&not_before).expect("set not_before");
    builder.set_not_after(&not_after).expect("set not_after");
    builder.set_pubkey(&key).expect("set pubkey");

    add_ca_extensions(&mut builder, None, None);

    builder
        .sign(&key, MessageDigest::sha384())
        .expect("sign cert");
    let cert = builder.build();
    let cert_der = cert.to_der().expect("cert to DER");

    let mut tbs_bytes = tbs::extract_tbs(&cert_der);

    let pk_offset = tbs::find_needle(&tbs_bytes, &pubkey_bytes, "PUBLIC_KEY");
    let sn_offset = tbs::find_needle(&tbs_bytes, &serial, "SERIAL_NUMBER");
    let nb_offset = tbs::find_needle(&tbs_bytes, not_before_needle().as_bytes(), "NOT_BEFORE");
    let na_offset = tbs::find_needle(&tbs_bytes, not_after_needle().as_bytes(), "NOT_AFTER");

    // CN appears twice in root (issuer=subject, self-signed)
    // DER order: issuer before subject, so first match = ISSUER_CN, second = SUBJECT_CN
    let cn_offsets = tbs::find_all_needles(&tbs_bytes, subject_cn.as_bytes());
    assert_eq!(
        cn_offsets.len(),
        2,
        "Expected subject_cn needle twice in self-signed root TBS"
    );

    // SN appears twice in root (issuer=subject, self-signed)
    let sn_offsets = tbs::find_all_needles(&tbs_bytes, subject_sn.as_bytes());
    assert_eq!(
        sn_offsets.len(),
        2,
        "Expected subject_sn needle twice in self-signed root TBS"
    );

    let ski_value = compute_ski(&pubkey_bytes);
    let ski_offset = tbs::find_needle(&tbs_bytes, &ski_value, "SUBJECT_KEY_ID");

    let fields = vec![
        FieldOffset {
            name: "PUBLIC_KEY",
            offset: pk_offset,
            len: P384_PUBKEY_LEN,
        },
        FieldOffset {
            name: "SERIAL_NUMBER",
            offset: sn_offset,
            len: SERIAL_NUMBER_LEN,
        },
        FieldOffset {
            name: "NOT_BEFORE",
            offset: nb_offset,
            len: GENERALIZED_TIME_LEN,
        },
        FieldOffset {
            name: "NOT_AFTER",
            offset: na_offset,
            len: GENERALIZED_TIME_LEN,
        },
        FieldOffset {
            name: "ISSUER_CN",
            offset: cn_offsets[0],
            len: CN_LEN,
        },
        FieldOffset {
            name: "SUBJECT_CN",
            offset: cn_offsets[1],
            len: CN_LEN,
        },
        FieldOffset {
            name: "ISSUER_SN",
            offset: sn_offsets[0],
            len: SN_LEN,
        },
        FieldOffset {
            name: "SUBJECT_SN",
            offset: sn_offsets[1],
            len: SN_LEN,
        },
        FieldOffset {
            name: "SUBJECT_KEY_ID",
            offset: ski_offset,
            len: SKI_LEN,
        },
    ];

    tbs::sanitize_tbs(&mut tbs_bytes, &fields);

    CertTemplateResult {
        tbs: tbs_bytes,
        fields,
    }
}

/// Build a Leaf (end-entity) certificate template.
///
/// A temporary CA cert is created internally to act as the issuer. The
/// CA's subject DN uses the issuer needle patterns. The leaf has
/// BasicConstraints(CA:FALSE) and variable KeyUsage.
///
/// # Returns
/// A [`CertTemplateResult`] with 11 variable fields: PUBLIC_KEY, SERIAL_NUMBER,
/// NOT_BEFORE, NOT_AFTER, ISSUER_CN, SUBJECT_CN, ISSUER_SN, SUBJECT_SN,
/// SUBJECT_KEY_ID, AUTHORITY_KEY_ID, KEY_USAGE.
pub fn build_leaf_cert() -> CertTemplateResult {
    // Build root CA
    let (root_key, _root_pubkey) = generate_p384_keypair();
    let root_cn = "Root CA Placeholder XXXXXXXXXXXX";
    let root_sn = "0000000000000000000000000000000000000000000000000000000000000001";
    let root_subject = build_name(root_cn, root_sn);

    let mut root_builder = X509Builder::new().expect("root builder");
    root_builder.set_version(2).expect("ver");
    set_serial(&mut root_builder, &[0x01]);
    root_builder.set_subject_name(&root_subject).expect("subj");
    root_builder.set_issuer_name(&root_subject).expect("issuer");
    let nb = Asn1Time::from_str_x509("20990101000000Z").expect("nb");
    let na = Asn1Time::from_str_x509("20991231235959Z").expect("na");
    root_builder.set_not_before(&nb).expect("nb");
    root_builder.set_not_after(&na).expect("na");
    root_builder.set_pubkey(&root_key).expect("pubkey");
    add_ca_extensions(&mut root_builder, None, None);
    root_builder
        .sign(&root_key, MessageDigest::sha384())
        .expect("sign");
    let root_cert = root_builder.build();

    // Intermediate CA — its subject becomes the leaf's issuer
    let (inter_key, inter_pubkey_bytes) = generate_p384_keypair();
    let inter_subject = build_name(&issuer_cn_needle(), &issuer_sn_needle());

    let mut inter_builder = X509Builder::new().expect("inter builder");
    inter_builder.set_version(2).expect("ver");
    set_serial(&mut inter_builder, &[0x02]);
    inter_builder
        .set_subject_name(&inter_subject)
        .expect("subj");
    inter_builder
        .set_issuer_name(root_cert.subject_name())
        .expect("issuer");
    let nb = Asn1Time::from_str_x509("20990101000000Z").expect("nb");
    let na = Asn1Time::from_str_x509("20991231235959Z").expect("na");
    inter_builder.set_not_before(&nb).expect("nb");
    inter_builder.set_not_after(&na).expect("na");
    inter_builder.set_pubkey(&inter_key).expect("pubkey");
    add_ca_extensions(&mut inter_builder, Some(&root_cert), Some(0));
    add_aki(&mut inter_builder, &root_cert);
    inter_builder
        .sign(&root_key, MessageDigest::sha384())
        .expect("sign");
    let inter_cert = inter_builder.build();

    // Leaf certificate
    let (leaf_key, leaf_pubkey_bytes) = generate_p384_keypair();
    let serial = serial_needle();
    let subject_cn = subject_cn_needle();
    let subject_sn = subject_sn_needle();
    let leaf_subject = build_name(&subject_cn, &subject_sn);

    let mut builder = X509Builder::new().expect("X509Builder");
    builder.set_version(2).expect("ver");
    set_serial(&mut builder, &serial);
    builder.set_subject_name(&leaf_subject).expect("subj");
    builder
        .set_issuer_name(inter_cert.subject_name())
        .expect("issuer");

    let not_before = Asn1Time::from_str_x509(not_before_needle()).expect("nb");
    let not_after = Asn1Time::from_str_x509(not_after_needle()).expect("na");
    builder.set_not_before(&not_before).expect("nb");
    builder.set_not_after(&not_after).expect("na");
    builder.set_pubkey(&leaf_key).expect("pubkey");

    // CA:FALSE
    builder
        .append_extension(BasicConstraints::new().critical().build().expect("bc"))
        .expect("bc");

    // Key Usage: digitalSignature as needle
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .expect("ku"),
        )
        .expect("ku");

    // SKI
    {
        let ctx = builder.x509v3_context(Some(&inter_cert), None);
        builder
            .append_extension(SubjectKeyIdentifier::new().build(&ctx).expect("ski"))
            .expect("ski");
    }

    // AKI
    add_aki(&mut builder, &inter_cert);

    builder
        .sign(&inter_key, MessageDigest::sha384())
        .expect("sign");
    let cert = builder.build();
    let cert_der = cert.to_der().expect("DER");

    let mut tbs_bytes = tbs::extract_tbs(&cert_der);

    let ski_value = compute_ski(&leaf_pubkey_bytes);
    let aki_value = compute_ski(&inter_pubkey_bytes);

    // Key Usage: digitalSignature = BIT STRING 03 02 07 80
    let ku_needle = [0x03, 0x02, 0x07, 0x80];
    let ku_offset = tbs::find_needle(&tbs_bytes, &ku_needle, "KEY_USAGE_BITSTRING");

    let fields = vec![
        FieldOffset {
            name: "PUBLIC_KEY",
            offset: tbs::find_needle(&tbs_bytes, &leaf_pubkey_bytes, "PUBLIC_KEY"),
            len: P384_PUBKEY_LEN,
        },
        FieldOffset {
            name: "SERIAL_NUMBER",
            offset: tbs::find_needle(&tbs_bytes, &serial, "SERIAL_NUMBER"),
            len: SERIAL_NUMBER_LEN,
        },
        FieldOffset {
            name: "NOT_BEFORE",
            offset: tbs::find_needle(&tbs_bytes, not_before_needle().as_bytes(), "NOT_BEFORE"),
            len: GENERALIZED_TIME_LEN,
        },
        FieldOffset {
            name: "NOT_AFTER",
            offset: tbs::find_needle(&tbs_bytes, not_after_needle().as_bytes(), "NOT_AFTER"),
            len: GENERALIZED_TIME_LEN,
        },
        // Issuer CN/SN from the intermediate
        FieldOffset {
            name: "ISSUER_CN",
            offset: tbs::find_needle(&tbs_bytes, issuer_cn_needle().as_bytes(), "ISSUER_CN"),
            len: CN_LEN,
        },
        FieldOffset {
            name: "ISSUER_SN",
            offset: tbs::find_needle(&tbs_bytes, issuer_sn_needle().as_bytes(), "ISSUER_SN"),
            len: SN_LEN,
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
        FieldOffset {
            name: "SUBJECT_KEY_ID",
            offset: tbs::find_needle(&tbs_bytes, &ski_value, "SUBJECT_KEY_ID"),
            len: SKI_LEN,
        },
        FieldOffset {
            name: "AUTHORITY_KEY_ID",
            offset: tbs::find_needle(&tbs_bytes, &aki_value, "AUTHORITY_KEY_ID"),
            len: AKI_LEN,
        },
        // Variable portion: unused_bits + usage byte (2 bytes at offset+2)
        FieldOffset {
            name: "KEY_USAGE",
            offset: ku_offset + 2,
            len: 2,
        },
    ];

    tbs::sanitize_tbs(&mut tbs_bytes, &fields);

    CertTemplateResult {
        tbs: tbs_bytes,
        fields,
    }
}
