// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-platform X.509 PTA certificate-chain fixtures for `PartFinal`.
//!
//! `PartFinal` validates that the supplied PTA certificate chain is
//! anchored to the policy `POTAPubKey` and that its leaf public key is the
//! partition's PTA key. These helpers build such a chain on the host with
//! [`azihsm_crypto`] (key generation + ECDSA-P384 signing, cross-platform
//! CNG on Windows / OpenSSL on Linux) and the
//! [`azihsm_crypto::x509_builder`] TBS templates, so the emu tests exercise
//! the real firmware `x509-chain` validator end to end without depending on
//! any `fw` crate or on OpenSSL directly.

use azihsm_crypto::x509_builder::cert_builder;
use azihsm_crypto::x509_builder::cert_builder::IntermediateCertParams;
use azihsm_crypto::x509_builder::cert_builder::RootCertParams;
use azihsm_crypto::x509_builder::cert_builder::CN_LEN;
use azihsm_crypto::x509_builder::cert_builder::SN_LEN;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EcdsaAlgo;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::SignOp;

/// Length of a SEC1 uncompressed P-384 point (`0x04 ‖ X ‖ Y`).
pub const SEC1_PUB_LEN: usize = 97;

/// Length of a raw P-384 public point (`X ‖ Y`, big-endian, no tag).
pub const RAW_PUB_LEN: usize = 96;

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const ROOT_CN: &str = "AZIHSM POTA Root CA";
const ROOT_SN: &str = "POTAROOT1";
const PTA_CN: &str = "AZIHSM PTA Intermediate CA";
const PTA_SN: &str = "PTAINT001";

/// A synthetic P-384 CA key (e.g. a policy POTA trust anchor) that can
/// sign certificates and expose its public key.
pub struct CaKey {
    private_key: EccPrivateKey,
    pub_sec1: [u8; SEC1_PUB_LEN],
}

impl CaKey {
    /// Generate a fresh P-384 CA key.
    pub fn generate() -> Self {
        let private_key = EccPrivateKey::from_curve(EccCurve::P384).expect("P-384 key");
        let (x, y) = private_key.coord_vec().expect("coords");
        let mut pub_sec1 = [0u8; SEC1_PUB_LEN];
        pub_sec1[0] = 0x04;
        pub_sec1[1..49].copy_from_slice(&x);
        pub_sec1[49..97].copy_from_slice(&y);
        Self {
            private_key,
            pub_sec1,
        }
    }

    /// Raw `X ‖ Y` (96-byte, big-endian) public coordinates — the form a
    /// policy `pota_pub_key` stores.
    pub fn raw_pub(&self) -> [u8; RAW_PUB_LEN] {
        self.pub_sec1[1..].try_into().expect("raw pub")
    }

    /// SEC1 uncompressed public key (`0x04 ‖ X ‖ Y`, 97 bytes).
    pub fn sec1_pub(&self) -> [u8; SEC1_PUB_LEN] {
        self.pub_sec1
    }

    /// SHA-1 of the SEC1 public key — the Subject Key Identifier.
    fn ski(&self) -> [u8; 20] {
        sha1_ski(&self.pub_sec1)
    }

    /// ECDSA-P384 / SHA-384 sign `tbs`, returning `(r, s)` (48 bytes each).
    fn sign(&self, tbs: &[u8]) -> ([u8; 48], [u8; 48]) {
        let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
        let len = algo.sign(&self.private_key, tbs, None).expect("sig len");
        let mut sig = vec![0u8; len];
        let written = algo
            .sign(&self.private_key, tbs, Some(&mut sig))
            .expect("sign");
        assert_eq!(written, 96, "P-384 raw signature is 96 bytes");
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..96]);
        (r, s)
    }
}

/// SHA-1 of a SEC1 public key (Subject / Authority Key Identifier).
fn sha1_ski(sec1: &[u8; SEC1_PUB_LEN]) -> [u8; 20] {
    let mut algo = HashAlgo::sha1();
    let mut out = [0u8; 20];
    algo.hash(sec1, Some(&mut out)).expect("sha1");
    out
}

/// A 20-byte positive DER serial number seeded from `tag`.
fn serial(tag: u8) -> [u8; 20] {
    let mut s = [0u8; 20];
    s[0] = tag & 0x7F; // positive INTEGER (bit 7 clear)
    for (i, b) in s.iter_mut().enumerate().skip(1) {
        *b = tag.wrapping_add(i as u8);
    }
    s
}

fn pad_cn(cn: &str) -> [u8; CN_LEN] {
    let mut out = [b' '; CN_LEN];
    out[..cn.len()].copy_from_slice(cn.as_bytes());
    out
}

fn pad_sn(sn: &str) -> [u8; SN_LEN] {
    let mut out = [b'0'; SN_LEN];
    out[..sn.len()].copy_from_slice(sn.as_bytes());
    out
}

/// Build a self-signed Root CA certificate for `ca` (DER).
pub fn build_root(ca: &CaKey) -> Vec<u8> {
    let params = RootCertParams {
        public_key: &ca.pub_sec1,
        serial_number: &serial(1),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: ROOT_CN,
        subject_sn: ROOT_SN,
        subject_key_id: &ca.ski(),
    };

    let mut tbs = azihsm_crypto::x509_builder::root_cert::TBS_TEMPLATE;
    patch_tbs_root(&mut tbs, &params);
    let (r, s) = ca.sign(&tbs);

    let mut out = vec![0u8; 1024];
    let len = cert_builder::build_root_cert(&params, &r, &s, &mut out).expect("root cert");
    out.truncate(len);
    out
}

/// Build the PTA intermediate CA certificate whose subject public key is
/// `pta_pub_sec1` (the partition PTA key), signed by `issuer` (the POTA
/// CA).  The PTA is a CA cert (`cA=true`), **not** an end-entity leaf.
pub fn build_pta_intermediate(pta_pub_sec1: &[u8; SEC1_PUB_LEN], issuer: &CaKey) -> Vec<u8> {
    let params = IntermediateCertParams {
        public_key: pta_pub_sec1,
        serial_number: &serial(2),
        not_before: NOT_BEFORE,
        not_after: NOT_AFTER,
        subject_cn: PTA_CN,
        subject_sn: PTA_SN,
        issuer_cn: ROOT_CN,
        issuer_sn: ROOT_SN,
        subject_key_id: &sha1_ski(pta_pub_sec1),
        authority_key_id: &issuer.ski(),
        path_len: 0,
    };

    let mut tbs = azihsm_crypto::x509_builder::intermediate_cert::TBS_TEMPLATE;
    patch_tbs_intermediate(&mut tbs, &params);
    let (r, s) = issuer.sign(&tbs);

    let mut out = vec![0u8; 1024];
    let len =
        cert_builder::build_intermediate_cert(&params, &r, &s, &mut out).expect("PTA intermediate");
    out.truncate(len);
    out
}

/// A generated PTA chain, root → PTA intermediate, DER-encoded.
pub struct PtaChain {
    /// Self-signed POTA root CA certificate (DER).
    pub root_der: Vec<u8>,
    /// PTA intermediate CA certificate carrying the partition PTA key (DER).
    pub pta_der: Vec<u8>,
}

impl PtaChain {
    /// The chain's certificate DERs in root → PTA order, ready to hand to
    /// `PartFinal` as out-of-band items.
    pub fn der_items(&self) -> [&[u8]; 2] {
        [self.root_der.as_slice(), self.pta_der.as_slice()]
    }
}

/// Build a root→PTA chain: a self-signed root CA (`pota_ca`, whose public
/// key is the policy `POTAPubKey`) certifying a PTA intermediate CA that
/// carries `pta_pub_sec1` (the partition PTA key, e.g. learned from the
/// `PartInit` CSR).
pub fn make_pta_chain(pota_ca: &CaKey, pta_pub_sec1: &[u8; SEC1_PUB_LEN]) -> PtaChain {
    PtaChain {
        root_der: build_root(pota_ca),
        pta_der: build_pta_intermediate(pta_pub_sec1, pota_ca),
    }
}

/// Extract the SEC1 public key (`0x04 ‖ X ‖ Y`, 97 bytes) from a DER
/// PKCS#10 CSR, parsed structurally per
/// [RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986):
///
/// ```text
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo SEQUENCE {
///         version                 INTEGER,
///         subject                 Name,
///         subjectPKInfo           SEQUENCE {
///             algorithm           AlgorithmIdentifier,
///             subjectPublicKey     BIT STRING },   -- 00 ‖ 04 ‖ X ‖ Y
///         attributes          [0] IMPLICIT ... },
///     signatureAlgorithm       AlgorithmIdentifier,
///     signature                BIT STRING }
/// ```
///
/// This is the receiver's "convert CSR → certificate" step: read the
/// requested public key so the POTA CA can issue the PTA cert for it.
pub fn pta_pub_from_csr(csr: &[u8]) -> [u8; SEC1_PUB_LEN] {
    // CertificationRequest ::= SEQUENCE
    let (_, cr, _) = der_tlv(csr);
    // certificationRequestInfo ::= SEQUENCE (first field of the request)
    let (_, cri, _) = der_tlv(cr);
    // version INTEGER
    let (_, _version, after_version) = der_tlv(cri);
    // subject Name ::= SEQUENCE
    let (_, _subject, after_subject) = der_tlv(after_version);
    // subjectPKInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let (_, spki, _) = der_tlv(after_subject);
    // algorithm AlgorithmIdentifier ::= SEQUENCE
    let (_, _algorithm, after_algorithm) = der_tlv(spki);
    // subjectPublicKey BIT STRING
    let (tag, bit_string, _) = der_tlv(after_algorithm);
    assert_eq!(tag, 0x03, "subjectPublicKey must be a BIT STRING");
    // BIT STRING content: leading unused-bits octet (0), then the SEC1
    // uncompressed point (0x04 ‖ X ‖ Y).
    let point = &bit_string[1..];
    assert_eq!(point.len(), SEC1_PUB_LEN, "P-384 uncompressed point");
    assert_eq!(point[0], 0x04, "uncompressed point tag");
    point.try_into().expect("SEC1 point")
}

/// Read one DER TLV at the start of `der`, returning `(tag, contents,
/// rest)`.  Supports short- and long-form definite lengths (sufficient
/// for the small CSRs the firmware emits).
fn der_tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = der[0];
    let len_octet = der[1];
    let (len, header) = if len_octet & 0x80 == 0 {
        (usize::from(len_octet), 2)
    } else {
        let n = usize::from(len_octet & 0x7F);
        let mut len = 0usize;
        for &b in &der[2..2 + n] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + n)
    };
    (tag, &der[header..header + len], &der[header + len..])
}

fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    use azihsm_crypto::x509_builder::root_cert::*;
    let cn = pad_cn(params.subject_cn);
    let sn = pad_sn(params.subject_sn);
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
}

fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    use azihsm_crypto::x509_builder::intermediate_cert::*;
    let s_cn = pad_cn(params.subject_cn);
    let i_cn = pad_cn(params.issuer_cn);
    let s_sn = pad_sn(params.subject_sn);
    let i_sn = pad_sn(params.issuer_sn);
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[PATH_LEN_OFFSET] = params.path_len;
}
