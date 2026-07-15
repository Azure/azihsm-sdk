// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime certificate builder.
//!
//! Patches variable fields into pre-generated TBS (To-Be-Signed) templates
//! and assembles complete DER-encoded X.509 certificates with ECDSA-P384
//! signatures.
//!
//! # Usage
//!
//! 1. Fill a params struct ([`RootCertParams`](super::cert_builder::RootCertParams), [`IntermediateCertParams`](super::cert_builder::IntermediateCertParams),
//!    or [`LeafCertParams`](super::cert_builder::LeafCertParams)) with the variable field values.
//! 2. Sign the patched TBS externally (the TBS template is available as a
//!    public `const` in the corresponding template module).
//! 3. Call the matching `build_*` function with the params, the raw ECDSA
//!    (r, s) signature components, and an output buffer.
//!
//! CN and SN strings are validated and padded internally — callers pass
//! plain `&str` values.
//!
//! # Returns
//!
//! Each builder returns `Option<usize>`: the number of DER bytes written
//! to the output buffer, or `None` if any validation fails (invalid CN/SN,
//! bad serial number, buffer too small).

use bitfield_struct::bitfield;

use super::der_helpers::ECDSA_SHA384_ALG_ID;
use super::der_helpers::MAX_ECDSA384_SIG_DER_LEN;
use super::der_helpers::{self};

/// Length of Common Name field (space-padded ASCII, 32 bytes).
pub const CN_LEN: usize = 32;

/// Length of DN serialNumber field (hex-encoded, 64 bytes).
pub const SN_LEN: usize = 64;

/// X.509 Key Usage extension as a DER BIT STRING value (2 bytes).
///
/// The 2-byte encoding matches the DER BIT STRING content for the
/// KeyUsage extension: `[unused_bits_count, usage_flags_byte]`.
///
/// - `unused_bits_count`: number of unused trailing bits (0–7) in the
///   flags byte.
/// - `usage_flags_byte`: bit flags where MSB = digitalSignature, per
///   RFC 5280 §4.2.1.3.
///
/// # Bit Ordering Note
///
/// `bitfield_struct` packs bits LSB-first, but X.509 KeyUsage uses
/// MSB-first. The [`to_bytes`](KeyUsage::to_bytes) method reverses the
/// flags byte automatically.
///
/// # Predefined Constants
///
/// - [`DIGITAL_SIGNATURE`](KeyUsage::DIGITAL_SIGNATURE) — `[0x07, 0x80]`
/// - [`KEY_CERT_SIGN_CRL_SIGN`](KeyUsage::KEY_CERT_SIGN_CRL_SIGN) — `[0x01, 0x06]`
/// - [`KEY_AGREEMENT`](KeyUsage::KEY_AGREEMENT) — `[0x03, 0x08]`
#[bitfield(u16)]
#[derive(PartialEq, Eq)]
pub struct KeyUsage {
    /// Number of unused trailing bits in the usage flags byte.
    #[bits(8)]
    pub unused_bits: u8,

    /// digitalSignature (bit 7 of usage byte).
    #[bits(1)]
    pub digital_signature: bool,

    /// contentCommitment / nonRepudiation (bit 6).
    #[bits(1)]
    pub content_commitment: bool,

    /// keyEncipherment (bit 5).
    #[bits(1)]
    pub key_encipherment: bool,

    /// dataEncipherment (bit 4).
    #[bits(1)]
    pub data_encipherment: bool,

    /// keyAgreement (bit 3).
    #[bits(1)]
    pub key_agreement: bool,

    /// keyCertSign (bit 2).
    #[bits(1)]
    pub key_cert_sign: bool,

    /// cRLSign (bit 1).
    #[bits(1)]
    pub crl_sign: bool,

    /// encipherOnly (bit 0).
    #[bits(1)]
    pub encipher_only: bool,
}

impl KeyUsage {
    /// digitalSignature only: `[0x07, 0x80]`.
    pub const DIGITAL_SIGNATURE: Self =
        Self::new().with_digital_signature(true).with_unused_bits(7);

    /// keyCertSign + cRLSign: `[0x01, 0x06]`.
    pub const KEY_CERT_SIGN_CRL_SIGN: Self = Self::new()
        .with_key_cert_sign(true)
        .with_crl_sign(true)
        .with_unused_bits(1);

    /// keyAgreement only: `[0x03, 0x08]`.
    pub const KEY_AGREEMENT: Self = Self::new().with_key_agreement(true).with_unused_bits(3);

    /// Convert to the 2-byte DER BIT STRING value `[unused_bits, flags]`.
    ///
    /// The flags byte is bit-reversed to convert from bitfield_struct's
    /// LSB-first layout to X.509's MSB-first layout.
    pub const fn to_bytes(self) -> [u8; 2] {
        let raw = self.into_bits();
        let unused_bits = raw as u8;
        // bitfield_struct packs bits LSB-first, but X.509 Key Usage uses
        // MSB-first ordering (digitalSignature = bit 7 of the flags byte).
        // Reverse the bit order of the flags byte.
        let flags_lsb = (raw >> 8) as u8;
        let flags = flags_lsb.reverse_bits();
        [unused_bits, flags]
    }
}

/// Parameters for building a self-signed Root CA certificate.
///
/// Because the root is self-signed, the issuer DN is set equal to the
/// subject DN — only `subject_cn` and `subject_sn` are needed.
///
/// All CN/SN strings are validated and padded internally by the builder.
pub struct RootCertParams<'a> {
    /// Uncompressed P-384 public key (97 bytes: `0x04 || x || y`).
    pub public_key: &'a [u8; 97],
    /// Serial number (20 bytes, first byte must have bit 7 = 0 for positive DER INTEGER).
    pub serial_number: &'a [u8; 20],
    /// NOT_BEFORE as GeneralizedTime ASCII (15 bytes, e.g. `b"20250101000000Z"`).
    pub not_before: &'a [u8; 15],
    /// NOT_AFTER as GeneralizedTime ASCII (15 bytes).
    pub not_after: &'a [u8; 15],
    /// Subject (and issuer) Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub subject_cn: &'a str,
    /// Subject (and issuer) serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub subject_sn: &'a str,
    /// Subject Key Identifier (SHA-1 of the public key, 20 bytes).
    pub subject_key_id: &'a [u8; 20],
}

/// Parameters for building an Intermediate CA certificate.
///
/// All CN/SN strings are validated and padded internally by the builder.
pub struct IntermediateCertParams<'a> {
    /// Uncompressed P-384 public key (97 bytes: `0x04 || x || y`).
    pub public_key: &'a [u8; 97],
    /// Serial number (20 bytes, first byte must have bit 7 = 0 for positive DER INTEGER).
    pub serial_number: &'a [u8; 20],
    /// NOT_BEFORE as GeneralizedTime ASCII (15 bytes, e.g. `b"20250101000000Z"`).
    pub not_before: &'a [u8; 15],
    /// NOT_AFTER as GeneralizedTime ASCII (15 bytes).
    pub not_after: &'a [u8; 15],
    /// Subject Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub subject_cn: &'a str,
    /// Subject serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub subject_sn: &'a str,
    /// Issuer Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub issuer_cn: &'a str,
    /// Issuer serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub issuer_sn: &'a str,
    /// Subject Key Identifier (SHA-1 of the subject's public key, 20 bytes).
    pub subject_key_id: &'a [u8; 20],
    /// Authority Key Identifier (SHA-1 of the issuer's public key, 20 bytes).
    pub authority_key_id: &'a [u8; 20],
    /// Path length constraint for BasicConstraints extension (0–127).
    pub path_len: u8,
}

/// Parameters for building a Leaf (end-entity) certificate.
///
/// All CN/SN strings are validated and padded internally by the builder.
pub struct LeafCertParams<'a> {
    /// Uncompressed P-384 public key (97 bytes: `0x04 || x || y`).
    pub public_key: &'a [u8; 97],
    /// Serial number (20 bytes, first byte must have bit 7 = 0 for positive DER INTEGER).
    pub serial_number: &'a [u8; 20],
    /// NOT_BEFORE as GeneralizedTime ASCII (15 bytes, e.g. `b"20250101000000Z"`).
    pub not_before: &'a [u8; 15],
    /// NOT_AFTER as GeneralizedTime ASCII (15 bytes).
    pub not_after: &'a [u8; 15],
    /// Subject Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub subject_cn: &'a str,
    /// Subject serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub subject_sn: &'a str,
    /// Issuer Common Name (ASCII, max [`CN_LEN`] bytes; space-padded internally).
    pub issuer_cn: &'a str,
    /// Issuer serialNumber (max [`SN_LEN`] bytes; zero-padded internally).
    pub issuer_sn: &'a str,
    /// Subject Key Identifier (SHA-1 of the subject's public key, 20 bytes).
    pub subject_key_id: &'a [u8; 20],
    /// Authority Key Identifier (SHA-1 of the issuer's public key, 20 bytes).
    pub authority_key_id: &'a [u8; 20],
    /// Key Usage extension flags (see [`KeyUsage`] named constants).
    pub key_usage: KeyUsage,
}

/// Pad an ASCII CN string to exactly [`CN_LEN`] bytes with trailing spaces.
///
/// # Arguments
/// * `cn` — The Common Name string (must be ASCII, at most [`CN_LEN`] bytes).
///
/// # Returns
/// `Some([u8; CN_LEN])` with the padded result, or `None` if the input is
/// too long or contains non-ASCII bytes.
pub fn pad_cn(cn: &str) -> Option<[u8; CN_LEN]> {
    if cn.len() > CN_LEN || !cn.is_ascii() {
        return None;
    }
    let mut result = [b' '; CN_LEN];
    result[..cn.len()].copy_from_slice(cn.as_bytes());
    Some(result)
}

/// Pad a hex SN string to exactly [`SN_LEN`] bytes with trailing `'0'` chars.
///
/// # Arguments
/// * `sn` — The serialNumber string (must be ASCII, at most [`SN_LEN`] bytes).
///
/// # Returns
/// `Some([u8; SN_LEN])` with the padded result, or `None` if the input is
/// too long or contains non-ASCII bytes.
pub fn pad_sn(sn: &str) -> Option<[u8; SN_LEN]> {
    if sn.len() > SN_LEN || !sn.is_ascii() {
        return None;
    }
    let mut result = [b'0'; SN_LEN];
    result[..sn.len()].copy_from_slice(sn.as_bytes());
    Some(result)
}

/// Build a self-signed Root CA certificate from the [`root_cert`](super::root_cert) template.
///
/// The issuer DN is set equal to the subject DN (self-signed).
///
/// # Arguments
/// * `params` — Certificate field values (see [`RootCertParams`]).
/// * `sig_r` — ECDSA-P384 signature `r` component (48 bytes, big-endian).
/// * `sig_s` — ECDSA-P384 signature `s` component (48 bytes, big-endian).
/// * `out` — Output buffer for the DER-encoded certificate.
///
/// # Returns
/// `Some(n)` where `n` is the number of DER bytes written to `out`, or
/// `None` if validation fails or the buffer is too small.
pub fn build_root_cert(
    params: &RootCertParams<'_>,
    sig_r: &[u8; 48],
    sig_s: &[u8; 48],
    out: &mut [u8],
) -> Option<usize> {
    use super::root_cert::*;

    validate_serial(params.serial_number)?;

    let subject_cn = pad_cn(params.subject_cn)?;
    let subject_sn = pad_sn(params.subject_sn)?;

    let mut tbs = TBS_TEMPLATE;
    patch(&mut tbs, PUBLIC_KEY_OFFSET, params.public_key);
    patch(&mut tbs, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch(&mut tbs, NOT_BEFORE_OFFSET, params.not_before);
    patch(&mut tbs, NOT_AFTER_OFFSET, params.not_after);
    patch(&mut tbs, ISSUER_CN_OFFSET, &subject_cn); // self-signed
    patch(&mut tbs, ISSUER_SN_OFFSET, &subject_sn); // self-signed
    patch(&mut tbs, SUBJECT_CN_OFFSET, &subject_cn);
    patch(&mut tbs, SUBJECT_SN_OFFSET, &subject_sn);
    patch(&mut tbs, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);

    assemble_cert(&tbs, sig_r, sig_s, out)
}

/// Build an Intermediate CA certificate from the [`intermediate_cert`](super::intermediate_cert) template.
///
/// # Arguments
/// * `params` — Certificate field values (see [`IntermediateCertParams`]).
/// * `sig_r` — ECDSA-P384 signature `r` component (48 bytes, big-endian).
/// * `sig_s` — ECDSA-P384 signature `s` component (48 bytes, big-endian).
/// * `out` — Output buffer for the DER-encoded certificate.
///
/// # Returns
/// `Some(n)` where `n` is the number of DER bytes written to `out`, or
/// `None` if validation fails (bad serial, CN/SN, path_len > 127) or the
/// buffer is too small.
pub fn build_intermediate_cert(
    params: &IntermediateCertParams<'_>,
    sig_r: &[u8; 48],
    sig_s: &[u8; 48],
    out: &mut [u8],
) -> Option<usize> {
    use super::intermediate_cert::*;

    validate_serial(params.serial_number)?;
    if params.path_len > 127 {
        return None;
    }

    let subject_cn = pad_cn(params.subject_cn)?;
    let subject_sn = pad_sn(params.subject_sn)?;
    let issuer_cn = pad_cn(params.issuer_cn)?;
    let issuer_sn = pad_sn(params.issuer_sn)?;

    let mut tbs = TBS_TEMPLATE;
    patch(&mut tbs, PUBLIC_KEY_OFFSET, params.public_key);
    patch(&mut tbs, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch(&mut tbs, NOT_BEFORE_OFFSET, params.not_before);
    patch(&mut tbs, NOT_AFTER_OFFSET, params.not_after);
    patch(&mut tbs, ISSUER_CN_OFFSET, &issuer_cn);
    patch(&mut tbs, ISSUER_SN_OFFSET, &issuer_sn);
    patch(&mut tbs, SUBJECT_CN_OFFSET, &subject_cn);
    patch(&mut tbs, SUBJECT_SN_OFFSET, &subject_sn);
    patch(&mut tbs, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    patch(&mut tbs, AUTHORITY_KEY_ID_OFFSET, params.authority_key_id);
    tbs[PATH_LEN_OFFSET] = params.path_len;

    assemble_cert(&tbs, sig_r, sig_s, out)
}

/// Build a Leaf (end-entity) certificate from the [`leaf_cert`](super::leaf_cert) template.
///
/// # Arguments
/// * `params` — Certificate field values (see [`LeafCertParams`]).
/// * `sig_r` — ECDSA-P384 signature `r` component (48 bytes, big-endian).
/// * `sig_s` — ECDSA-P384 signature `s` component (48 bytes, big-endian).
/// * `out` — Output buffer for the DER-encoded certificate.
///
/// # Returns
/// `Some(n)` where `n` is the number of DER bytes written to `out`, or
/// `None` if validation fails or the buffer is too small.
pub fn build_leaf_cert(
    params: &LeafCertParams<'_>,
    sig_r: &[u8; 48],
    sig_s: &[u8; 48],
    out: &mut [u8],
) -> Option<usize> {
    use super::leaf_cert::*;

    validate_serial(params.serial_number)?;

    let subject_cn = pad_cn(params.subject_cn)?;
    let subject_sn = pad_sn(params.subject_sn)?;
    let issuer_cn = pad_cn(params.issuer_cn)?;
    let issuer_sn = pad_sn(params.issuer_sn)?;

    let mut tbs = TBS_TEMPLATE;
    patch(&mut tbs, PUBLIC_KEY_OFFSET, params.public_key);
    patch(&mut tbs, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch(&mut tbs, NOT_BEFORE_OFFSET, params.not_before);
    patch(&mut tbs, NOT_AFTER_OFFSET, params.not_after);
    patch(&mut tbs, ISSUER_CN_OFFSET, &issuer_cn);
    patch(&mut tbs, ISSUER_SN_OFFSET, &issuer_sn);
    patch(&mut tbs, SUBJECT_CN_OFFSET, &subject_cn);
    patch(&mut tbs, SUBJECT_SN_OFFSET, &subject_sn);
    patch(&mut tbs, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    patch(&mut tbs, AUTHORITY_KEY_ID_OFFSET, params.authority_key_id);
    patch(&mut tbs, KEY_USAGE_OFFSET, &params.key_usage.to_bytes());

    assemble_cert(&tbs, sig_r, sig_s, out)
}

/// Validate that a serial number is valid for DER encoding.
/// First byte must have bit 7 = 0 (positive integer).
fn validate_serial(serial: &[u8; 20]) -> Option<()> {
    if serial[0] & 0x80 != 0 {
        return None;
    }
    Some(())
}

/// Patch a field in the TBS template at the given offset.
fn patch(tbs: &mut [u8], offset: usize, value: &[u8]) {
    tbs[offset..offset + value.len()].copy_from_slice(value);
}

/// Assemble a complete DER-encoded certificate from TBS + signature.
///
/// Certificate ::= SEQUENCE {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING
/// }
fn assemble_cert(tbs: &[u8], sig_r: &[u8; 48], sig_s: &[u8; 48], out: &mut [u8]) -> Option<usize> {
    // Encode signature as DER BIT STRING
    let mut sig_buf = [0u8; MAX_ECDSA384_SIG_DER_LEN];
    let sig_len = der_helpers::encode_ecdsa_signature(&mut sig_buf, sig_r, sig_s)?;

    // Total content length: TBS + AlgId + Signature
    let content_len = tbs.len() + ECDSA_SHA384_ALG_ID.len() + sig_len;

    // Outer SEQUENCE header
    let header_len = 1 + der_helpers::der_length_size(content_len);
    let total_len = header_len + content_len;

    if out.len() < total_len {
        return None;
    }

    let mut pos = 0;

    // SEQUENCE tag
    out[pos] = 0x30;
    pos += 1;
    pos += der_helpers::encode_der_length(&mut out[pos..], content_len)?;

    // TBS
    out[pos..pos + tbs.len()].copy_from_slice(tbs);
    pos += tbs.len();

    // AlgorithmIdentifier
    out[pos..pos + ECDSA_SHA384_ALG_ID.len()].copy_from_slice(&ECDSA_SHA384_ALG_ID);
    pos += ECDSA_SHA384_ALG_ID.len();

    // Signature BIT STRING
    out[pos..pos + sig_len].copy_from_slice(&sig_buf[..sig_len]);
    pos += sig_len;

    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_cn_basic() {
        let result = pad_cn("Test CA").expect("valid CN");
        assert_eq!(&result[..7], b"Test CA");
        assert!(result[7..].iter().all(|&b| b == b' '));
    }

    #[test]
    fn test_pad_cn_exact_len() {
        let name = "A".repeat(CN_LEN);
        let result = pad_cn(&name).expect("valid CN");
        assert_eq!(&result[..], name.as_bytes());
    }

    #[test]
    fn test_pad_cn_too_long() {
        let name = "A".repeat(CN_LEN + 1);
        assert!(pad_cn(&name).is_none());
    }

    #[test]
    fn test_pad_cn_non_ascii() {
        assert!(pad_cn("Ünîcödé").is_none());
    }

    #[test]
    fn test_pad_sn_basic() {
        let result = pad_sn("ABCDEF01").expect("valid SN");
        assert_eq!(&result[..8], b"ABCDEF01");
        assert!(result[8..].iter().all(|&b| b == b'0'));
    }

    #[test]
    fn test_pad_sn_too_long() {
        let name = "A".repeat(SN_LEN + 1);
        assert!(pad_sn(&name).is_none());
    }
}
