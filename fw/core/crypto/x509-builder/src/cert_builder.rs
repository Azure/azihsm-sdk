// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime certificate builder.
//!
//! Mirrors the surface shape of
//! [`azihsm_fw_core_crypto_key_report::key_report`]: async,
//! `pal + io + alloc` plumbing, query/copy on `Option<&mut [u8]>`.
//!
//! Patches variable fields into pre-generated TBS (To-Be-Signed)
//! templates ([`crate::root_cert`], [`crate::leaf_cert`]), drives
//! SHA-384 + ECDSA-P384 signing through the PAL, and assembles
//! complete DER-encoded X.509 certificates in the caller's output
//! buffer.
//!
//! CN and SN strings are validated and padded internally — callers
//! pass plain `&str` values.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use bitfield_struct::bitfield;

use crate::csr_builder::PRIV_KEY_LEN;
use crate::csr_builder::SIGNATURE_LEN;
use crate::der_helpers::ECDSA_SHA384_ALG_ID;
use crate::der_helpers::MAX_ECDSA384_SIG_DER_LEN;
use crate::der_helpers::{self};

/// Length of Common Name field (space-padded ASCII, 32 bytes).
pub const CN_LEN: usize = 32;

/// Length of DN serialNumber field (hex-encoded, 64 bytes).
pub const SN_LEN: usize = 64;

/// SHA-384 digest length in bytes.
const SHA384_DIGEST_LEN: usize = 48;

/// Upper bound on the TBS-template scratch buffer used internally.
/// Sized for any single P-384 cert template in this crate.
const MAX_TBS_LEN: usize = 1024;

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
/// Returns `None` if the input is too long or contains non-ASCII bytes.
pub fn pad_cn(cn: &str) -> Option<[u8; CN_LEN]> {
    if cn.len() > CN_LEN || !cn.is_ascii() {
        return None;
    }
    let mut result = [b' '; CN_LEN];
    result[..cn.len()].copy_from_slice(cn.as_bytes());
    Some(result)
}

/// Pad an ASCII SN string to exactly [`SN_LEN`] bytes with trailing `'0'` chars.
///
/// Returns `None` if the input is too long or contains characters that
/// are not ASCII hex digits (`0..=9 | a..=f | A..=F`).
pub fn pad_sn(sn: &str) -> Option<[u8; SN_LEN]> {
    if sn.len() > SN_LEN || !sn.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut result = [b'0'; SN_LEN];
    result[..sn.len()].copy_from_slice(sn.as_bytes());
    Some(result)
}

/// Build a self-signed Root CA certificate from the
/// [`root_cert`](crate::root_cert) template.
///
/// See the crate-level docs for the shared `(pal, io, alloc, params,
/// priv_key, out)` contract and query/copy semantics.
pub async fn build_root_cert<'a>(
    pal: &(impl HsmCrypto + HsmAlloc + 'a),
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &RootCertParams<'_>,
    priv_key: &DmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    use crate::root_cert::TBS_TEMPLATE;
    let tbs_len = TBS_TEMPLATE.len();
    preflight(priv_key, tbs_len)?;
    let max_size = max_signed_size(tbs_len);
    let Some(out) = out else {
        return Ok(max_size);
    };
    if out.len() < max_size {
        return Err(HsmError::InvalidArg);
    }
    let (tbs_dma, sig_dma) = sign(pal, io, alloc, priv_key, tbs_len, |tbs| {
        patch_root_tbs(tbs, params)
    })
    .await?;
    assemble_signed(out, tbs_dma, sig_dma)
}

/// Build a Leaf (end-entity) certificate from the
/// [`leaf_cert`](crate::leaf_cert) template.
///
/// See the crate-level docs for the shared `(pal, io, alloc, params,
/// priv_key, out)` contract and query/copy semantics.
pub async fn build_leaf_cert<'a>(
    pal: &(impl HsmCrypto + HsmAlloc + 'a),
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    params: &LeafCertParams<'_>,
    priv_key: &DmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    use crate::leaf_cert::TBS_TEMPLATE;
    let tbs_len = TBS_TEMPLATE.len();
    preflight(priv_key, tbs_len)?;
    let max_size = max_signed_size(tbs_len);
    let Some(out) = out else {
        return Ok(max_size);
    };
    if out.len() < max_size {
        return Err(HsmError::InvalidArg);
    }
    let (tbs_dma, sig_dma) = sign(pal, io, alloc, priv_key, tbs_len, |tbs| {
        patch_leaf_tbs(tbs, params)
    })
    .await?;
    assemble_signed(out, tbs_dma, sig_dma)
}

/// Common input validation shared by every builder.
fn preflight(priv_key: &DmaBuf, tbs_len: usize) -> HsmResult<()> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    if tbs_len > MAX_TBS_LEN {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Allocate the TBS scratch buffer, hand it to the caller's `patch`
/// closure, run `SHA-384 → ECDSA-P384 sign` against the supplied
/// private key, and return the DMA buffers holding the patched TBS
/// and the LE-by-half signature.
async fn sign<'a, F>(
    pal: &(impl HsmCrypto + HsmAlloc + 'a),
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    priv_key: &DmaBuf,
    tbs_len: usize,
    patch: F,
) -> HsmResult<(&'a mut DmaBuf, &'a mut DmaBuf)>
where
    F: FnOnce(&mut [u8]) -> HsmResult<()>,
{
    let tbs_dma = alloc.dma_alloc(tbs_len)?;
    patch(tbs_dma)?;

    let digest_dma = alloc.dma_alloc(SHA384_DIGEST_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, tbs_dma, digest_dma, false)
        .await?;

    let sig_dma = alloc.dma_alloc(SIGNATURE_LEN)?;
    pal.ecc_sign(io, HsmEccCurve::P384, priv_key, digest_dma, sig_dma)
        .await?;

    Ok((tbs_dma, sig_dma))
}

/// Worst-case `Certificate ::= SEQUENCE { TBS, AlgId, BIT STRING sig }`
/// size for a TBS of the given length.
fn max_signed_size(tbs_len: usize) -> usize {
    let max_content = tbs_len + ECDSA_SHA384_ALG_ID.len() + MAX_ECDSA384_SIG_DER_LEN;
    1 + der_helpers::der_length_size(max_content) + max_content
}

fn patch_root_tbs(out: &mut [u8], params: &RootCertParams<'_>) -> HsmResult<()> {
    use crate::root_cert::*;
    validate_serial(params.serial_number)?;
    let subject_cn = pad_cn(params.subject_cn).ok_or(HsmError::InvalidArg)?;
    let subject_sn = pad_sn(params.subject_sn).ok_or(HsmError::InvalidArg)?;

    out[..TBS_TEMPLATE.len()].copy_from_slice(&TBS_TEMPLATE);
    patch_field(out, PUBLIC_KEY_OFFSET, params.public_key);
    patch_field(out, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch_field(out, NOT_BEFORE_OFFSET, params.not_before);
    patch_field(out, NOT_AFTER_OFFSET, params.not_after);
    patch_field(out, ISSUER_CN_OFFSET, &subject_cn);
    patch_field(out, ISSUER_SN_OFFSET, &subject_sn);
    patch_field(out, SUBJECT_CN_OFFSET, &subject_cn);
    patch_field(out, SUBJECT_SN_OFFSET, &subject_sn);
    patch_field(out, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    Ok(())
}

fn patch_leaf_tbs(out: &mut [u8], params: &LeafCertParams<'_>) -> HsmResult<()> {
    use crate::leaf_cert::*;
    validate_serial(params.serial_number)?;
    if params.key_usage.unused_bits() > 7 {
        return Err(HsmError::InvalidArg);
    }
    let subject_cn = pad_cn(params.subject_cn).ok_or(HsmError::InvalidArg)?;
    let subject_sn = pad_sn(params.subject_sn).ok_or(HsmError::InvalidArg)?;
    let issuer_cn = pad_cn(params.issuer_cn).ok_or(HsmError::InvalidArg)?;
    let issuer_sn = pad_sn(params.issuer_sn).ok_or(HsmError::InvalidArg)?;

    out[..TBS_TEMPLATE.len()].copy_from_slice(&TBS_TEMPLATE);
    patch_field(out, PUBLIC_KEY_OFFSET, params.public_key);
    patch_field(out, SERIAL_NUMBER_OFFSET, params.serial_number);
    patch_field(out, NOT_BEFORE_OFFSET, params.not_before);
    patch_field(out, NOT_AFTER_OFFSET, params.not_after);
    patch_field(out, ISSUER_CN_OFFSET, &issuer_cn);
    patch_field(out, ISSUER_SN_OFFSET, &issuer_sn);
    patch_field(out, SUBJECT_CN_OFFSET, &subject_cn);
    patch_field(out, SUBJECT_SN_OFFSET, &subject_sn);
    patch_field(out, SUBJECT_KEY_ID_OFFSET, params.subject_key_id);
    patch_field(out, AUTHORITY_KEY_ID_OFFSET, params.authority_key_id);
    patch_field(out, KEY_USAGE_OFFSET, &params.key_usage.to_bytes());
    Ok(())
}

fn validate_serial(serial: &[u8; 20]) -> HsmResult<()> {
    if serial[0] & 0x80 != 0 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

fn patch_field(tbs: &mut [u8], offset: usize, value: &[u8]) {
    tbs[offset..offset + value.len()].copy_from_slice(value);
}

/// Assemble `SEQUENCE { TBS, AlgId, BIT STRING sig }` into `out`.
/// PAL signature is `r || s` LE-by-half; convert each half to BE for
/// the DER INTEGERs.
fn assemble_signed(out: &mut [u8], tbs: &DmaBuf, sig_le: &DmaBuf) -> HsmResult<usize> {
    let (sig_r_be, sig_s_be) = sig_le_halves_to_be(sig_le)?;

    let mut sig_buf = [0u8; MAX_ECDSA384_SIG_DER_LEN];
    let sig_len = der_helpers::encode_ecdsa_signature(&mut sig_buf, &sig_r_be, &sig_s_be)
        .ok_or(HsmError::InternalError)?;

    let tbs_bytes: &[u8] = tbs;
    let content_len = tbs_bytes.len() + ECDSA_SHA384_ALG_ID.len() + sig_len;
    let header_len = 1 + der_helpers::der_length_size(content_len);
    let total_len = header_len + content_len;
    if out.len() < total_len {
        return Err(HsmError::InvalidArg);
    }

    let mut pos = 0;
    out[pos] = 0x30;
    pos += 1;
    pos += der_helpers::encode_der_length(&mut out[pos..], content_len)
        .ok_or(HsmError::InternalError)?;

    out[pos..pos + tbs_bytes.len()].copy_from_slice(tbs_bytes);
    pos += tbs_bytes.len();

    out[pos..pos + ECDSA_SHA384_ALG_ID.len()].copy_from_slice(&ECDSA_SHA384_ALG_ID);
    pos += ECDSA_SHA384_ALG_ID.len();

    out[pos..pos + sig_len].copy_from_slice(&sig_buf[..sig_len]);
    pos += sig_len;

    Ok(pos)
}

fn sig_le_halves_to_be(sig_le: &DmaBuf) -> HsmResult<([u8; 48], [u8; 48])> {
    let bytes: &[u8] = sig_le;
    if bytes.len() != SIGNATURE_LEN {
        return Err(HsmError::InternalError);
    }
    let half = SIGNATURE_LEN / 2;
    let mut r = [0u8; 48];
    let mut s = [0u8; 48];
    for i in 0..half {
        r[i] = bytes[half - 1 - i];
        s[i] = bytes[SIGNATURE_LEN - 1 - i];
    }
    Ok((r, s))
}
