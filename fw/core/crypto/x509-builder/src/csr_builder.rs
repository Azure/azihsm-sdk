// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime CSR (PKCS#10) builder.
//!
//! Mirrors the surface shape of
//! [`azihsm_fw_core_crypto_key_report::key_report`]: async,
//! `pal + io + alloc` plumbing, query/copy on `Option<&mut [u8]>`.
//!
//! Patches variable fields into a pre-generated
//! CertificationRequestInfo (TBS) template, drives SHA-384 + ECDSA-P384
//! signing through the PAL, and assembles a complete DER-encoded
//! PKCS#10 CertificationRequest in the caller's output buffer.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::der_helpers::ECDSA_SHA384_ALG_ID;
use crate::der_helpers::MAX_ECDSA384_SIG_DER_LEN;
use crate::der_helpers::{self};

/// P-384 attestation private key length in bytes (raw scalar, LE wire format).
pub const PRIV_KEY_LEN: usize = 48;

/// ECDSA-P384 raw signature length (`r || s`).
pub const SIGNATURE_LEN: usize = 96;

/// SHA-384 digest length in bytes.
const SHA384_DIGEST_LEN: usize = 48;

/// Upper bound on the TBS-template scratch buffer used internally.
/// Sized for any single P-384 CSR template in this crate.
const MAX_TBS_LEN: usize = 512;

/// Parameters for building a CSR from any pre-generated TBS template.
///
/// All three variable fields (public key, subject CN, subject SN)
/// are pulled from the chosen template module's `*_OFFSET` / `*_LEN`
/// constants — callers are responsible for passing slices of exactly
/// the right length.  Mismatched lengths cause [`build_csr`] to
/// return [`HsmError::InvalidArg`].
pub struct CsrInput<'a> {
    /// Auto-generated TBS template bytes from the chosen template
    /// module (e.g. [`crate::csr::TBS_TEMPLATE`]).
    pub tbs_template: &'a [u8],

    /// Offset of the SubjectPublicKeyInfo public-key bytes within
    /// the TBS template (e.g. [`crate::csr::PUBLIC_KEY_OFFSET`]).
    pub public_key_offset: usize,

    /// Uncompressed P-384 public key (`0x04 || X || Y`, 97 bytes).
    pub public_key: &'a [u8],

    /// Offset of the subject Common Name string within the TBS
    /// template (e.g. [`crate::csr::SUBJECT_CN_OFFSET`]).
    pub subject_cn_offset: usize,

    /// Subject Common Name bytes, exactly the length pinned by the
    /// chosen template's `SUBJECT_CN_LEN` constant.  Padding is the
    /// caller's responsibility (see [`crate::padding::pad_cn_to`]).
    pub subject_cn: &'a [u8],

    /// Offset of the subject serialNumber string within the TBS
    /// template (e.g. [`crate::csr::SUBJECT_SN_OFFSET`]).
    pub subject_sn_offset: usize,

    /// Subject serialNumber bytes, exactly the length pinned by the
    /// chosen template's `SUBJECT_SN_LEN` constant.  Padding is the
    /// caller's responsibility (see [`crate::padding::pad_sn_to`]).
    pub subject_sn: &'a [u8],
}

impl CsrInput<'_> {
    /// Validate that each field-offset + field-length lies within
    /// `tbs_template`.  Returns [`HsmError::InvalidArg`] on overflow.
    fn validate(&self) -> HsmResult<()> {
        let n = self.tbs_template.len();
        let check = |off: usize, len: usize| -> HsmResult<()> {
            off.checked_add(len)
                .filter(|end| *end <= n)
                .map(|_| ())
                .ok_or(HsmError::InvalidArg)
        };
        check(self.public_key_offset, self.public_key.len())?;
        check(self.subject_cn_offset, self.subject_cn.len())?;
        check(self.subject_sn_offset, self.subject_sn.len())?;
        Ok(())
    }
}

/// Build a complete DER-encoded PKCS#10 CertificationRequest.
///
/// Mirrors [`azihsm_fw_core_crypto_key_report::key_report`] in shape:
///
/// * `pal`      — `HsmCrypto` (SHA-384 + ECDSA-P384) and `HsmAlloc`.
/// * `io`       — caller's IO scope.
/// * `alloc`    — scoped allocator for internal DMA scratch.
/// * `input`    — TBS template + variable field values
///   (see [`CsrInput`]).
/// * `priv_key` — P-384 signing key (raw scalar, LE wire format),
///   exactly [`PRIV_KEY_LEN`] bytes, supplied as a [`DmaBuf`] so it
///   can be handed straight to
///   [`HsmEcc::ecc_sign`](azihsm_fw_hsm_pal_traits::HsmEcc::ecc_sign).
/// * `out`      — output buffer.  `None` runs in query mode and
///   returns the worst-case upper-bound size without touching the
///   PAL.  `Some(buf)` writes the complete DER-encoded CSR into
///   `buf[..returned]`.
///
/// # Returns
///
/// * `Ok(size)` — worst-case upper bound (query) or actual bytes
///   written (copy).  The copy value may be 1–2 bytes shorter than
///   the query value depending on whether the signature's `r` / `s`
///   integers needed DER sign-bit padding.
/// * `Err(HsmError::InvalidArg)` — input validation failed, the TBS
///   template exceeds the internal scratch bound, or `buf.len()`
///   would not hold the worst-case output.
/// * Other [`HsmError`] values propagated from the PAL.
pub async fn build_csr<'a>(
    pal: &(impl HsmCrypto + HsmAlloc + 'a),
    io: &impl HsmIo,
    alloc: &'a impl HsmScopedAlloc,
    input: &CsrInput<'_>,
    priv_key: &DmaBuf,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    if priv_key.len() != PRIV_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    input.validate()?;
    if input.tbs_template.len() > MAX_TBS_LEN {
        return Err(HsmError::InvalidArg);
    }

    let max_size = max_signed_size(input.tbs_template.len());

    let Some(out) = out else {
        return Ok(max_size);
    };
    if out.len() < max_size {
        return Err(HsmError::InvalidArg);
    }

    // 1. Patch TBS into DMA scratch.
    let tbs_len = input.tbs_template.len();
    let tbs_dma = alloc.dma_alloc(tbs_len)?;
    patch_tbs(tbs_dma, input)?;

    // 2. SHA-384 digest of TBS.
    let digest_dma = alloc.dma_alloc(SHA384_DIGEST_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, tbs_dma, digest_dma, false)
        .await?;

    // 3. ECDSA-P384 sign — output is `r || s` in LE-by-half wire format.
    let sig_dma = alloc.dma_alloc(SIGNATURE_LEN)?;
    pal.ecc_sign(io, HsmEccCurve::P384, priv_key, digest_dma, sig_dma)
        .await?;

    // 4. Assemble the final DER document into `out`.
    let n = assemble_signed(out, tbs_dma, sig_dma)?;
    Ok(n)
}

/// Worst-case PKCS#10 `CertificationRequest ::= SEQUENCE { TBS, AlgId, BIT STRING sig }`
/// size for a TBS of the given length.
fn max_signed_size(tbs_len: usize) -> usize {
    let max_content = tbs_len + ECDSA_SHA384_ALG_ID.len() + MAX_ECDSA384_SIG_DER_LEN;
    1 + der_helpers::der_length_size(max_content) + max_content
}

/// Copy `input.tbs_template` into `dst` and patch the three variable
/// fields in place.  Validates that every patched range stays within
/// the buffer (`CsrInput::validate` has already enforced this; this
/// is a belt-and-suspenders bounds check on the destination slice).
fn patch_tbs(dst: &mut [u8], input: &CsrInput<'_>) -> HsmResult<()> {
    let n = input.tbs_template.len();
    if dst.len() < n {
        return Err(HsmError::InternalError);
    }
    dst[..n].copy_from_slice(input.tbs_template);
    patch_field(&mut dst[..n], input.public_key_offset, input.public_key)?;
    patch_field(&mut dst[..n], input.subject_cn_offset, input.subject_cn)?;
    patch_field(&mut dst[..n], input.subject_sn_offset, input.subject_sn)?;
    Ok(())
}

/// Patch a contiguous range of `tbs` starting at `offset`.
fn patch_field(tbs: &mut [u8], offset: usize, value: &[u8]) -> HsmResult<()> {
    let end = offset
        .checked_add(value.len())
        .ok_or(HsmError::InternalError)?;
    if end > tbs.len() {
        return Err(HsmError::InternalError);
    }
    tbs[offset..end].copy_from_slice(value);
    Ok(())
}

/// Assemble PKCS#10 `CertificationRequest ::= SEQUENCE { TBS, AlgId, BIT STRING sig }`
/// into `out`.  The PAL-returned signature is in `r || s` LE-by-half
/// wire format and is converted to big-endian halves for DER
/// INTEGER encoding.
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
    out[pos] = 0x30; // SEQUENCE
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

/// Convert the PAL ECDSA-P384 wire format (`r || s`, each 48 B in
/// little-endian byte order) into the big-endian byte halves required
/// for DER INTEGER encoding.
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
