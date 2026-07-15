// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime CSR (PKCS#10) builder.
//!
//! Patches variable fields into a pre-generated CertificationRequestInfo
//! (TBS) template and assembles a complete DER-encoded PKCS#10
//! CertificationRequest with an ECDSA-P384 signature.
//!
//! # Usage
//!
//! 1. Fill a [`DeviceCsrParams`](super::csr_builder::DeviceCsrParams) with the public key, CN, and SN.
//! 2. Sign the patched TBS externally (template available as
//!    [`device_csr::TBS_TEMPLATE`](super::device_csr::TBS_TEMPLATE)).
//! 3. Call [`build_device_csr`](super::csr_builder::build_device_csr) with the params, raw ECDSA (r, s), and
//!    an output buffer.

use super::cert_builder::pad_cn;
use super::cert_builder::pad_sn;
use super::der_helpers::ECDSA_SHA384_ALG_ID;
use super::der_helpers::MAX_ECDSA384_SIG_DER_LEN;
use super::der_helpers::{self};

/// Parameters for building a device CSR (PKCS#10 CertificationRequest).
///
/// CN and SN strings are validated and padded internally by the builder.
pub struct DeviceCsrParams<'a> {
    /// Uncompressed P-384 public key (97 bytes: `0x04 || x || y`).
    pub public_key: &'a [u8; 97],
    /// Subject Common Name (ASCII, max [`CN_LEN`](super::cert_builder::CN_LEN) bytes;
    /// space-padded internally).
    pub subject_cn: &'a str,
    /// Subject serialNumber (max [`SN_LEN`](super::cert_builder::SN_LEN) bytes;
    /// zero-padded internally).
    pub subject_sn: &'a str,
}

/// Build a device CSR from the [`device_csr`](super::device_csr) template.
///
/// # Arguments
/// * `params` — CSR field values (see [`DeviceCsrParams`]).
/// * `sig_r` — ECDSA-P384 signature `r` component (48 bytes, big-endian).
/// * `sig_s` — ECDSA-P384 signature `s` component (48 bytes, big-endian).
/// * `out` — Output buffer for the DER-encoded CSR.
///
/// # Returns
/// `Some(n)` where `n` is the number of DER bytes written to `out`, or
/// `None` if CN/SN validation fails or the buffer is too small.
pub fn build_device_csr(
    params: &DeviceCsrParams<'_>,
    sig_r: &[u8; 48],
    sig_s: &[u8; 48],
    out: &mut [u8],
) -> Option<usize> {
    use super::device_csr::*;

    let mut tbs = TBS_TEMPLATE;
    let subject_cn = pad_cn(params.subject_cn)?;
    let subject_sn = pad_sn(params.subject_sn)?;
    patch(&mut tbs, PUBLIC_KEY_OFFSET, params.public_key);
    patch(&mut tbs, SUBJECT_CN_OFFSET, &subject_cn);
    patch(&mut tbs, SUBJECT_SN_OFFSET, &subject_sn);

    assemble_signed_data(&tbs, sig_r, sig_s, out)
}

/// Patch a field in the TBS template at the given offset.
fn patch(tbs: &mut [u8], offset: usize, value: &[u8]) {
    tbs[offset..offset + value.len()].copy_from_slice(value);
}

/// Assemble a complete DER-encoded CSR from CertificationRequestInfo + signature.
///
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo  CertificationRequestInfo,
///     signatureAlgorithm        AlgorithmIdentifier,
///     signature                 BIT STRING
/// }
fn assemble_signed_data(
    tbs: &[u8],
    sig_r: &[u8; 48],
    sig_s: &[u8; 48],
    out: &mut [u8],
) -> Option<usize> {
    let mut sig_buf = [0u8; MAX_ECDSA384_SIG_DER_LEN];
    let sig_len = der_helpers::encode_ecdsa_signature(&mut sig_buf, sig_r, sig_s)?;

    let content_len = tbs.len() + ECDSA_SHA384_ALG_ID.len() + sig_len;
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

    // TBS (CertificationRequestInfo)
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
