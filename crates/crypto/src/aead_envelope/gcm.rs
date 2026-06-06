// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM seal / open over the AEAD-envelope wire format.
//!
//! Delegates to the platform `AesGcmAlgo` for the actual
//! encrypt/decrypt; this module is responsible only for the
//! envelope assembly and slot management.

use super::alg::AeadAlg;
use super::envelope::AeadEnvelope;
use super::envelope::region_offsets;
use super::format::HEADER_LEN;
use super::format::Header;
use super::format::write_header;
use crate::AesGcmAlgo;
use crate::AesKey;
use crate::CryptoError;
use crate::DecryptOp;
use crate::EncryptOp;
use crate::Key;

/// AES-256-GCM seal. See [`super::seal`] for the public entry
/// point.
///
/// Assumes `alg == AeadAlg::AesGcm256`; the dispatcher in
/// [`super`] is the only caller and guarantees this.
pub(crate) fn seal_gcm(
    alg: AeadAlg,
    key: &AesKey,
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    buf: &mut [u8],
) -> Result<usize, CryptoError> {
    if key.size() != alg.key_len() {
        return Err(CryptoError::GcmInvalidKeySize);
    }
    if iv.len() != alg.iv_len() {
        return Err(CryptoError::GcmInvalidIvLength);
    }
    let envelope_len = alg.envelope_len(pt.len(), aad.len());
    if buf.len() < envelope_len {
        return Err(CryptoError::GcmBufferTooSmall);
    }

    // Header (also revalidates aad_len against alg.aad_granularity()).
    write_header(buf, alg, aad.len())?;

    // Region offsets within `buf`.
    let iv_off = HEADER_LEN;
    let aad_off = iv_off + alg.iv_len();
    let data_off = aad_off + aad.len();
    let tag_off = data_off + pt.len();

    // Assemble header || IV || AAD into `buf`.
    buf[iv_off..aad_off].copy_from_slice(iv);
    buf[aad_off..data_off].copy_from_slice(aad);

    // Encrypt plaintext into the data slot.
    let mut algo = AesGcmAlgo::for_encrypt(iv, Some(aad))?;
    let (data_slot, tag_slot) = buf[data_off..tag_off + alg.tag_len()].split_at_mut(pt.len());
    let n = algo.encrypt(key, pt, Some(data_slot))?;
    debug_assert_eq!(
        n,
        pt.len(),
        "GCM encrypt wrote {n} bytes, expected {}",
        pt.len()
    );

    // Copy authentication tag into the tag slot.
    let tag = algo.tag();
    debug_assert_eq!(tag.len(), alg.tag_len());
    tag_slot.copy_from_slice(tag);

    Ok(envelope_len)
}

/// AES-256-GCM open. See [`super::open`] for the public entry
/// point.
///
/// `header` is the already-parsed envelope header passed in from
/// the dispatcher to avoid double-parsing.
pub(crate) fn open_gcm<'a>(
    key: &AesKey,
    buf: &'a mut [u8],
    header: Header,
) -> Result<AeadEnvelope<'a>, CryptoError> {
    if key.size() != header.alg.key_len() {
        return Err(CryptoError::GcmInvalidKeySize);
    }
    let total_len = buf.len();
    let (iv_off, aad_off, payload_off, tag_off) = region_offsets(header, total_len)?;

    // Build a copy of the ciphertext we need as `&[u8]` input
    // (openssl `cipher_update` does not promise correctness on
    // overlapping in/out slices, and the convenience APIs we use
    // here take separate buffers anyway).
    let iv = buf[iv_off..aad_off].to_vec();
    let aad = buf[aad_off..payload_off].to_vec();
    let tag = buf[tag_off..total_len].to_vec();
    let ct = buf[payload_off..tag_off].to_vec();

    let mut algo = AesGcmAlgo::for_decrypt(&iv, &tag, Some(&aad))?;
    let n = algo.decrypt(key, &ct, Some(&mut buf[payload_off..tag_off]))?;
    debug_assert_eq!(
        n,
        ct.len(),
        "GCM decrypt wrote {n} bytes, expected {}",
        ct.len()
    );

    // Re-borrow `buf` immutably to construct the view.
    let view: &'a [u8] = &*buf;
    Ok(AeadEnvelope {
        alg: header.alg,
        iv: &view[iv_off..aad_off],
        aad: &view[aad_off..payload_off],
        payload: &view[payload_off..tag_off],
        tag: &view[tag_off..total_len],
    })
}
