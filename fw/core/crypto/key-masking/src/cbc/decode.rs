// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! In-place AES-CBC-256 + HMAC-SHA-384 unmasking.
//!
//! Authenticate-then-decrypt: verify the trailing HMAC tag against the
//! authenticated region first, then AES-CBC decrypt the ciphertext in
//! place.  Plaintext lands where the ciphertext was (plaintext length is
//! always `<=` ciphertext length, since AES-CBC zero-pads to the next
//! block).  The caller recovers the exact plaintext length from the
//! metadata's higher-level format (e.g. `key_length`).

use azihsm_fw_hsm_pal_traits::AesOp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmHmac;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::cbc::format::MaskedKeyAesHeader;
use crate::cbc::format::MaskedKeyHeader;
use crate::cbc::format::AES_CBC_256_KEY_SIZE;
use crate::cbc::format::AES_CBC_IV_SIZE;
use crate::cbc::format::MASKING_KEY_AES_CBC_256_HMAC_384_LEN;

/// Layout of a successfully unmasked blob.
///
/// All offsets are relative to the start of the `blob` passed into
/// [`unmask`].  The function requires `blob.len()` to
/// equal the on-wire length, so `blob.len()` itself is the total
/// authenticated length — no separate field is returned for it.
#[derive(Debug, Clone, Copy)]
pub struct UnmaskLayout {
    /// Byte offset of the (cleartext, MAC-covered) metadata region.
    pub metadata_offset: usize,
    /// Length of the metadata region in bytes.
    pub metadata_len: usize,
    /// Byte offset of the decrypted plaintext (formerly the ciphertext
    /// slot).
    pub plaintext_offset: usize,
    /// Upper bound on plaintext length: equals the on-wire ciphertext
    /// length after AES-CBC zero-padding.
    ///
    /// AES-CBC pads the plaintext to a multiple of the AES block size
    /// (16 B).  The true plaintext length is the higher-level format's
    /// business (e.g. an explicit `key_length` field inside `metadata`)
    /// and is **always** `<=` `plaintext_max_len`.
    pub plaintext_max_len: usize,
}

/// In-place authenticate-and-decrypt a `MaskedKey` AES-CBC-256 +
/// HMAC-SHA-384 blob.
///
/// On success, `blob[plaintext_offset..plaintext_offset + plaintext_max_len]`
/// contains the decrypted plaintext (with up to 15 trailing zero pad
/// bytes); `blob[metadata_offset..metadata_offset + metadata_len]`
/// retains the original metadata.  All other slots (outer header, AES
/// header, IV, HMAC tag) are unchanged.
///
/// # Type parameters
///
/// * `P` — any PAL providing AES and HMAC.
///
/// # Parameters
///
/// * `pal` — PAL providing AES and HMAC.
/// * `io` — caller's I/O context (per-IO scope).
/// * `masking_key` — 80-byte DMA buffer: 32-byte AES-256 key (low
///   half) followed by 48-byte HMAC-SHA-384 key (high half).  Used
///   as sub-views; never copied.
/// * `blob` — DMA buffer holding the masked blob.  Its length **must**
///   exactly equal the on-wire blob size (as encoded in the headers).
///   On success the ciphertext slot is overwritten with the decrypted
///   plaintext.
///
/// # Returns
///
/// * `Ok(layout)` — offsets and lengths of the in-place decrypted
///   regions.  Caller uses `metadata` to discover the exact plaintext
///   length within `plaintext_max_len`.
/// * `Err(HsmError::InvalidArg)` — `masking_key` is the wrong length.
/// * `Err(HsmError::MaskedKeyDecodeFailed)` — `blob.len()` does not
///   match the on-wire length declared by its headers, its headers are
///   malformed, or the HMAC tag does not match.
/// * Any [`HsmError`] surfaced by the PAL HMAC or AES drivers.  On
///   AES-decrypt failure, the ciphertext slot is wiped before
///   returning so partial plaintext does not leak.
pub async fn unmask<P>(
    pal: &P,
    io: &impl HsmIo,
    masking_key: &DmaBuf,
    blob: &mut DmaBuf,
) -> HsmResult<UnmaskLayout>
where
    P: HsmAes + HsmHmac,
{
    if masking_key.len() != MASKING_KEY_AES_CBC_256_HMAC_384_LEN {
        return Err(HsmError::InvalidArg);
    }

    // Parse + validate headers (structural checks only; HMAC must still
    // pass before trusting any byte).
    MaskedKeyHeader::parse_cbc(blob)?;
    let hdr = MaskedKeyAesHeader::parse_cbc(&blob[MaskedKeyHeader::SIZE..])?;

    if blob.len() != hdr.total_len() {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    let iv_off = hdr.iv_offset();
    let meta_off = hdr.metadata_offset();
    let meta_len = hdr.metadata_len_bytes();
    let ct_off = hdr.ciphertext_offset();
    let ct_len = hdr.ciphertext_len();
    let tag_off = hdr.tag_offset();

    // HMAC-SHA-384 verify the tagged region; HMAC key = high 48 B of
    // `masking_key`.
    let hmac_ok = {
        let (tagged, tag) = blob.split_at(tag_off);
        let hmac_key = &masking_key[AES_CBC_256_KEY_SIZE..];
        pal.hmac_verify(io, HsmHashAlgo::Sha384, hmac_key, tagged, tag)
            .await?
    };
    if !hmac_ok {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    // AES-CBC-256 decrypt in place; split at `ct_off` to disjoin the IV
    // (immutable) and ciphertext (mutable) sub-views.  AES key = low
    // 32 B of `masking_key`.
    let aes_result = {
        let (front, back) = blob.split_at_mut(ct_off);
        let iv = &front[iv_off..iv_off + AES_CBC_IV_SIZE];
        let ct = &mut back[..ct_len];
        let aes_key = &masking_key[..AES_CBC_256_KEY_SIZE];
        pal.aes_cbc_enc_dec_in_place(io, AesOp::Decrypt, aes_key, ct, iv, None)
            .await
    };
    if let Err(e) = aes_result {
        // May hold partial plaintext; wipe before surfacing the error.
        blob[ct_off..ct_off + ct_len].fill(0);
        return Err(e);
    }

    Ok(UnmaskLayout {
        metadata_offset: meta_off,
        metadata_len: meta_len,
        plaintext_offset: ct_off,
        plaintext_max_len: ct_len,
    })
}
