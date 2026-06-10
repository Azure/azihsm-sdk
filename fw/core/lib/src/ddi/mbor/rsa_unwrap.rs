// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RsaUnwrap command handler.
//!
//! Takes a wrapped key blob — RSA-OAEP-encrypted AES key wrap key
//! (KEK) followed by an AES-KWP-wrapped payload — and imports the
//! contained key into the partition vault.
//!
//! Wire-format blob layout (RFC-style):
//!
//! ```text
//! [ 0 .. modulus_len ) = RSA-OAEP-encrypted AES KEK
//! [ modulus_len ..   ) = AES-KWP-wrapped payload (the actual key)
//! ```
//!
//! The unwrap private key is the partition's
//! [`GetUnwrappingKey`](super::get_unwrapping_key) RSA key (currently
//! always RSA-2048 → 256 B modulus, but the handler derives the
//! actual modulus size from the vault kind so larger unwrap keys
//! would Just Work).  The host wraps with that public key using OAEP
//! over a fresh AES-256 KEK, then
//! AES-KWP-wraps the target key with the KEK.
//!
//! Once the payload is recovered, the per-key-class import paths
//! ([`import_aes`], [`import_rsa`], [`import_ecc`]) tag the vault
//! entry with the right kind + attrs and build the response.  Bulk
//! AES variants and other key classes return
//! [`HsmError::UnsupportedCmd`] until dedicated import modules are
//! added.
//!
//! `masked_key` is emitted as an empty placeholder, matching the
//! convention of the other handlers until the masking infrastructure
//! lands.

mod import_aes;
mod import_ecc;
mod import_rsa;

use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapReq;
use azihsm_fw_ddi_mbor_types::DdiKeyClass;
use azihsm_fw_ddi_mbor_types::DdiRsaCryptoPadding;

use super::*;

/// Handle `DdiRsaUnwrapCmd`.
pub(crate) async fn rsa_unwrap<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiRsaUnwrapReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Validate OAEP — the only padding scheme RsaUnwrap supports.
    if body.wrapped_blob_padding != DdiRsaCryptoPadding::Oaep {
        return Err(HsmError::InvalidArg);
    }
    let hash_algo = super::from_ddi::hash(body.wrapped_blob_hash_algorithm)?;

    // Look up the unwrap key and verify it's the partition's
    // GetUnwrappingKey-issued key — comparing the supplied id to the
    // cached `part_unwrapping_key_id` prevents the host from
    // accidentally (or maliciously) directing the unwrap at any
    // other vault entry that happens to carry `unwrap = true`.
    let unwrap_key_id = HsmKeyId::from(body.key_id);
    let cached = pal
        .part_unwrapping_key_id(io)?
        .ok_or(HsmError::RsaUnwrapInvalidRequest)?;
    if unwrap_key_id != cached {
        return Err(HsmError::RsaUnwrapInvalidRequest);
    }
    let rsa_key_size = super::from_pal::rsa_key(pal.vault_key_kind(io, unwrap_key_id)?)?;
    if !pal.vault_key_attrs(io, unwrap_key_id)?.unwrap() {
        return Err(HsmError::InvalidPermissions);
    }
    let unwrap_priv = pal.vault_key(io, unwrap_key_id)?;
    let modulus_len = rsa_key_size.modulus_len();

    // Validate the wrapped-blob length: at minimum the RSA-OAEP
    // ciphertext (modulus_len) plus one AES-KW block (16 B).  The
    // wrapped_blob is already DMA-resident (decoded from the request
    // input buffer), so we sub-slice it in place instead of copying
    // each half into fresh scratch.
    if body.wrapped_blob.len() < modulus_len + 16 {
        return Err(HsmError::RsaUnwrapInvalidRequest);
    }
    let (oaep_ct, kwp_ct) = body.wrapped_blob.split_at_mut(modulus_len);

    // Step 1: RSA-OAEP-decrypt the KEK in place into the OAEP
    // ciphertext half of the wrapped blob.  The recovered plaintext
    // (the KEK) is far shorter than the `modulus_len` ciphertext, so
    // it fits, and decrypting in place avoids a separate output
    // allocation (real-HW PALs decrypt directly into the DMA buffer).
    // The KEK must be a 32-byte AES-256 key — any other length is a
    // host contract violation (or corrupted blob).
    let kek_len = pal
        .alloc_scoped_async(io, async |a| {
            pal.rsa_oaep_decrypt_in_place(
                io,
                rsa_key_size,
                hash_algo,
                unwrap_priv,
                &mut *oaep_ct,
                None,
                a,
            )
            .await
        })
        .await
        .map_err(|_| HsmError::RsaUnwrapOaepDecodeFailed)?;
    if kek_len != 32 {
        return Err(HsmError::RsaUnwrapInvalidKek);
    }

    // Step 2: AES-KWP-unwrap the payload using the recovered KEK.
    // KWP unwrap shrinks the output (strips the AIV + padding); the
    // max recovered size equals the wrapped size, so allocate that.
    let payload_buf = pal.dma_alloc(io, kwp_ct.len())?;
    let payload_len = pal
        .aes_kwp_unwrap(io, &oaep_ct[..kek_len], kwp_ct, payload_buf)
        .await
        .map_err(|_| HsmError::RsaUnwrapAesUnwrapFailed)?;

    // Step 3: hand the recovered payload to the per-key-class
    // import path.  Each import returns the vault guard + the
    // response payload so the encode + dismiss happens uniformly
    // here.  `RsaCrt` is not yet supported (the crypto crate's CRT
    // HSM layout does not match the canonical vault CRT blob size);
    // it falls through to `UnsupportedCmd` until reconciled.
    let payload = &payload_buf[..payload_len];
    let (guard, resp_data) = match body.wrapped_blob_key_class {
        DdiKeyClass::Aes => import_aes::import(pal, io, sess_id, &body, payload)?,
        DdiKeyClass::Rsa => import_rsa::import(pal, io, sess_id, &body, payload)?,
        DdiKeyClass::Ecc => import_ecc::import(pal, io, sess_id, &body, payload)?,
        _ => return Err(HsmError::UnsupportedCmd),
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::RsaUnwrap, sess_id),
            &resp_data,
            buf,
        )
    })?;
    let _ = guard.dismiss();
    Ok(resp)
}
