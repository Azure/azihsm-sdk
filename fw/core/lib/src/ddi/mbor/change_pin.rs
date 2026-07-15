// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI ChangePin command handler.
//!
//! Within an open session, authenticate a host-supplied encrypted new
//! PIN and replace the partition credential's PIN in place, preserving
//! the user id.
//!
//! The authentication mirrors [`open_session`](super::open_session):
//! ECDH against the partition's session-encryption key + HKDF-SHA-384
//! (`info = nonce`) yields an 80-byte OKM split into a 32-byte AES key
//! and a 48-byte HMAC key.  The HMAC key authenticates
//! `encrypted_pin ‖ iv ‖ nonce`; the AES key AES-CBC-decrypts the new
//! PIN.  The partition nonce is refreshed before the credential is
//! updated so the authenticated request cannot be replayed.

use azihsm_fw_ddi_mbor_types::change_pin::DdiChangePinReq;
use azihsm_fw_ddi_mbor_types::change_pin::DdiChangePinResp;
use azihsm_fw_ddi_mbor_types::change_pin::DdiEncryptedPin;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_hsm_pal_traits::PartPropId;

use super::*;

/// Credential half-field length (id / pin) in bytes.  The stored
/// credential is `id ‖ pin` (16 + 16 = 32 bytes).
const CRED_FIELD_LEN: usize = 16;

/// Handle `DdiChangePinCmd`.
///
/// Runs under the partition lock.  DDI commands execute on a
/// single-threaded cooperative executor, but multiple IOs are in flight
/// and interleave at await points, so the lock serializes this handler's
/// multi-step fail-fast checks with the credential update at the end.
pub(crate) async fn change_pin<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiChangePinReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    let _lock = pal.partition_lock(io).await?;

    // ── Fail-fast (under the lock, before any crypto) ────────────────
    //
    // The request is authenticated by the partition nonce; reject a
    // stale nonce before doing ECDH work.
    crate::part_state::part_verify_nonce(pal, io, body.new_pin.nonce)?;

    // A PIN change only makes sense once a credential exists.
    if !crate::part_state::part_is_credential_set(pal, io)? {
        return Err(HsmError::InvalidAppCredentials);
    }

    if body.pub_key.key_kind != DdiKeyType::Ecc384Public {
        return Err(HsmError::InvalidKeyType);
    }
    if body.pub_key.raw.len() != HsmEccCurve::P384.pub_key_len() {
        return Err(HsmError::InvalidArg);
    }

    // ── ECDH + HKDF → 80-byte OKM (aes_key ‖ hmac_key) ───────────────
    let okm = pal.dma_alloc(io, BK_LEN)?;
    super::open_session::derive_session_credential_keys(
        pal,
        io,
        body.pub_key.raw,
        body.new_pin.nonce,
        okm,
    )
    .await?;
    // HMAC-SHA-384 key length matches the digest length; the AES key is
    // the leading remainder of the 80-byte OKM.
    let (aes_key, hmac_key) = okm.split_at(okm.len() - HsmHashAlgo::Sha384.digest_len());

    // ── Authenticate the encrypted PIN ───────────────────────────────
    verify_change_pin_hmac(pal, io, &body.new_pin, hmac_key).await?;

    // ── Reset nonce before decrypt / commit ──────────────────────────
    //
    // The nonce that authenticated this request must not be replayable,
    // so refresh it now even though a later step may still fail.
    {
        let nonce = pal.dma_alloc(io, crate::part_state::NONCE_LEN)?;
        pal.rng_fill_bytes(io, nonce)?;
        crate::part_state::part_set_nonce(pal, io, nonce)?;
    }

    // ── AES-CBC decrypt the new PIN in place ─────────────────────────
    pal.aes_cbc_enc_dec_in_place(
        io,
        AesOp::Decrypt,
        aes_key,
        body.new_pin.encrypted_pin,
        body.new_pin.iv,
        None,
    )
    .await?;

    // Reject an all-zero PIN *before* mutating the credential: the
    // update clears the write-once credential then re-writes it, and
    // there is no undo log yet, so a rejected change must leave the
    // existing credential untouched.  (The CREDENTIAL prop setter also
    // rejects an all-zero half.)
    if body.new_pin.encrypted_pin.iter().all(|&b| b == 0) {
        return Err(HsmError::InvalidAppCredentials);
    }

    // ── Update credential: preserve id, replace pin ──────────────────
    //
    // Snapshot the id half onto the stack (a public identifier, not a
    // secret) so the `part_credential` borrow is released before the
    // clear/re-write below.
    let mut id = [0u8; CRED_FIELD_LEN];
    {
        let stored = crate::part_state::part_credential(pal, io)?;
        if stored.len() != 2 * CRED_FIELD_LEN {
            return Err(HsmError::InternalError);
        }
        id.copy_from_slice(&stored[..CRED_FIELD_LEN]);
    }

    let new_cred = pal.dma_alloc(io, 2 * CRED_FIELD_LEN)?;
    new_cred[..CRED_FIELD_LEN].copy_from_slice(&id);
    new_cred[CRED_FIELD_LEN..].copy_from_slice(&body.new_pin.encrypted_pin[..CRED_FIELD_LEN]);

    // The credential is write-once: `part_set_credential` rejects a
    // re-set without an intervening clear, so clear before re-writing
    // `id ‖ new_pin`.
    pal.part_prop_clear(io, PartPropId::CREDENTIAL)?;
    crate::part_state::part_set_credential(pal, io, new_cred)?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::ChangePin, sess_id),
            &DdiChangePinResp {},
            buf,
        )
    })?;
    Ok(resp)
}

/// HMAC-SHA-384 verifies the encrypted PIN's tag over
/// `encrypted_pin ‖ iv ‖ nonce`.
///
/// `hmac_key` must be at least 48 bytes (the HMAC-SHA-384 key).
/// Returns [`HsmError::PinDecryptionFailed`] on a tag mismatch —
/// covering a tampered PIN, IV, nonce, tag, or peer public key (which
/// derives a different key).
async fn verify_change_pin_hmac<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    new_pin: &DdiEncryptedPin<'_>,
    hmac_key: &DmaBuf,
) -> HsmResult<()> {
    let pin_len = new_pin.encrypted_pin.len();
    let iv_len = new_pin.iv.len();
    let nonce_len = new_pin.nonce.len();

    let hmac_input = pal.dma_alloc(io, pin_len + iv_len + nonce_len)?;
    let (pin_dst, rest) = hmac_input.split_at_mut(pin_len);
    let (iv_dst, nonce_dst) = rest.split_at_mut(iv_len);
    pin_dst.copy_from_slice(new_pin.encrypted_pin);
    iv_dst.copy_from_slice(new_pin.iv);
    nonce_dst.copy_from_slice(new_pin.nonce);

    if !pal
        .hmac_verify(io, HsmHashAlgo::Sha384, hmac_key, hmac_input, new_pin.tag)
        .await?
    {
        return Err(HsmError::PinDecryptionFailed);
    }
    Ok(())
}
