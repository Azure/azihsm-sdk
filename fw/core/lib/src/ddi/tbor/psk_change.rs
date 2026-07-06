// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PskChange` handler.
//!
//! Changes the active session's own partition PSK to a new value
//! delivered encrypted in an AEAD-GCM envelope under the session's
//! `param_key`.  The target slot is derived from the session role
//! (CO → CO PSK, CU → CU PSK); the wire request carries no slot
//! selector.
//!
//! ## Replay model
//!
//! Cross-session replay is structurally impossible: `param_key` is
//! HPKE-derived per session, so an envelope captured from session A
//! cannot decrypt under session B's key (the AEAD tag fails before
//! any plaintext is produced).
//!
//! Intra-session replay is bounded to **one successful change per
//! session**: the handler marks the session as "change used" on
//! success; a second `PskChange` on the same session is rejected
//! with `InvalidPermissions`.

use azihsm_fw_core_crypto_aead_envelope::open as aead_open;
use azihsm_fw_ddi_tbor_types::build_psk_change_aad;
use azihsm_fw_ddi_tbor_types::TborPskChangeReq;
use azihsm_fw_ddi_tbor_types::TborPskChangeResp;
use azihsm_fw_ddi_tbor_types::PSK_CHANGE_AAD_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_hsm_pal_traits::PSK_LEN;

/// PSK slot id written when the active session is the Crypto Officer.
const PSK_ID_CO: u8 = 0;
/// PSK slot id written when the active session is a Crypto User.
const PSK_ID_CU: u8 = 1;

/// Handle a TBOR `PskChange` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // `decode_mut` validates the wire frame and hands back a
    // destructured view: scalar `session_id` by value, plus
    // `psk_envelope` as `&mut DmaBuf` so `aead_open` can decrypt the
    // envelope in place — no scratch copy.
    let req = TborPskChangeReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));

    // Target slot is implicit in the session role; no cross-role
    // rotation is permitted.
    let target_psk_id = target_psk_for_role(sess_id.role());

    // The `psk_envelope` length is pinned by the schema
    // (`PSK_CHANGE_ENVELOPE_LEN` = 100 B); a malformed length was
    // already rejected at decode with `TborInvalidFixedLength`. The
    // AEAD-open below plus the AAD/payload-length checks remain the
    // load-bearing validation for a correctly-sized but crafted
    // envelope.

    // Reserve the session's one-shot PSK-change budget **before** any
    // crypto work, so replayed-after-success envelopes are rejected
    // cheaply.  A successful return here means no further `PskChange`
    // can succeed on this session; if the subsequent crypto/persist
    // steps fail, the session is "burned" — the caller must
    // renegotiate to retry.  Cross-session replay is already
    // structurally impossible (HPKE-derived per-session `param_key`).
    pal.session_try_consume_psk_change(io, sess_id)?;

    pal.alloc_scoped_async(io, async |_alloc| {
        // Fetch the session's `param_key` schedule (the PAL hides the
        // session-blob layout from us).
        let param_key = pal.session_param_key(io, sess_id)?;

        // AEAD-open the envelope **in place** on the inbound request
        // buffer.  The destructured `req.psk_envelope` is a
        // `&mut DmaBuf` carved by `decode_mut` from the same parent
        // `req_buf`; no copy into a scratch buffer is needed.
        let aead_view = aead_open(pal, io, param_key, req.psk_envelope)
            .await
            .map_err(|_| HsmError::AeadEnvelopeAuthFailed)?;

        // Validate AAD and plaintext shape.  The AEAD tag has already
        // authenticated these bytes, so an attacker cannot drive
        // divergent values through these branches; a non-constant-time
        // `!=` is safe (no timing oracle on a secret).  A length
        // mismatch is a client encoding bug, not an auth failure, so
        // it surfaces as `InvalidArg`.
        if aead_view.aad.len() != PSK_CHANGE_AAD_LEN {
            return Err(HsmError::InvalidArg);
        }
        let expected_aad = build_psk_change_aad(u16::from(sess_id));
        let aad_bytes: &[u8] = aead_view.aad;
        if aad_bytes != expected_aad.as_slice() {
            return Err(HsmError::AeadEnvelopeAuthFailed);
        }
        if aead_view.payload.len() != PSK_LEN {
            return Err(HsmError::InvalidArg);
        }

        // Persist the new PSK directly from the in-place envelope
        // view.  `part_psk_set` is synchronous and takes `&[u8]`, so
        // the borrow ends with the call — no need for a separate
        // scratch buffer.
        crate::part_state::part_set_psk(pal, io, target_psk_id, aead_view.payload)?;

        encode_response(pal, io)
    })
    .await
}

/// Maps the active session's role to the partition PSK slot it is
/// allowed to write.  Self-rotate-only: there is no cross-role
/// rotation path.
fn target_psk_for_role(role: SessionRole) -> u8 {
    match role {
        SessionRole::CryptoOfficer => PSK_ID_CO,
        SessionRole::CryptoUser => PSK_ID_CU,
    }
}

/// Encode the `PskChange` empty acknowledgement into a fresh
/// IO-scoped DmaBuf.
fn encode_response<'p, P: HsmPal>(pal: &'p P, io: &impl HsmIo) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborPskChangeResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use azihsm_fw_ddi_tbor_types::PSK_CHANGE_AAD_LABEL;

    use super::*;

    #[test]
    fn co_session_targets_co_slot() {
        assert_eq!(target_psk_for_role(SessionRole::CryptoOfficer), PSK_ID_CO);
    }

    #[test]
    fn cu_session_targets_cu_slot() {
        assert_eq!(target_psk_for_role(SessionRole::CryptoUser), PSK_ID_CU);
    }

    #[test]
    fn session_id_zero_is_co_session() {
        // Sanity guard against drift in the slot-to-role mapping owned
        // by `HsmSessId::role`.
        assert_eq!(HsmSessId::from(0u16).role(), SessionRole::CryptoOfficer);
        for slot in 1u16..=7 {
            assert_eq!(HsmSessId::from(slot).role(), SessionRole::CryptoUser);
        }
    }

    #[test]
    fn aad_helper_layout_is_label_then_session_id_le() {
        // Sanity guard on the shared AAD builder both sides use.
        let aad = build_psk_change_aad(0x1234);
        assert_eq!(&aad[..13], PSK_CHANGE_AAD_LABEL);
        assert_eq!(&aad[13..15], &[0x34, 0x12]);
        assert_eq!(aad.len(), PSK_CHANGE_AAD_LEN);
    }
}
