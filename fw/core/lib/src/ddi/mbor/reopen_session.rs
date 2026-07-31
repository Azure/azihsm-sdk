// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI ReopenSession command handler.
//!
//! Re-establishes a session that a live-migration / NSSR reset left in
//! the [`NeedsRenegotiation`](azihsm_fw_hsm_pal_traits::HsmSessionState::NeedsRenegotiation)
//! state.  It shares the credential-authentication and `BK_SESSION`
//! derivation with [`OpenSession`](super::open_session) — the two must
//! stay in lock-step so the `BK_SESSION` that masked `bmk_session` on
//! open is exactly the one that unmasks it on reopen — then, instead of
//! generating a fresh `MK_SESSION`, recovers it by unmasking the
//! host-persisted `bmk_session` and re-keys the **same** session slot.
//!
//! Flow at a glance (mirrors the reference firmware's `is_reopen` path
//! in the OpenSession FSM):
//!
//! 1. Decode + fail-fast (shared [`check_fail_fast`] with
//!    `is_reopen = true`, which skips the free-slot check since the slot
//!    already exists).
//! 2. Authenticate the credential and derive `BK_SESSION` via the shared
//!    [`authenticate_and_derive_bk_session`].
//! 3. Unmask the host-persisted `bmk_session` under `BK_SESSION` to
//!    recover `MK_SESSION` (the HMAC is verified before decryption, so a
//!    tampered blob or wrong credential lineage is rejected).
//! 4. `session_create(Some(old_sess_id))` — re-key the migrated slot with
//!    the recovered `MK_SESSION`.
//! 5. Re-envelope `MK_SESSION` under `BK_SESSION` into the response's
//!    `bmk_session` for the host to persist, and echo the reused
//!    `sess_id` in the response header.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_core_crypto_key_masking::cbc::unmask;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::reopen_session::DdiReopenSessionReq;
use azihsm_fw_ddi_mbor_types::reopen_session::DdiReopenSessionResp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;

use super::open_session::authenticate_and_derive_bk_session;
use super::open_session::check_fail_fast;
use super::open_session::pack_api_rev;
use super::open_session::SMK_KEY_LABEL;
use super::*;

/// Handle `DdiReopenSessionCmd`.
///
/// Re-establishes a session that a live-migration / NSSR wiped from the
/// partition.  Authenticates the host credential and derives `BK_SESSION`
/// exactly as [`open_session`](super::open_session::open_session); then,
/// instead of generating a fresh `MK_SESSION`, recovers it by unmasking
/// the host-persisted `bmk_session` under `BK_SESSION`, and recreates the
/// **same** session slot via `session_create(Some(old_sess_id))`.  The
/// session id to reopen is carried in the request header.  Mirrors the
/// reference firmware's `is_reopen` path in the OpenSession FSM.
pub(crate) async fn reopen_session<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let mut body: DdiReopenSessionReq = decoder.decode_data()?;
    let reopen_id = HsmSessId::from(hdr.sess_id.ok_or(HsmError::SessionExpected)?);

    let _lock = pal.partition_lock(io).await?;

    check_fail_fast(
        pal,
        io,
        body.encrypted_credential.nonce,
        &body.pub_key,
        true,
    )?;
    let api_rev = hdr.rev.ok_or(HsmError::UnsupportedRevision)?;

    // Authenticate the credential and derive BK_SESSION — identical to
    // OpenSession, so the same BK_SESSION that masked `bmk_session`
    // unmasks it below.
    let pub_key_raw = body.pub_key.raw;
    let bk_session =
        authenticate_and_derive_bk_session(pal, io, &mut body.encrypted_credential, pub_key_raw)
            .await?;

    // Recover MK_SESSION by unmasking the host-persisted `bmk_session`
    // under BK_SESSION.  `unmask` verifies the HMAC before decrypting, so
    // a tampered blob or one from a different credential lineage (wrong
    // BK_SESSION) is rejected without leaking plaintext.
    let layout = unmask(pal, io, bk_session, body.bmk_session).await?;
    // The authenticated blob must carry at least a full MK_SESSION; a
    // shorter plaintext is a malformed masked key, reported like the rest
    // of the unmask path.
    if layout.plaintext_max_len < BK_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    let mk_session = pal.dma_alloc(io, BK_LEN)?;
    mk_session.copy_from_slice(
        &body.bmk_session[layout.plaintext_offset..layout.plaintext_offset + BK_LEN],
    );

    // Recreate the migrated session's own slot with the recovered key.
    let api_rev_bytes = pack_api_rev(api_rev);
    let sess_id = pal
        .session_create(io, &api_rev_bytes, mk_session, Some(reopen_id))
        .await?;

    // Re-envelope MK_SESSION under BK_SESSION for the host to persist
    // (the SVN etc. recorded in the metadata may have advanced), mirroring
    // OpenSession's response.
    let resp = encode_reopen_response(
        pal,
        io,
        hdr,
        sess_id,
        bk_session,
        mk_session,
        crate::part_state::part_mfgr_svn(pal),
        u16::try_from(crate::part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?,
    )
    .await?;

    // `ReopenSession` is an in-session command: it reuses the caller's
    // existing session id (echoed in the response header), so unlike
    // `OpenSession` there is no *new* id to surface to the CQE — return the
    // plain response slice.
    Ok(resp)
}

/// Envelopes `mk_session` under `bk_session` and encodes the
/// `ReopenSession` response.  Structurally identical to
/// [`encode_response`](super::open_session) but frames a
/// [`DdiReopenSessionResp`] under the [`DdiOp::ReopenSession`] opcode.
#[allow(clippy::too_many_arguments)]
async fn encode_reopen_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    hdr: &DdiReqHdr,
    sess_id: HsmSessId,
    bk_session: &DmaBuf,
    mk_session: &DmaBuf,
    svn: u64,
    bks2_id: u16,
) -> HsmResult<&'p DmaBuf> {
    let bmk_metadata = DdiMaskedKeyMetadata {
        svn,
        key_type: DdiKeyType::AesCbc256Hmac384,
        key_attributes: HsmVaultKeyAttrs::new().into(),
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label: SMK_KEY_LABEL,
        key_length: BK_LEN as u16,
    };

    let bmk_len = mask(pal, io, bk_session, mk_session, &bmk_metadata, None).await?;

    let short_app_id: u8 = 0;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::ReopenSession, u16::from(sess_id)),
            buf,
        )?;
        let layout =
            DdiReopenSessionResp::reserve(&mut encoder, u16::from(sess_id), short_app_id, bmk_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiReopenSessionResp::from_layout(resp, &layout);

    // `key_masking::cbc::mask` requires `out[..total_len]` to be zero
    // on entry.
    frame.bmk_session.fill(0);
    mask(
        pal,
        io,
        bk_session,
        mk_session,
        &bmk_metadata,
        Some(frame.bmk_session),
    )
    .await?;
    Ok(resp)
}
