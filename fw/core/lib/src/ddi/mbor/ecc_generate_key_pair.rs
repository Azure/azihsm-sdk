// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccGenerateKeyPair command handler.
//!
//! Within an open session, generate a fresh ECC keypair on the
//! requested NIST curve (P-256 / P-384 / P-521), persist the private
//! key in the partition vault — optionally session-scoped so it is
//! torn down by [`CloseSession`](super::close_session) — and return
//! the public key plus an opaque masked-key envelope the host may
//! re-import on a future session.

use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairReq;
use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairResp;

use super::*;

/// Handle `DdiEccGenerateKeyPairCmd`.
///
/// No `partition_lock` is needed: this handler does not perform any
/// multi-step read-then-mutate against partition state.  Its single
/// state mutation — `vault_key_create` — is sync and atomic.  A
/// concurrent `CloseSession` racing with our `ecc_gen_keypair` await
/// would just turn the subsequent vault create into a clean
/// `SessionNotFound` error, never a partial commit.
pub(crate) async fn ecc_generate_key_pair<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEccGenerateKeyPairReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let pal_curve = super::from_ddi::curve(body.curve)?;
    let vault_kind = super::from_pal::ecc_private(pal_curve);
    let attrs = super::key_attrs::for_ecc(pal_curve, &body.key_properties.key_metadata)?;

    // Session-only keys are anonymous — disallow a host-supplied
    // `key_tag` because the key cannot be looked up across sessions.
    // Matches `test_ecc_generate_session_only_key_with_key_tag`.
    super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;

    // ECC key generation follows the trait's query-alloc-use flow.
    // The IO-lifetime priv/pub buffers must outlive the scoped
    // allocator block — `StdScopedAlloc::Drop` resets the DMA
    // bump-mark on scope exit, including any `pal.dma_alloc(io, _)`
    // bumps made inside, so an IO-scoped allocation done within the
    // scope would silently overlap the next post-scope allocation
    // (e.g. the response buffer).  Keep the `dma_alloc(io, _)`
    // bufs outside any scope; reserve the scope only for the
    // keygen's internal PKA-style scratch.
    let (priv_size, pub_size) = pal
        .alloc_scoped_async(io, async |a| {
            pal.ecc_gen_keypair(io, a, pal_curve, None, HsmEccPct::SignVerify)
                .await
        })
        .await?;
    let priv_key = pal.dma_alloc(io, priv_size)?;
    let pub_key = pal.dma_alloc(io, pub_size)?;
    let (priv_len, pub_len) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            pal.ecc_gen_keypair(
                io,
                a,
                pal_curve,
                Some((&mut *priv_key, &mut *pub_key)),
                HsmEccPct::SignVerify,
            )
            .await
        })
        .await?;

    // Store the private key in the vault, session-scoped iff the
    // requested attrs say so.  RAII guard rolls the entry back if
    // the response encoding below fails.
    let session_binding = if attrs.session() {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let guard = pal.vault_key_create(
        io,
        &priv_key[..priv_len],
        vault_kind,
        session_binding,
        attrs,
        body.key_properties.key_label,
    )?;
    let private_key_id: u16 = guard.key_id().into();

    // Build the response.  `masked_key` is the host's opaque
    // re-import blob; firmware-side masking against the session BK is
    // pending the corresponding `UnmaskKey` handler — emit an empty
    // placeholder for now so the response is wire-valid.
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::EccGenerateKeyPair, sess_id),
            buf,
        )?;
        let layout = DdiEccGenerateKeyPairResp::reserve(
            &mut encoder,
            private_key_id,
            DdiPublicKeyFrameParams {
                raw_len: pub_len,
                key_kind: super::from_pal::ecc_public_ddi(pal_curve),
            },
            0, /* masked_key length — empty placeholder */
        )?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccGenerateKeyPairResp::from_layout(resp, &layout);

    // PAL already emitted the public key in wire format (LE + P-521
    // padding), so copy directly without further reordering.
    frame.pub_key.raw.copy_from_slice(&pub_key[..pub_len]);

    // Commit the vault entry; response is now fully populated.
    let _ = guard.dismiss();

    Ok(resp)
}
