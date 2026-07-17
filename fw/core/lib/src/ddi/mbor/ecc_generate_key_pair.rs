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

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairReq;
use azihsm_fw_ddi_mbor_types::ecc_generate_key_pair::DdiEccGenerateKeyPairResp;

use super::*;

/// Handle `DdiEccGenerateKeyPairCmd`.
///
/// No `partition_lock` is needed.  DDI commands execute on a
/// single-threaded cooperative executor; multiple IOs are in flight and
/// interleave at await points — including inside the awaited
/// `vault_key_create` (which can yield on Uno during the GDMA key copy) —
/// but this handler's only partition-state mutation is that single,
/// self-contained `vault_key_create`, with no multi-step
/// read-modify-write across an await for an interleaved handler to
/// corrupt.
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
    let attrs = super::key_attrs::for_ecc(&body.key_properties.key_metadata, true)?;

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
    // requested attrs say so.
    let session_binding = if attrs.session() {
        Some(HsmSessId::from(sess_id))
    } else {
        None
    };
    let private_key_id: u16 = pal
        .vault_key_create(
            io,
            &priv_key[..priv_len],
            vault_kind,
            session_binding,
            attrs,
        )
        .await?
        .into();

    // Build the host's re-import blob.  ECC envelopes the private-key
    // blob followed by the public point so the unmask path can restore
    // both; `key_length` records the private-key length so the importer
    // can split the plaintext.  Session-scoped keys use the session
    // masking key; persistent keys use the partition masking key (`MK`).
    let key_plain = pal.dma_alloc(io, priv_len + pub_len)?;
    key_plain[..priv_len].copy_from_slice(&priv_key[..priv_len]);
    key_plain[priv_len..priv_len + pub_len].copy_from_slice(&pub_key[..pub_len]);
    let masking_key =
        super::masking::resolve_masking_key(pal, io, HsmSessId::from(sess_id), attrs.session())?;
    let metadata = super::masking::masked_metadata(
        pal,
        super::from_pal::vault_kind_ddi(vault_kind)?,
        attrs,
        body.key_properties.key_label,
        priv_len as u16,
    )?;
    let masked_len = mask(pal, io, masking_key, &key_plain[..], &metadata, None).await?;

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
            masked_len,
        )?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccGenerateKeyPairResp::from_layout(resp, &layout);

    // PAL already emitted the public key in wire format (LE + P-521
    // padding), so copy directly without further reordering.
    frame.pub_key.raw.copy_from_slice(&pub_key[..pub_len]);

    // `mask` requires `out[..total_len]` to be zero on entry; zero the
    // reserved slot before filling it with the envelope.
    frame.masked_key.fill(0);
    mask(
        pal,
        io,
        masking_key,
        &key_plain[..],
        &metadata,
        Some(frame.masked_key),
    )
    .await?;

    Ok(resp)
}
