// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesGenerateKey command handler.
//!
//! Within an open session, generate a fresh random AES key (128 /
//! 192 / 256 bits) or an AES-256-GCM bulk key, persist it in the
//! partition vault — optionally session-scoped so it is torn down by
//! [`CloseSession`](super::close_session) — and return the assigned
//! `key_id` plus an masked-key envelope that the host may re-import on
//! a future session.
//!
//! For the GCM bulk kinds (`AesGcmBulk256` / `AesGcmBulk256Unapproved`)
//! the response also carries a `bulk_key_id`.  The bulk key is the key
//! consumed by the fast-path GCM encrypt/decrypt op; the host addresses
//! it via this `bulk_key_id`.  On this platform the bulk key material is
//! held in the vault and `bulk_key_id` aliases the vault `key_id`.
//!
//! Scope: 128/192/256-bit AES keys and AES-256-GCM bulk keys.  The
//! AES-XTS bulk variant is rejected with `InvalidArg`.

use azihsm_fw_ddi_mbor_types::aes_generate_key::DdiAesGenerateKeyReq;
use azihsm_fw_ddi_mbor_types::aes_generate_key::DdiAesGenerateKeyResp;
use azihsm_fw_ddi_mbor_types::DdiAesKeySize;

use super::*;

/// Handle `DdiAesGenerateKeyCmd`.
///
/// No `partition_lock` is needed.  DDI commands execute on a
/// single-threaded cooperative executor; multiple IOs are in flight and
/// interleave at await points — including inside the awaited
/// `vault_key_create` (which can yield on Uno during the GDMA key copy) —
/// but this handler's only partition-state mutation is that single,
/// self-contained `vault_key_create`, with no multi-step
/// read-modify-write across an await for an interleaved handler to
/// corrupt.
pub(crate) async fn aes_generate_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesGenerateKeyReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // GCM bulk kinds map to a 32-byte AES-256 key and report a
    // `bulk_key_id`; non-bulk kinds map to their sized AES vault kind.
    let is_bulk = matches!(
        body.key_size,
        DdiAesKeySize::AesGcmBulk256 | DdiAesKeySize::AesGcmBulk256Unapproved
    );
    let (key_len, vault_kind) = if is_bulk {
        super::from_ddi::aes_bulk(body.key_size)?
    } else {
        super::from_ddi::aes(body.key_size)?
    };
    let attrs = super::key_attrs::for_aes(&body.key_properties.key_metadata, true)?;

    // Session-only keys are anonymous — disallow a host-supplied
    // `key_tag` because the key cannot be looked up across sessions.
    super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;

    // Generate the random AES key bytes into a scratch buffer.  The
    // PAL's `aes_gen_key` wraps the CSPRNG and validates the buffer
    // length, so the handler just sizes the buffer per the requested
    // key kind.
    let key_buf = pal.dma_alloc(io, key_len)?;
    pal.aes_gen_key(io, key_buf).await?;

    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));

    // Bulk GCM keys live in the fast-path (FP) engine: hand the freshly
    // generated material to FP and keep only the 2-byte `bulk_key_id`
    // reference in the vault.  The FP registration is scoped to the
    // creating session so later fast-path GCM ops (which carry the
    // session id) match.  Non-bulk keys are stored directly.
    let (key_handle, bulk_key_id) = if is_bulk {
        let (handle, bulk_id) = super::bulk::register_bulk_key(
            pal,
            io,
            key_buf,
            vault_kind,
            HsmSessId::from(sess_id),
            attrs,
        )
        .await?;
        (handle, Some(bulk_id))
    } else {
        let handle = pal
            .vault_key_create(io, key_buf, vault_kind, session_binding, attrs)
            .await?;
        (handle, None)
    };
    let key_id: u16 = key_handle.into();

    // Build the host's opaque re-import blob: envelope the freshly
    // generated key under the per-session masking key (session-scoped
    // keys) or the partition masking key (persistent keys).  Bulk keys
    // mask the generated material directly (the vault holds only the
    // `bulk_key_id`); non-bulk keys read the stored bytes back from the
    // vault so the masked bytes match a later re-import.
    let plaintext: &DmaBuf = if is_bulk {
        key_buf
    } else {
        pal.vault_key(io, key_handle)?
    };
    let masked_key = super::masking::mask_blob(
        pal,
        io,
        HsmSessId::from(sess_id),
        super::masking::MaskSpec {
            attrs,
            key_type: super::from_pal::vault_kind_ddi(vault_kind)?,
            key_label: body.key_properties.key_label,
            key_length: plaintext.len() as u16,
        },
        plaintext,
    )
    .await?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::AesGenerateKey, sess_id),
            &DdiAesGenerateKeyResp {
                key_id,
                bulk_key_id,
                masked_key,
            },
            buf,
        )
    })?;

    Ok(resp)
}
