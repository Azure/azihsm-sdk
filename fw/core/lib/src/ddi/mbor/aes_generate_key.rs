// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesGenerateKey command handler.
//!
//! Within an open session, generate a fresh random AES key (128 /
//! 192 / 256 bits) or an AES-256 GCM / XTS bulk key, persist it in the
//! partition vault — optionally session-scoped so it is torn down by
//! [`CloseSession`](super::close_session) — and return the assigned
//! `key_id` plus a masked-key envelope that the host may re-import on
//! a future session.
//!
//! For the bulk kinds (`AesGcmBulk256` / `AesGcmBulk256Unapproved` /
//! `AesXtsBulk256`) the response also carries a `bulk_key_id`.  The bulk
//! key is the key consumed by the bulk GCM / XTS encrypt/decrypt op; the
//! host addresses it via this `bulk_key_id`.  Bulk key material is registered with the
//! bulk-crypto backend (see [`bulk::commit_key`](super::bulk));
//! the vault stores only the 2-byte backend handle, and `bulk_key_id` is
//! the distinct backend-assigned id, not the vault `key_id`.
//!
//! Scope: 128/192/256-bit AES keys and AES-256 GCM / XTS bulk keys.

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
/// but this handler's only partition-state mutations are that single,
/// self-contained `vault_key_create` and, if a later step fails, the
/// deletion of the key it just created — no multi-step read-modify-write
/// across an await for an interleaved handler to corrupt.
pub(crate) async fn aes_generate_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesGenerateKeyReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Bulk kinds (GCM / XTS) map to a 32-byte AES-256 key and report a
    // `bulk_key_id`; non-bulk kinds map to their sized AES vault kind.
    let is_bulk = matches!(
        body.key_size,
        DdiAesKeySize::AesGcmBulk256
            | DdiAesKeySize::AesGcmBulk256Unapproved
            | DdiAesKeySize::AesXtsBulk256
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
    if let Err(e) = pal.aes_gen_key(io, key_buf).await {
        key_buf.zeroize();
        return Err(e);
    }

    // Bulk keys live in the bulk-crypto backend: hand the freshly
    // generated material to the backend and keep only the 2-byte
    // `bulk_key_id` reference in the vault.  Non-bulk keys are stored
    // directly.  The registration is scoped to the creating session so
    // later bulk ops (which carry the session id) match.  Scrub the
    // material on commit failure before propagating.
    let (key_handle, bulk_key_id) = match super::bulk::commit_key(
        pal,
        io,
        key_buf,
        vault_kind,
        HsmSessId::from(sess_id),
        attrs,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            key_buf.zeroize();
            return Err(e);
        }
    };
    let key_id: u16 = key_handle.into();

    // Build the host's opaque re-import blob: envelope the freshly
    // generated key under the per-session masking key (session-scoped
    // keys) or the partition masking key (persistent keys).  Bulk keys
    // mask the generated material directly (the vault holds only the
    // `bulk_key_id`); non-bulk keys read the stored bytes back from the
    // vault so the masked bytes match a later re-import.
    let result = async {
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

        pal.dma_alloc_var(io, |buf| {
            super::encode_resp(
                &super::success_hdr_sess(hdr, DdiOp::AesGenerateKey, sess_id),
                &DdiAesGenerateKeyResp {
                    key_id,
                    bulk_key_id,
                    masked_key,
                },
                buf,
            )
        })
    }
    .await;

    // Scrub the freshly generated key material now that the vault (or the
    // bulk-crypto backend, for bulk keys) owns it and masking has consumed
    // it.  Wipe on all paths — including a masking error — since the per-IO
    // arena is not guaranteed to be wiped on teardown.
    key_buf.zeroize();
    super::bulk::rollback_on_err(pal, io, key_handle, result.map(|b| &*b)).await
}
