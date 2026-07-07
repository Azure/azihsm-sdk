// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI AesGenerateKey command handler.
//!
//! Within an open session, generate a fresh random AES key (128 /
//! 192 / 256 bits), persist it in the partition vault — optionally
//! session-scoped so it is torn down by
//! [`CloseSession`](super::close_session) — and return the assigned
//! `key_id` plus an (empty placeholder) masked-key envelope that the
//! host may re-import on a future session.
//!
//! Scope: non-bulk AES key kinds only.  XTS / GCM bulk variants are
//! rejected with `InvalidArg`.

use azihsm_fw_ddi_mbor_types::aes_generate_key::DdiAesGenerateKeyReq;
use azihsm_fw_ddi_mbor_types::aes_generate_key::DdiAesGenerateKeyResp;

use super::*;

/// Handle `DdiAesGenerateKeyCmd`.
///
/// No `partition_lock` is needed.  Although `vault_key_create` is now
/// awaited (it can yield on Uno during the GDMA key copy), DDI commands
/// run on a single-threaded cooperative executor with one command in
/// flight per partition, so no concurrent handler can interleave with
/// this one — there is nothing for a lock to serialize.
pub(crate) async fn aes_generate_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiAesGenerateKeyReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    let (key_len, vault_kind) = super::from_ddi::aes(body.key_size)?;
    let attrs = super::key_attrs::for_aes(&body.key_properties.key_metadata)?;

    // Session-only keys are anonymous — disallow a host-supplied
    // `key_tag` because the key cannot be looked up across sessions.
    super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;

    // Generate the random AES key bytes into a scratch buffer.  The
    // PAL's `aes_gen_key` wraps the CSPRNG and validates the buffer
    // length, so the handler just sizes the buffer per the requested
    // key kind.
    let key_buf = pal.dma_alloc(io, key_len)?;
    pal.aes_gen_key(io, key_buf).await?;

    // Store in the vault, session-scoped iff requested.
    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
    let key_id: u16 = pal
        .vault_key_create(io, key_buf, vault_kind, session_binding, attrs)
        .await?
        .into();

    // Build the response.  `masked_key` is the host's opaque
    // re-import blob; firmware-side masking against the session BK is
    // pending the corresponding `UnmaskKey` handler — emit an empty
    // placeholder for now so the response is wire-valid.  `bulk_key_id`
    // is reserved for the AES-XTS / AES-GCM bulk variants which this
    // handler rejects; non-bulk keys always report `None`.
    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::AesGenerateKey, sess_id),
            &DdiAesGenerateKeyResp {
                key_id,
                bulk_key_id: None,
                masked_key: &[],
            },
            buf,
        )
    })?;

    Ok(resp)
}
