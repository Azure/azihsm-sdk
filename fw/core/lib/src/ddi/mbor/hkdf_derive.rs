// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI HkdfDerive command handler.
//!
//! Within an open session, derive key material from an existing ECDH
//! shared secret via HKDF (RFC 5869: Extract-then-Expand), persist
//! the result in the partition vault — optionally session-scoped so
//! it is torn down by [`CloseSession`](super::close_session) — and
//! return the assigned `key_id` plus an (empty placeholder) masked-key
//! envelope the host may re-import on a future session.
//!
//! The input key must be an ECDH shared secret (`Secret256` /
//! `Secret384` / `Secret521`) with the `derive` permission.  The
//! requested output `key_type` selects the vault kind: AES outputs
//! are stored as AES keys, while every HMAC output (fixed `HmacSha*`
//! or `VarHmac*`) is stored as a variable-length HMAC key.  See
//! [`kdf`](super::kdf) for the full mapping and length rules.

use azihsm_fw_ddi_mbor_types::derive_hkdf::DdiHkdfDeriveReq;
use azihsm_fw_ddi_mbor_types::derive_hkdf::DdiHkdfDeriveResp;

use super::kdf::KdfClass;
use super::*;

/// Handle `DdiHkdfDeriveCmd`.
///
/// No `partition_lock` is needed.  Although `vault_key_create` is now
/// awaited (it can yield on Uno during the GDMA key copy), DDI commands
/// run on a single-threaded cooperative executor with one command in
/// flight per partition, so no concurrent handler can interleave with
/// this one — there is nothing for a lock to serialize.
pub(crate) async fn hkdf_derive<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiHkdfDeriveReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let input_key_id = HsmKeyId::from(body.key_id);

    // The IKM must be an ECDH shared secret carrying `derive`.
    super::kdf::validate_input_secret(pal.vault_key_kind(io, input_key_id)?)?;
    if !pal.vault_key_attrs(io, input_key_id)?.derive() {
        return Err(HsmError::InvalidPermissions);
    }

    let algo = super::from_ddi::hash(body.hash_algorithm)?;
    let target = super::kdf::resolve_target(body.key_type, body.key_length)?;
    let attrs = match target.class {
        KdfClass::Aes => super::key_attrs::for_aes(&body.key_properties.key_metadata)?,
        KdfClass::Hmac => super::key_attrs::for_var_hmac(&body.key_properties.key_metadata)?,
    };
    super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;

    // Derive the OKM into a DMA scratch slot; `vault_key_create`
    // copies it into vault-owned storage so the scratch can drop
    // after.  An absent salt (`None`) selects the RFC 5869 default
    // all-zero salt.
    //
    // `out` and `prk` are allocated separately rather than carved
    // from one buffer: each `dma_alloc` is independently 4-byte
    // aligned, which the crypto DMA engine requires.  `out_len` is
    // caller-controlled and need not be 4-aligned (variable-length
    // HMAC outputs), so splitting a single buffer at `out_len` could
    // leave `prk` misaligned.
    let out = pal.dma_alloc(io, target.out_len)?;
    let prk = pal.dma_alloc(io, algo.digest_len())?;

    {
        let ikm = pal.vault_key(io, input_key_id)?;
        pal.hkdf_extract(io, algo, body.salt.as_deref(), ikm, prk)
            .await?;
    }

    pal.hkdf_expand(io, algo, prk, body.info.as_deref(), out)
        .await?;

    // RAII vault entry — rolls back if response encoding below fails.
    // `masked_key` is the host's opaque re-import blob; firmware-side
    // masking is pending the `UnmaskKey` handler, so we emit an empty
    // placeholder for wire validity.
    let key_id: u16 = pal
        .vault_key_create(
            io,
            out,
            target.kind,
            attrs.session().then_some(HsmSessId::from(sess_id)),
            attrs,
        )
        .await?
        .into();

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::HkdfDerive, sess_id),
            &DdiHkdfDeriveResp {
                key_id,
                masked_key: &[],
                bulk_key_id: None,
            },
            buf,
        )
    })?;
    Ok(resp)
}
