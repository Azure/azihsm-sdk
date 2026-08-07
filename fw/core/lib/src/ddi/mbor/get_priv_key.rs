// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `GetPrivKey` command handler (test hook, op 2005).
//!
//! Within an open session, read back the raw plaintext material of a
//! previously created / imported key and return it alongside the key's
//! on-wire kind.  This is a validation-only hook (`fips_validation_hooks`)
//! that lets a host Known-Answer-Test confirm imported key vectors landed
//! correctly; the normal DDI surface never exposes private / secret key
//! bytes.
//!
//! No `partition_lock` is needed: the handler only performs read-only
//! vault lookups (`vault_key_kind` / `vault_key`) — no partition-state
//! mutation held across an await.

use azihsm_fw_ddi_mbor_types::get_priv_key::DdiGetPrivKeyReq;
use azihsm_fw_ddi_mbor_types::get_priv_key::DdiGetPrivKeyResp;

use super::*;

/// Handle `DdiGetPrivKeyCmd`.
pub(crate) async fn get_priv_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let body: DdiGetPrivKeyReq = decoder.decode_data()?;

    let key_id = HsmKeyId::from(body.key_id);

    // Resolve the stored kind and map it back to its on-wire type, then
    // borrow the committed plaintext (exact key length, no padding).
    let vault_kind = pal.vault_key_kind(io, key_id)?;
    let key_kind = super::from_pal::vault_kind_ddi(vault_kind)?;
    let plaintext = pal.vault_key(io, key_id)?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::GetPrivKey, sess_id),
            &DdiGetPrivKeyResp {
                key_kind,
                key_data: plaintext,
            },
            buf,
        )
    })?;

    Ok(resp)
}
