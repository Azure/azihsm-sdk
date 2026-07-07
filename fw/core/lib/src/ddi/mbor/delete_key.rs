// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI DeleteKey command handler.
//!
//! Within an open session, delete a vault-resident key by id.
//!
//! Internal device keys (the partition's unwrapping key, session and
//! credential keys, etc. — anything carrying the `internal` attribute)
//! cannot be destroyed by the host and are rejected with
//! `CannotDeleteInternalKeys`.  An unknown `key_id` is rejected with
//! `KeyNotFound`.

use azihsm_fw_ddi_mbor_types::delete_key::DdiDeleteKeyReq;
use azihsm_fw_ddi_mbor_types::delete_key::DdiDeleteKeyResp;

use super::*;

/// Handle `DdiDeleteKeyCmd`.
///
/// No `partition_lock` is needed: the `internal`-attribute check and
/// the [`HsmVault::vault_key_delete`] mutation are both synchronous
/// with no yield point between them, so there is no read-then-mutate
/// window that could race against a concurrent handler on the same
/// partition.
pub(crate) async fn delete_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiDeleteKeyReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let key_id = HsmKeyId::from(body.key_id);

    // Resolve the key's attributes first — an unknown id surfaces as
    // `KeyNotFound`.  Internal device keys are never host-destroyable.
    if pal.vault_key_attrs(io, key_id)?.internal() {
        return Err(HsmError::CannotDeleteInternalKeys);
    }
    pal.vault_key_delete(io, key_id).await?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::DeleteKey, sess_id),
            &DdiDeleteKeyResp {},
            buf,
        )
    })?;
    Ok(resp)
}
