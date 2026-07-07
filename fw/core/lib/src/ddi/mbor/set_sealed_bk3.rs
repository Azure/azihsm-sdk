// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI SetSealedBk3 command handler.
//!
//! Stores the sealed BK3 blob on the partition. Returns
//! `SealedBk3AlreadySet` if one has already been stored, or
//! `SealedBk3TooLarge` if the blob exceeds the PAL's
//! [`SEALED_BK3_MAX_LEN`](azihsm_fw_pal_traits::SEALED_BK3_MAX_LEN)
//! bound.

use azihsm_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Req;
use azihsm_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Resp;
use azihsm_fw_hsm_pal_traits::SEALED_BK3_MAX_LEN;

use super::*;

/// Handle DdiSetSealedBk3Cmd.
///
/// 1. **Body decode** — Decodes `DdiSetSealedBk3Req` with the blob.
///
/// 2. **Size check** — Rejects blobs larger than
///    [`SEALED_BK3_MAX_LEN`] with `SealedBk3TooLarge` before the
///    PAL property setter (which would otherwise surface the
///    overflow as the generic `InvalidArg`).
///
/// 3. **Already-set check** — `SetSealedBk3` is write-once per
///    power cycle; the PAL setter returns `SealedBk3AlreadySet` if
///    a blob is already stored.
///
/// 4. **Store** — Writes the blob via the PAL.
///
/// 5. **Response** — Encodes `DdiSetSealedBk3Resp` (empty) into a
///    heap-allocated response buffer.
pub(crate) fn set_sealed_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiSetSealedBk3Req<'_> = decoder.decode_data()?;

    if body.sealed_bk3.len() > usize::from(SEALED_BK3_MAX_LEN) {
        return Err(HsmError::SealedBk3TooLarge);
    }

    crate::part_state::part_set_sealed_bk3(pal, io, body.sealed_bk3)?;

    let resp_hdr = super::success_hdr(hdr, DdiOp::SetSealedBk3);
    let resp_data = DdiSetSealedBk3Resp {};

    let resp = pal.dma_alloc_var(io, |buf| super::encode_resp(&resp_hdr, &resp_data, buf))?;

    Ok(resp)
}
