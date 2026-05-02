// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI SetSealedBk3 command handler.
//!
//! Stores the sealed BK3 blob on the partition. Returns
//! `SealedBk3AlreadySet` if one has already been stored, or
//! `SealedBk3TooLarge` if the blob exceeds 1024 bytes.

use azihsm_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Req;
use azihsm_fw_ddi_mbor_types::set_sealed_bk3::DdiSetSealedBk3Resp;

use super::*;

/// Handle DdiSetSealedBk3Cmd.
///
/// 1. **Already-set check** — `sealed_bk3 len != 0` → `SealedBk3AlreadySet`.
///
/// 2. **Body decode** — Decodes `DdiSetSealedBk3Req` with the blob.
///
/// 3. **Store** — Writes the blob via the PAL (validates size internally).
///
/// 4. **Response** — Encodes `DdiSetSealedBk3Resp` (empty) into `smem`.
pub(crate) fn set_sealed_bk3<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiSetSealedBk3Req<'_> = decoder.decode_data()?;
    pal.part_set_sealed_bk3(part_id, body.sealed_bk3)?;

    let resp_hdr = ddi::success_hdr(hdr, DdiOp::SetSealedBk3);
    let resp_data = DdiSetSealedBk3Resp {};

    let len = ddi::encode_resp(&resp_hdr, &resp_data, smem)?;
    Ok(&smem[..len])
}
