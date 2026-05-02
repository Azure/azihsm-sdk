// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetSealedBk3 command handler.
//!
//! Returns the sealed BK3 blob stored on the partition, or
//! `SealedBk3NotPresent` if none has been set.
//!
//! Uses the encode-frame-then-fill pattern: the response blob is
//! filled directly into the encoder-reserved slot — zero intermediate
//! copies.

use azihsm_fw_ddi_mbor_types::get_sealed_bk3::DdiGetSealedBk3Req;
use azihsm_fw_ddi_mbor_types::get_sealed_bk3::DdiGetSealedBk3Resp;

use super::*;

/// Handle DdiGetSealedBk3Cmd.
///
/// 1. **Body decode** — Decodes `DdiGetSealedBk3Req` (empty struct).
///
/// 2. **Presence check** — `sealed_bk3 len == 0` → `SealedBk3NotPresent`.
///
/// 3. **Response** — Encodes header + frame, fills blob in-place.
pub(crate) fn get_sealed_bk3<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetSealedBk3Req = decoder.decode_data()?;

    let sealed_len = pal.part_sealed_bk3(part_id, None)?;
    if sealed_len == 0 {
        return Err(HsmError::SealedBk3NotPresent);
    }

    let mut encoder = ddi::encode_resp_hdr(&ddi::success_hdr(hdr, DdiOp::GetSealedBk3), smem)?;
    let frame = DdiGetSealedBk3Resp::frame(&mut encoder, sealed_len)?;
    let total = encoder.position();

    pal.part_sealed_bk3(part_id, Some(frame.sealed_bk3))?;

    Ok(&smem[..total])
}
