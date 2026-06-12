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
pub(crate) fn get_sealed_bk3<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetSealedBk3Req = decoder.decode_data()?;

    let sealed_len = match crate::part_state::part_sealed_bk3(pal, io) {
        Ok(bytes) => bytes.len(),
        Err(HsmError::PartPropNotFound) => return Err(HsmError::SealedBk3NotPresent),
        Err(e) => return Err(e),
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        let mut encoder =
            super::encode_resp_hdr(&super::success_hdr(hdr, DdiOp::GetSealedBk3), buf)?;
        let frame = DdiGetSealedBk3Resp::frame(&mut encoder, sealed_len)?;
        let total = encoder.position();
        let bytes = crate::part_state::part_sealed_bk3(pal, io)?;
        frame.sealed_bk3.copy_from_slice(&bytes[..sealed_len]);
        Ok(total)
    })?;

    Ok(resp)
}
