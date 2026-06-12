// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetDeviceInfo command handler.
//!
//! Returns device kind, number of tables, and FIPS approval status.
//! This is a NoSession command — no session validation beyond hijack
//! protection (handled by io.rs).

use super::*;

/// Handle DdiGetDeviceInfoCmd.
///
/// 1. **Body decode** — Decodes `DdiGetDeviceInfoReq` (empty struct)
///    to verify no unexpected fields or trailing bytes.
///
/// 2. **Response** — Encodes `DdiGetDeviceInfoResp` with device kind,
///    table count, and FIPS status. Echoes `hdr.rev` back in the
///    response header.
pub(crate) fn get_device_info<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetDeviceInfoReq = decoder.decode_data()?;

    let resp_data = DdiGetDeviceInfoResp {
        kind: DdiDeviceKind::Physical,
        tables: crate::part_state::part_res_count(pal, io).unwrap_or(0),
        fips_approved: false,
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr(hdr, DdiOp::GetDeviceInfo),
            &resp_data,
            buf,
        )
    })?;
    Ok(resp)
}
