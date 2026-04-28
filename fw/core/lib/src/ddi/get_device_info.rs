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
pub(crate) fn get_device_info<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetDeviceInfoReq = decoder.decode_data()?;

    let resp_data = DdiGetDeviceInfoResp {
        kind: DdiDeviceKind::Physical,
        tables: pal.part_res_count(part_id).unwrap_or(0),
        fips_approved: false,
    };

    let len = ddi::encode_resp(ddi::success_hdr(hdr, DdiOp::GetDeviceInfo), resp_data, smem)?;

    Ok(&smem[..len])
}
