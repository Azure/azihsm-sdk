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
pub(crate) fn get_device_info<'a>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: u8,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetDeviceInfoReq = decoder.decode_data().map_err(|_| DDI_DECODE_FAILURE)?;

    let resp_hdr = DdiRespHdr {
        rev: hdr.rev,
        op: DdiOp::GetDeviceInfo,
        sess_id: None,
        status: DdiStatus::Success,
        fips_approved: false,
    };

    let resp_data = DdiGetDeviceInfoResp {
        kind: DdiDeviceKind::Physical,
        // `tables` is encoded as a `u8`, so avoid wrapping when `part_id`
        // is unexpectedly `u8::MAX`.
        tables: part_id.saturating_add(1),
        fips_approved: false,
    };

    let len = ddi::encode_resp(resp_hdr, resp_data, smem).map_err(|_| DDI_ENCODE_FAILURE)?;

    Ok(&smem[..len])
}
