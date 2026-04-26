// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) mod get_api_rev;
pub(crate) mod get_device_info;

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborLen;
use azihsm_fw_ddi_mbor::MborLenAccumulator;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_types::error::DdiErrResp;
use azihsm_fw_ddi_types::*;
pub(crate) use get_api_rev::*;
pub(crate) use get_device_info::*;

use super::*;
use crate::error::*;

/// Dispatch a DDI command to its handler.
///
/// Returns the response length on success, or the original [`HsmError`]
/// on failure. The caller wraps failures in a DDI error response.
pub(crate) fn dispatch(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: u8,
    pal: &Pal,
    fmem: &mut [u8],
    smem: &mut [u8],
) -> HsmResult<usize> {
    let resp = match hdr.op {
        DdiOp::GetApiRev => get_api_rev(hdr, decoder, fmem, smem)?,
        DdiOp::GetDeviceInfo => get_device_info(hdr, decoder, part_id, pal, fmem, smem)?,
        _ => return Err(DDI_UNKNOWN_OP),
    };
    Ok(resp.len())
}

/// Map an [`HsmError`] from a DDI handler to the corresponding [`DdiStatus`].
pub(crate) fn ddi_status(err: HsmError) -> DdiStatus {
    match err {
        DDI_DECODE_FAILURE => DdiStatus::DdiDecodeFailed,
        DDI_ENCODE_FAILURE => DdiStatus::DdiEncodeFailed,
        DDI_UNKNOWN_OP => DdiStatus::UnsupportedCmd,
        DDI_UNSUPPORTED_REV => DdiStatus::UnsupportedRevision,
        DDI_INVALID_ARGUMENT => DdiStatus::InvalidArg,
        DDI_SESSION_NOT_EXPECTED => DdiStatus::SessionNotExpected,
        _ => DdiStatus::InternalError,
    }
}

/// Encode a DDI response (header + data) with a single upfront bounds check.
///
/// Computes the total encoded length via [`MborLen`], checks it fits in
/// `smem`, then encodes with no per-field bounds checks. Returns the
/// encoded length, or [`DDI_ENCODE_FAILURE`] if the buffer is too small.
pub(crate) fn encode_resp<H, D>(hdr: H, data: D, smem: &mut [u8]) -> HsmResult<usize>
where
    H: MborEncode + MborLen,
    D: MborEncode + MborLen,
{
    // Pre-compute total length
    let mut acc = MborLenAccumulator::default();
    MborMap(2).mbor_len(&mut acc); // outer Map(2)
    0u8.mbor_len(&mut acc); // key=0
    hdr.mbor_len(&mut acc); // header map
    1u8.mbor_len(&mut acc); // key=1
    data.mbor_len(&mut acc); // data map
    let total = acc.len();

    // Single bounds check
    if total > smem.len() {
        return Err(DDI_ENCODE_FAILURE);
    }

    // Encode — trusted mode: single upfront bounds check means
    // per-field checks are redundant.
    let mut encoder = MborEncoder::new_trusted(smem);
    MborMap(2)
        .mbor_encode(&mut encoder)
        .map_err(|_| DDI_ENCODE_FAILURE)?;
    0u8.mbor_encode(&mut encoder)
        .map_err(|_| DDI_ENCODE_FAILURE)?;
    hdr.mbor_encode(&mut encoder)
        .map_err(|_| DDI_ENCODE_FAILURE)?;
    1u8.mbor_encode(&mut encoder)
        .map_err(|_| DDI_ENCODE_FAILURE)?;
    data.mbor_encode(&mut encoder)
        .map_err(|_| DDI_ENCODE_FAILURE)?;

    Ok(total)
}

/// Encode a DDI error response into `smem`.
///
/// Writes `DdiRespHdr { op, status } + DdiErrResp {}` and returns the
/// encoded length. Used for post-decode errors where the host expects
/// a DDI response body (not just a CQE status code).
///
/// Returns [`DDI_ENCODE_FAILURE`] if the buffer is too small.
pub(crate) fn encode_ddi_err(op: DdiOp, status: DdiStatus, smem: &mut [u8]) -> HsmResult<usize> {
    let hdr = DdiRespHdr {
        rev: None,
        op,
        sess_id: None,
        status,
        fips_approved: false,
    };
    let data = DdiErrResp {};
    DdiEncoder::encode_parts(hdr, data, smem).map_err(|_| DDI_ENCODE_FAILURE)
}
