// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetCertChainInfo command handler.
//!
//! Returns the number of certificates and the chain thumbprint for a
//! partition's slot. This is a NoSession command.

use azihsm_fw_ddi_types::get_cert_chain_info::DdiGetCertChainInfoReq;
use azihsm_fw_ddi_types::get_cert_chain_info::DdiGetCertChainInfoResp;

use super::*;

/// Handle DdiGetCertChainInfoCmd.
///
/// 1. **Body decode** — Decodes `DdiGetCertChainInfoReq { slot_id }`.
///
/// 2. **Response** — Calls `pal.get_cert_chain_info(part_id, slot_id)`,
///    encodes `DdiGetCertChainInfoResp { num_certs, thumbprint }`.
pub(crate) async fn get_cert_chain_info<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let body: DdiGetCertChainInfoReq = decoder.decode_data()?;

    let info = pal.get_cert_chain_info(part_id, body.slot_id).await?;

    let resp_data = DdiGetCertChainInfoResp {
        num_certs: info.count,
        thumbprint: &info.thumbprint,
    };

    let len = ddi::encode_resp(
        ddi::success_hdr(hdr, DdiOp::GetCertChainInfo),
        resp_data,
        smem,
    )?;
    Ok(&smem[..len])
}
