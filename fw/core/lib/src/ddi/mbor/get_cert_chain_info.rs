// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetCertChainInfo command handler.
//!
//! Returns the number of certificates and the chain thumbprint for a
//! partition's slot. This is a NoSession command.

use azihsm_fw_ddi_mbor_types::get_cert_chain_info::DdiGetCertChainInfoReq;
use azihsm_fw_ddi_mbor_types::get_cert_chain_info::DdiGetCertChainInfoResp;

use super::*;

/// Handle DdiGetCertChainInfoCmd.
///
/// 1. **Body decode** — Decodes `DdiGetCertChainInfoReq { slot_id }`.
///
/// 2. **Response** — Calls `pal.get_cert_chain_info(io, io.pid(), slot_id)`,
///    encodes `DdiGetCertChainInfoResp { num_certs, thumbprint }`.
pub(crate) async fn get_cert_chain_info<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiGetCertChainInfoReq = decoder.decode_data()?;

    let info = pal.get_cert_chain_info(io, io.pid(), body.slot_id).await?;

    let resp_data = DdiGetCertChainInfoResp {
        num_certs: info.count,
        thumbprint: &info.thumbprint,
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr(hdr, DdiOp::GetCertChainInfo),
            &resp_data,
            buf,
        )
    })?;
    Ok(resp)
}
