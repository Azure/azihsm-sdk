// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertChainInfo` command handler.
//!
//! Out-of-session info command — the TBOR analogue of MBOR
//! `GetCertChainInfo`.  Returns the number of certificates and the
//! leaf-certificate SHA-256 thumbprint for the caller's partition at the
//! requested chain slot.  No session is required; the chain is read for
//! the caller's own bound partition (`io.pid()`), mirroring the MBOR
//! handler.
//!
//! The handler is `async` because the underlying
//! [`HsmCertStore::get_cert_chain_info`](azihsm_fw_hsm_pal_traits::HsmCertStore::get_cert_chain_info)
//! is async.

use azihsm_fw_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_fw_ddi_tbor_types::TborGetCertChainInfoResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `GetCertChainInfo` request.
///
/// Slot 2 generates a fresh PID leaf and fingerprints it; because each read
/// mints a new leaf, later reads need not match this fingerprint. No undo
/// log is needed.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborGetCertChainInfoReq::decode(req_buf)?;
    let slot_id = req.slot_id();

    let info = if slot_id == 2 {
        super::pta::chain_info(pal, io).await?
    } else {
        pal.get_cert_chain_info(io, io.pid(), slot_id).await?
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborGetCertChainInfoResp::encode(buf, 0, false)?
            .num_certs(info.count)?
            .thumbprint(&info.thumbprint)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
