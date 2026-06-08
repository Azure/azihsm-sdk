// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetApiRev` command handler.
//!
//! `GetApiRev` is the bootstrap TBOR command: it advertises the range
//! of TBOR wire-protocol versions this firmware understands. The
//! wire schema lives in [`azihsm_fw_ddi_tbor_types::get_api_rev`] —
//! the request body is empty (the derive emits a synthetic `none`
//! placeholder TOC entry), and the response carries `(min, max)`.

use azihsm_fw_ddi_tbor_types::TborGetApiRevReq;
use azihsm_fw_ddi_tbor_types::TborGetApiRevResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// Lowest TBOR wire-protocol version this firmware speaks.
pub(crate) const MIN_PROTOCOL_VERSION: u8 = 1;

/// Highest TBOR wire-protocol version this firmware speaks.
pub(crate) const MAX_PROTOCOL_VERSION: u8 = 1;

/// Handle a TBOR `GetApiRev` request.
///
/// Decodes the request through the shared schema (which enforces:
/// header parses, opcode matches, body is empty), then encodes the
/// `(MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION)` response into a
/// PAL-allocated buffer.  The synchronous body is wrapped in an
/// `async fn`-equivalent return so the dispatcher signature stays
/// uniform; this handler itself performs no async PAL work.
pub(crate) fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let _ = TborGetApiRevReq::decode(req_buf)?;
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborGetApiRevResp::encode(buf, 0, false)?
            .min_protocol_version(MIN_PROTOCOL_VERSION)?
            .max_protocol_version(MAX_PROTOCOL_VERSION)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
