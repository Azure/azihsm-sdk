// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ApiRev` command handler.
//!
//! `ApiRev` is the bootstrap TBOR command: it advertises the range
//! of TBOR wire-protocol versions this firmware understands. The
//! wire schema lives in [`azihsm_fw_ddi_tbor_types::api_rev`] —
//! the request body is empty (the derive emits a synthetic `none`
//! placeholder TOC entry), and the response carries `(min, max)`.

use azihsm_fw_ddi_tbor_types::TborApiRevResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// Lowest TBOR wire-protocol version this firmware speaks.
pub(crate) const MIN_PROTOCOL_VERSION: u8 = 1;

/// Highest TBOR wire-protocol version this firmware speaks.
pub(crate) const MAX_PROTOCOL_VERSION: u8 = 1;

/// Handle a TBOR `ApiRev` request.
///
/// The caller (`dispatch`) has already structurally validated the
/// buffer via [`RequestView::parse`] and confirmed the opcode is
/// `API_REV`. This handler performs a lightweight opcode
/// assertion (defense-in-depth) and encodes the
/// `(MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION)` response.
pub(crate) fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // Defense-in-depth: verify the opcode matches without a full
    // re-parse.  The header structure was already validated by the
    // upstream `RequestView::parse` in `handle_tbor_op`.
    debug_assert_eq!(req_buf[3], 0x01, "opcode mismatch in api_rev");

    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborApiRevResp::encode(buf, 0, false)?
            .min_ver(MIN_PROTOCOL_VERSION)?
            .max_ver(MAX_PROTOCOL_VERSION)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
