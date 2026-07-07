// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetApiRev command handler.
//!
//! Validates the request (rev must be None, body must be empty),
//! builds a response with the supported API revision range, and
//! MBOR-encodes it into a heap-allocated response buffer.

use super::*;

/// Handle DdiGetApiRevCmd.
///
/// Validates the request then builds and encodes the response:
///
/// 1. **Rev check** — `hdr.rev` must be `None`. GetApiRev is the
///    bootstrapping command — the caller doesn't know the revision yet.
///
/// 2. **Body decode** — Decodes `DdiGetApiRevReq` (empty struct) to
///    verify the request body contains no unexpected fields and no
///    trailing bytes.
///
/// 3. **Response** — Encodes `DdiGetApiRevCmdResp` with min/max API
///    revision into a heap-allocated response buffer.
pub(crate) fn get_api_rev<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    // GetApiRev is the bootstrap command — rev must not be set.
    if hdr.rev.is_some() {
        return Err(HsmError::UnsupportedRevision);
    }

    // Decode the body to ensure it is a valid empty map with no
    // trailing bytes (rejects malformed requests).
    let _body: DdiGetApiRevReq = decoder.decode_data()?;

    let resp_data = DdiGetApiRevResp {
        min: super::DDI_API_REV_MIN,
        max: super::DDI_API_REV_MAX,
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(&super::success_hdr(hdr, DdiOp::GetApiRev), &resp_data, buf)
    })?;

    Ok(resp)
}
