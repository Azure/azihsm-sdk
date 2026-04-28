// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetApiRev command handler.
//!
//! Validates the request (rev must be None, body must be empty),
//! builds a response with the supported API revision range, and
//! MBOR-encodes it into `smem`.

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
///    revision into `smem`.
pub(crate) fn get_api_rev<'a>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    _fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    // GetApiRev is the bootstrap command — rev must not be set.
    if hdr.rev.is_some() {
        return Err(HsmError::UnsupportedRevision);
    }

    // Decode the body to ensure it is a valid empty map with no
    // trailing bytes (rejects malformed requests).
    let _body: DdiGetApiRevReq = decoder.decode_data()?;

    let resp_data = DdiGetApiRevResp {
        min: DdiApiRev { major: 1, minor: 0 },
        max: DdiApiRev { major: 1, minor: 0 },
    };

    let len = ddi::encode_resp(ddi::success_hdr(hdr, DdiOp::GetApiRev), resp_data, smem)?;

    Ok(&smem[..len])
}
