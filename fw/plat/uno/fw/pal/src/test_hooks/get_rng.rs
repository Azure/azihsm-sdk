// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction::GetRng` FIPS-validation hook.
//!
//! Returns up to 64 random bytes within a live session. The core validates
//! the session and API revision before offering the request to this hook.
//! Random bytes are written directly into the DMA-backed response frame.

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRng;

use super::common::ReqHdr;
use super::common::encode_resp_hdr;
use super::common::success_hdr;
use crate::pal::UnoHsmPal;

/// Maximum requested random output length in bytes.
const MAX_RNG_NUMBER_SIZE: usize = 64;

/// Action-specific `GetRng` request data.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiGetRngReq {
    /// Requested output length in bytes.
    #[ddi(id = 1)]
    rng_len: u8,
}

/// Typed response data for `GetRng`.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiGetRngResp<'a> {
    /// Random output, padded to the MBOR variable-byte-string alignment.
    #[ddi(id = 1, max_len = 64)]
    rng_number: &'a [u8],
}

/// Handle the nested `GetRng` TestAction payload.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let request = DdiGetRngReq::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if decoder.position() != request_len {
        return Err(HsmError::DdiDecodeFailed);
    }
    let rng_len = output_len(request.rng_len)?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = encode_resp_hdr(&success_hdr(hdr, Some(sess_id)), buf)?;
        let layout = DdiGetRngResp::reserve(&mut encoder, rng_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiGetRngResp::from_layout(resp, &layout);
    if let Err(error) = pal.rng_fill_bytes(io, frame.rng_number) {
        frame.rng_number.zeroize();
        return Err(error);
    }
    Ok(resp)
}

const fn output_len(rng_len: u8) -> HsmResult<usize> {
    let len = rng_len as usize;
    if len > MAX_RNG_NUMBER_SIZE {
        Err(HsmError::InvalidArg)
    } else {
        Ok(len)
    }
}

// This firmware crate has no runtime unit-test target.
const _: () = {
    assert!(matches!(output_len(0), Ok(0)));
    assert!(matches!(output_len(1), Ok(1)));
    assert!(matches!(output_len(32), Ok(32)));
    assert!(matches!(output_len(64), Ok(64)));
    assert!(matches!(output_len(65), Err(HsmError::InvalidArg)));
    assert!(matches!(output_len(u8::MAX), Err(HsmError::InvalidArg)));
};
