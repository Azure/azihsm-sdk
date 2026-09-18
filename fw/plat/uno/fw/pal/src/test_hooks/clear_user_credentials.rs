// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clear the partition's stored user credential.

use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartPropId;

use super::common::ReqHdr;
use super::test_action::encode_success;
use crate::pal::UnoHsmPal;

pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &MborDecoder,
    body_count: u8,
    req_len: usize,
) -> HsmResult<&'p DmaBuf> {
    decode_request(decoder, body_count, req_len)?;
    execute(pal, io, hdr)
}

fn decode_request(decoder: &MborDecoder, body_count: u8, req_len: usize) -> HsmResult<()> {
    if body_count != 1 || decoder.position() != req_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    Ok(())
}

fn execute<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
) -> HsmResult<&'p DmaBuf> {
    pal.part_prop_clear(io, PartPropId::CREDENTIAL)?;
    encode_success(pal, io, hdr)
}
