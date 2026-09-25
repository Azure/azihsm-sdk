// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clear the partition's stored user credential.

use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartPropId;

use super::common::ReqHdr;
use super::test_action::encode_success;
use super::test_action::expect_no_payload;
use crate::pal::UnoHsmPal;

/// Validate and execute `TestAction::ClearUserCredentials`.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &MborDecoder,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    expect_no_payload(decoder, request_field_count, request_len)?;
    execute(pal, io, hdr)
}

fn execute<'p>(pal: &'p UnoHsmPal, io: &impl HsmIo, hdr: &ReqHdr) -> HsmResult<&'p DmaBuf> {
    // Prepare the response before mutating credential state so an allocation
    // or encoding failure cannot clear the credential and return an error.
    let resp = encode_success(pal, io, hdr)?;
    pal.part_prop_clear(io, PartPropId::CREDENTIAL)?;
    Ok(resp)
}
