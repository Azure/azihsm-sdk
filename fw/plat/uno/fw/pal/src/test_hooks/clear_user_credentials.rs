// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clear the partition's stored user credential.

use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionLock;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartPropId;

use super::common::ReqHdr;
use super::test_action::encode_success;
use super::test_action::expect_empty_payload;
use crate::pal::UnoHsmPal;

/// Validate and execute `TestAction::ClearUserCredentials`.
pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    expect_empty_payload(decoder, request_field_count, request_len)?;
    execute(pal, io, hdr).await
}

async fn execute<'p>(pal: &'p UnoHsmPal, io: &impl HsmIo, hdr: &ReqHdr) -> HsmResult<&'p DmaBuf> {
    // Serialize with EstablishCredential/ChangePin, which hold this lock
    // across their own validation and CREDENTIAL commit: without it, a
    // concurrent request could interleave with the clear below and leave
    // provisioning/session state inconsistent.
    let _lock = pal.partition_lock(io).await?;

    // Prepare the response before mutating credential state so an allocation
    // or encoding failure cannot clear the credential and return an error.
    let resp = encode_success(pal, io, hdr)?;
    pal.part_prop_clear(io, PartPropId::CREDENTIAL)?;
    Ok(resp)
}
