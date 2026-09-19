// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction` (`DdiOp` 2004) action router.
//!
//! The outer request body has the stable `{1: action, 2: payload?}` shape.
//! This module decodes the action ID and routes the remaining body to the
//! action-specific module that owns its validation and behavior.

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

use super::clear_user_credentials;
use super::common::encode_resp;
use super::common::success_hdr;
use super::common::ReqHdr;
use super::trigger_crash;
use crate::pal::UnoHsmPal;

/// The response body shared by `TestAction` variants.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionResp {
    #[ddi(id = 1)]
    result: Option<u32>,
}

/// Test actions implemented by the Uno PAL.
///
/// Only actions with a compiled handler belong here. Unknown and
/// unimplemented action IDs remain indistinguishable and return
/// [`HsmError::UnsupportedCmd`].
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum SupportedTestAction {
    TriggerCrash = 8,
    ClearUserCredentials = 18,
}

#[derive(Debug, Copy, Clone)]
struct TestActionSelector {
    action: SupportedTestAction,
    body_count: u8,
}

impl TryFrom<u32> for SupportedTestAction {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Self::TriggerCrash as u32 {
            Ok(Self::TriggerCrash)
        } else if value == Self::ClearUserCredentials as u32 {
            Ok(Self::ClearUserCredentials)
        } else {
            Err(HsmError::UnsupportedCmd)
        }
    }
}

/// Decode the action selector and route the action-specific body.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder,
    req_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let selector = decode_action_selector(decoder)?;

    match selector.action {
        SupportedTestAction::ClearUserCredentials => clear_user_credentials::dispatch(
            pal,
            io,
            hdr,
            decoder,
            selector.body_count,
            req_len,
        ),
        SupportedTestAction::TriggerCrash => {
            trigger_crash::dispatch(decoder, selector.body_count, req_len)
                .map(|never| match never {})
        }
    }
}

fn decode_action_selector(decoder: &mut MborDecoder) -> HsmResult<TestActionSelector> {
    let body_count = MborMap::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if body_count.0 == 0 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let action_key = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if action_key != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }
    let action = u32::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    let action = SupportedTestAction::try_from(action)?;

    Ok(TestActionSelector {
        action,
        body_count: body_count.0,
    })
}

/// Encode a successful action response with no action-specific result.
pub(super) fn encode_success<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        encode_resp(
            &success_hdr(hdr, None),
            &DdiTestActionResp { result: None },
            buf,
        )
    })?;
    Ok(resp)
}
