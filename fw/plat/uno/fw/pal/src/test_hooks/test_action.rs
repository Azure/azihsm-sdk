// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction` (`DdiOp` 2004) action router.
//!
//! `TestAction` is an umbrella command: its body selects one of many
//! actions by id. This module decodes that selector and routes the
//! remaining body to the action-specific module that owns its validation
//! and behavior.
//!
//! - `ClearUserCredentials` (18) clears the partition's stored
//!   credential.
//! - `TriggerCrash` (8) crashes this core.
//!
//! Every other action is answered with [`HsmError::UnsupportedCmd`], the
//! same status the hook gives for an unknown opcode, so an unimplemented
//! action is indistinguishable from the hook not being built.
//!
//! `Level1SkipIo` (action 1) is deliberately *not* claimed. Its effect —
//! aborting a later, separate IO — is decided inside `fw/core`'s IO loop,
//! which reads no below-PAL fault flag, so a PAL hook cannot produce it.
//! Answering `UnsupportedCmd` lets the host read it as "firmware built
//! without this hook" and skip, rather than accepting placeholder success
//! when the skip never happened.
//!
//! Every request is decoded far enough to read its action; only the
//! selected action module decodes the rest.

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
use super::common::ReqHdr;
use super::common::encode_resp;
use super::common::success_hdr;
use super::trigger_crash;
use crate::pal::UnoHsmPal;

/// The `TestAction` response body.
///
/// `result` is an optional 4-byte out-param some actions return; it is
/// `None` for actions that report only success or failure through the
/// header status, such as `ClearUserCredentials`.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionResp {
    #[ddi(id = 1)]
    result: Option<u32>,
}

/// Test actions implemented by the Uno PAL.
///
/// Only actions with a compiled handler belong here. Unknown and
/// unimplemented action IDs return [`HsmError::UnsupportedCmd`].
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

/// Dispatch a `TestAction` body.
///
/// The decoder is positioned at the body map `{1: action, ...}`, whose
/// first entry is always `{1: action}` followed by at most one
/// action-specific field. Only the action is decoded up front, then the
/// arm that claims it reads the rest: map decode is strict — it rejects
/// any field a decoded struct does not declare — so decoding the whole
/// body here would turn an action whose field this firmware does not
/// declare into `DdiDecodeFailed`, when `UnsupportedCmd` (which the host
/// reads as "not built" and skips) is the answer those need.
///
/// `hdr` is the already-decoded request header, echoed into a response.
/// `req_len` is the exact encoded length — the core hands over
/// `req_buf[..src_len]` — used to reject trailing bytes before acting.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder,
    req_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let selector = decode_action_selector(decoder)?;

    match selector.action {
        SupportedTestAction::ClearUserCredentials => {
            clear_user_credentials::dispatch(pal, io, hdr, decoder, selector.body_count, req_len)
        }
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
    let action_id = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if action_id != 1 {
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
        encode_resp(&success_hdr(hdr), &DdiTestActionResp { result: None }, buf)
    })?;
    Ok(resp)
}
