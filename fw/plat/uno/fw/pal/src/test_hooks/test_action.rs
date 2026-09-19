// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The `TestAction` (`DdiOp` 2004) handler.
//!
//! `TestAction` is an umbrella command: its body selects one of many
//! actions by id. Two actions are implemented on uno:
//!
//! - `ClearUserCredentials` (18) clears the partition's stored
//!   credential. It is served entirely below the PAL — it calls
//!   [`HsmPartitionManager::part_prop_clear`] on
//!   [`PartPropId::CREDENTIAL`], the same trait method the core's
//!   credential handlers already use, so `fw/core` is untouched. The
//!   next `EstablishCredential` / `ChangePin` sees the credential absent
//!   through the existing `part_is_credential_set` read.
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
//! without this hook" and skip, rather than acting on a placeholder
//! success the skip never actually happened.
//!
//! Every request is decoded far enough to read its action; only the
//! actions uno acts on are decoded in full. A claimed request can still
//! fail with a precise status: a malformed body gives
//! [`HsmError::DdiDecodeFailed`], and a `TriggerCrash` naming an
//! unimplemented crash type gives [`HsmError::InvalidArg`].

use core::convert::Infallible;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::PartPropId;

use super::common::ReqHdr;
use super::common::encode_resp;
use super::common::success_hdr;
use crate::pal::UnoHsmPal;

/// `DdiTestAction::TriggerCrash` — the crash-injection action.
const ACTION_TRIGGER_CRASH: u32 = 8;

/// `DdiTestAction::ClearUserCredentials` — clears the partition's stored
/// credential.
const ACTION_CLEAR_USER_CREDENTIALS: u32 = 18;

/// `DdiTestActionCrashType` discriminants.
const CRASH_HARD_FAULT: u32 = 1;
const CRASH_EXPLICIT: u32 = 2;
const CRASH_PANIC: u32 = 3;
const CRASH_HANG: u32 = 4;

/// `DdiTestActionSocCpuId::Hsm` — CP1, the core this firmware runs on.
const CPU_ID_HSM: u32 = 1;

/// `TestAction`'s crash parameters.
///
/// The enum-valued fields decode as raw `u32` rather than as `open_enum`
/// types: every value is legal on the wire, the handler rejects the ones
/// it does not implement anyway, and `open_enum`'s attribute expansion
/// does not compose with a derive helper under this crate's edition.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionCrashReqInfo {
    /// `DdiTestActionCrashType`.
    #[ddi(id = 1)]
    crash_type: u32,
    /// `DdiTestActionSocCpuId`.
    #[ddi(id = 2)]
    cpu_id: u32,
}

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
    let body_count = MborMap::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if body_count.0 == 0 {
        return Err(HsmError::DdiDecodeFailed);
    }
    let action_id = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if action_id != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }
    let action = u32::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    match action {
        ACTION_CLEAR_USER_CREDENTIALS => {
            // `{1: action}` and nothing else.
            if body_count.0 != 1 || decoder.position() != req_len {
                return Err(HsmError::DdiDecodeFailed);
            }

            // Clear the partition's stored credential below the PAL. The
            // target partition is resolved from `io`; the clear is
            // idempotent on an already-absent credential and zeroizes the
            // sensitive slot. The next credential read (the existing core
            // `part_is_credential_set`) then sees it absent — no `fw/core`
            // change is involved.
            pal.part_prop_clear(io, PartPropId::CREDENTIAL)?;

            let resp = pal.dma_alloc_var(io, |buf| {
                encode_resp(&success_hdr(hdr), &DdiTestActionResp { result: None }, buf)
            })?;
            Ok(resp)
        }
        ACTION_TRIGGER_CRASH => {
            // `{1: action, 2: crash_info}`.
            if body_count.0 != 2 {
                return Err(HsmError::DdiDecodeFailed);
            }
            let key = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
            if key != 2 {
                return Err(HsmError::DdiDecodeFailed);
            }
            let crash_info = DdiTestActionCrashReqInfo::mbor_decode(decoder)
                .map_err(|_| HsmError::DdiDecodeFailed)?;
            if decoder.position() != req_len {
                return Err(HsmError::DdiDecodeFailed);
            }

            // This firmware is CP1. Crashing another core needs a
            // cross-core request that does not exist yet, and crashing
            // the wrong one instead would make a test that targeted
            // Admin look like it passed.
            if crash_info.cpu_id != CPU_ID_HSM {
                return Err(HsmError::UnsupportedCmd);
            }

            // `trigger_crash` diverges; map its `Infallible` success into
            // this function's `&DmaBuf` success type, which is never
            // produced on this arm.
            trigger_crash(crash_info.crash_type).map(|never| match never {})
        }
        _ => Err(HsmError::UnsupportedCmd),
    }
}

/// Crash this core in the requested way.
///
/// Diverges for every known crash type. An unrecognised type is rejected
/// rather than mapped onto a default, so a host asking for something
/// this firmware does not implement finds out instead of silently
/// getting a different crash than it asked for.
///
/// `empty_loop` is allowed for the whole function rather than on the
/// `CRASH_HANG` arm: an attribute inside a match arm makes rustfmt brace
/// that one arm differently from its neighbours, and a spinning core is
/// the entire point of the hang variant.
#[allow(clippy::empty_loop)]
fn trigger_crash(crash_type: u32) -> HsmResult<Infallible> {
    match crash_type {
        CRASH_HANG => loop {},
        CRASH_PANIC | CRASH_EXPLICIT => {
            panic!("crash injected by TestAction::TriggerCrash");
        }
        CRASH_HARD_FAULT => {
            // SAFETY: `udf` is an undefined instruction with no operands
            // and no memory effects. Executing it raises UsageFault,
            // which escalates to HardFault, so control never returns —
            // hence `options(noreturn)`. Crashing this core is the
            // entire point of the command; there is nothing to unwind
            // or leave consistent.
            #[cfg(target_arch = "arm")]
            unsafe {
                core::arch::asm!("udf #0", options(noreturn));
            }
            #[cfg(not(target_arch = "arm"))]
            panic!("hard fault injected by TestAction::TriggerCrash");
        }
        _ => Err(HsmError::InvalidArg),
    }
}
