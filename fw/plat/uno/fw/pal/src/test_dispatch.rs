// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only DDI commands, reached through the
//! [`HsmCustomDispatch`](azihsm_fw_hsm_pal_traits::HsmCustomDispatch)
//! PAL hook.
//!
//! The core matches an incoming opcode against its own handlers first,
//! and offers the request here when that yields `UnsupportedCmd`. That
//! status usually means "no handler matched", but not always — a handler
//! for a known opcode can return it too — so this module claims strictly
//! by opcode and answers `UnsupportedCmd` for anything else, which is
//! what keeps it from shadowing a real command. This is where uno adds
//! commands that exist purely to drive testing.
//!
//! Nothing above the PAL knows any of this exists: the opcode is in no
//! core table, the wire types are in no core crate, and `mcr_test_action`
//! — the feature that turns the command on — is declared in this crate
//! alone. Without it the whole module is compiled out and the hook keeps
//! its default `UnsupportedCmd`, so a production build answers exactly
//! as it would if the hook had never been added.
//!
//! # Wire compatibility
//!
//! `TestAction` (`DdiOp` 2004) and its request types mirror `mcr-hsm`'s
//! definitions field-for-field, so the existing host-side crash suite
//! drives either firmware unchanged.
//!
//! Only the subset uno can act on is decoded. Every other opcode, and
//! every other `DdiTestAction`, returns [`HsmError::UnsupportedCmd`] —
//! the same answer the hook's default gives, so those are
//! indistinguishable from the hook not existing.
//!
//! A request that *is* claimed can still fail with a different status: a
//! malformed body gives [`HsmError::DdiDecodeFailed`], and a
//! `TriggerCrash` missing its `crash_info` gives
//! [`HsmError::InvalidArg`]. Those two are the only externally visible
//! evidence that this module is compiled in at all, which makes them
//! useful for checking a build without crashing it.

use core::convert::Infallible;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// `DdiOp::TestAction` — matches `mcr-hsm`'s discriminant so the same
/// host tooling drives both firmwares.
const DDI_OP_TEST_ACTION: u32 = 2004;

/// `DdiTestAction::TriggerCrash` — the only action uno implements.
const ACTION_TRIGGER_CRASH: u32 = 8;

/// `DdiTestActionCrashType` discriminants.
const CRASH_HARD_FAULT: u32 = 1;
const CRASH_EXPLICIT: u32 = 2;
const CRASH_PANIC: u32 = 3;
const CRASH_HANG: u32 = 4;

/// `DdiTestActionSocCpuId::Hsm` — CP1, the core this firmware runs on.
const CPU_ID_HSM: u32 = 1;

/// Mirrors the core's `DdiApiRev`.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct TestApiRev {
    #[ddi(id = 1)]
    major: u32,
    #[ddi(id = 2)]
    minor: u32,
}

/// The request header, mirroring the core's `DdiReqHdr` on the wire.
///
/// Redeclared here rather than imported: the core types crate must not
/// gain a `TestAction` opcode, and this module must not be the reason a
/// crate above the PAL grows a dependency or a feature.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct TestReqHdr {
    /// API revision — decoded to advance the cursor, not inspected.
    #[ddi(id = 1)]
    rev: Option<TestApiRev>,
    /// Opcode.
    #[ddi(id = 2)]
    op: u32,
    /// Session id, if any.
    #[ddi(id = 3)]
    sess_id: Option<u16>,
}

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

/// The `TestAction` request body.
///
/// `mcr-hsm`'s struct carries ten optional fields, one per action
/// family; only the two uno acts on are declared here.
///
/// Absent `Option` fields are omitted on the wire, so every request for
/// an action uno does not implement still decodes — the host sends
/// `{1: action}` and nothing else, and the handler answers
/// `UnsupportedCmd`. That covers the capability probe the upstream crash
/// suite opens with.
///
/// A request that *populates* one of the undeclared fields is a
/// different matter: map decoding is strict, so it fails with
/// [`HsmError::DdiDecodeFailed`] rather than reaching the handler and
/// reporting `UnsupportedCmd`. Both are errors and neither performs the
/// action, but the status is less precise. Declaring the remaining eight
/// would mean mirroring request types for actions this firmware cannot
/// perform and has no way to exercise, so the imprecision is preferred
/// to unverifiable type definitions.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionReq {
    /// `DdiTestAction`.
    #[ddi(id = 1)]
    action: u32,
    /// Present when `action` is `TriggerCrash`.
    #[ddi(id = 2)]
    crash_info: Option<DdiTestActionCrashReqInfo>,
}

/// Route an MBOR request the core did not claim.
///
/// Returns [`HsmError::UnsupportedCmd`] for anything not handled here,
/// which the core surfaces to the host exactly as if no hook existed.
///
/// Takes neither the platform nor the IO: the only implemented action
/// crashes this core, so nothing is ever allocated or awaited. An action
/// that answers would need both back, along with the response-encoding
/// surface.
///
/// # Parameters
///
/// - `req` — the whole request, envelope included.
///
/// # Returns
///
/// - `Err(HsmError::UnsupportedCmd)` — not handled here.
/// - `Err(HsmError::DdiDecodeFailed)` — claimed, but malformed.
/// - `Err(HsmError::InvalidArg)` — claimed and well-formed, but asking
///   for something this firmware cannot do.
///
/// The `Ok` type is [`Infallible`] because there is no success path:
/// the only implemented action crashes this core, so the function
/// either returns an error or never returns. Saying so in the type
/// avoids inventing a response lifetime — an earlier revision returned
/// `&'static DmaBuf`, which coerced to the trait's IO-scoped `&DmaBuf`
/// but implied this could hand back a global DMA buffer.
pub(crate) fn mbor_dispatch(req: &mut DmaBuf) -> HsmResult<Infallible> {
    let req_len = req.len();
    let mut decoder = MborDecoder::new(req);

    // Re-parse the envelope. The core already did this, but telling the
    // core anything about this command is precisely what the hook exists
    // to avoid.
    let count = MborMap::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if count.0 != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let key = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if key != 0 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let hdr = TestReqHdr::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    // Not ours. Give back the same answer the core would have.
    if hdr.op != DDI_OP_TEST_ACTION {
        return Err(HsmError::UnsupportedCmd);
    }

    let key = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if key != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let body =
        DdiTestActionReq::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    // Reject trailing bytes, matching `DdiDecoder::decode_data`, which
    // the core applies to every command it handles itself. Checked
    // *before* acting, because the only action this module implements
    // crashes the core — there is no chance to reconsider afterwards.
    //
    // `req_len` is the exact encoded length, not a buffer capacity: the
    // core hands over `req_buf[..src_len]` and enforces the same
    // "fully consumed" rule over that slice for its own commands.
    if decoder.position() != req_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    test_action(&body)
}

/// Perform a decoded `TestAction`.
///
/// Never returns `Ok`: the only implemented action crashes this core, so
/// there is no response to encode and the host observes the command by
/// the device going away rather than by a completion. That is also why
/// this needs no allocator.
fn test_action(req: &DdiTestActionReq) -> HsmResult<Infallible> {
    match req.action {
        ACTION_TRIGGER_CRASH => {
            let info = req.crash_info.as_ref().ok_or(HsmError::InvalidArg)?;

            // This firmware is CP1. Crashing another core needs a
            // cross-core request that does not exist yet, and crashing
            // the wrong one instead would make a test that targeted
            // Admin look like it passed.
            if info.cpu_id != CPU_ID_HSM {
                return Err(HsmError::UnsupportedCmd);
            }

            trigger_crash(info.crash_type)
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
