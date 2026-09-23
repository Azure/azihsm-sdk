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
//! core table and the wire types are in no core crate. `TestAction` is
//! gated by `mcr_test_hooks`; `GetPrivKey` and `RawKeyImport` are gated by
//! `fips_validation_hooks`. With neither feature this module is compiled
//! out and uno rejects every custom opcode.
//!
//! # Layout
//!
//! - [`common`] — the `{0: hdr, 1: data}` envelope shared by every opcode.
//! - [`mbor_dispatch`] — the router: it decodes the envelope once, checks
//!   the opcode, and hands the request data to the matching handler.
//! - [`test_action`] — the `TestAction` (`DdiOp` 2004) handler.
//! - [`get_priv_key`] / [`raw_key_import`] — FIPS-validation handlers.
//!
//! # `TestAction` is an in-session command
//!
//! The core classifies any opcode it does not know as
//! `DdiSessionKind::User`, and the IO layer runs session validation
//! before dispatch. So a request sent without a live session fails that
//! check and never reaches this module — it surfaces as a session error
//! rather than anything from here. `mcr-hsm`'s host-side callers already
//! open a session first, so this is a constraint to know about rather
//! than one to work around.
//!
//! # Wire compatibility
//!
//! `TestAction` (`DdiOp` 2004) uses an **opaque-payload** request:
//! `{1: action, 2: payload?}`, where `payload` is a byte string holding
//! the MBOR encoding of the chosen action's own request-info map. The
//! opcode's wire schema is therefore fixed no matter which action is sent,
//! so adding an action never changes it. This intentionally **diverges
//! from `mcr-hsm`**, which still carries each action's parameters as typed
//! map entries: the two firmwares are no longer wire-compatible for
//! `TestAction`. This firmware is driven by the refactor's own
//! `azihsm_ddi_mbor_test_hooks` host crate, which encodes the matching opaque
//! request; the response stays `{1: result?}`.

#[cfg(feature = "mcr_test_hooks")]
mod clear_user_credentials;
mod common;
#[cfg(feature = "fips_validation_hooks")]
mod get_priv_key;
#[cfg(feature = "fips_validation_hooks")]
mod raw_key_import;
#[cfg(feature = "mcr_test_hooks")]
mod test_action;
#[cfg(feature = "mcr_test_hooks")]
mod trigger_crash;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use common::ReqHdr;

use crate::pal::UnoHsmPal;

/// `DdiOp::TestAction` — matches `mcr-hsm`'s discriminant so the same
/// host tooling drives both firmwares.
#[cfg(feature = "mcr_test_hooks")]
const DDI_OP_TEST_ACTION: u32 = 2004;
/// `DdiOp::GetPrivKey`.
#[cfg(feature = "fips_validation_hooks")]
const DDI_OP_GET_PRIV_KEY: u32 = 2005;
/// `DdiOp::RawKeyImport`.
#[cfg(feature = "fips_validation_hooks")]
const DDI_OP_RAW_KEY_IMPORT: u32 = 2008;

fn handles_opcode(opcode: u32) -> bool {
    match opcode {
        #[cfg(feature = "mcr_test_hooks")]
        DDI_OP_TEST_ACTION => true,
        #[cfg(feature = "fips_validation_hooks")]
        DDI_OP_GET_PRIV_KEY | DDI_OP_RAW_KEY_IMPORT => true,
        _ => false,
    }
}

/// Route an MBOR request the core did not claim.
///
/// Decodes the `{0: hdr, 1: data}` envelope, then dispatches on the
/// opcode. Returns [`HsmError::UnsupportedCmd`] for any opcode not
/// handled here, which the core surfaces to the host exactly as if no
/// hook existed.
///
/// # Parameters
///
/// - `pal` — the platform, for response allocation by handlers that answer.
/// - `io` — the IO whose arena backs a handler's response buffer.
/// - `req` — the whole request, envelope included.
///
/// # Returns
///
/// - `Ok(&DmaBuf)` — a claimed opcode that answers with a response.
/// - `Err(HsmError::UnsupportedCmd)` — not handled here.
/// - `Err(HsmError::DdiDecodeFailed)` — claimed, but the envelope or
///   request data is malformed.
pub(crate) async fn mbor_dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    req: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let request_len = req.len();
    let mut decoder = MborDecoder::new(req);

    // Re-parse the envelope. The core already did this, but telling the
    // core anything about this command is precisely what the hook exists
    // to avoid.
    let envelope_field_count =
        MborMap::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if envelope_field_count.0 != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let field_id = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if field_id != 0 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let hdr = ReqHdr::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    // Not ours. Give back the same answer the core would have. Claim
    // strictly by opcode so a known core command that returned
    // `UnsupportedCmd` can never be shadowed here.
    if !handles_opcode(hdr.op) {
        return Err(HsmError::UnsupportedCmd);
    }

    let result = async {
        let field_id = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
        if field_id != 1 {
            return Err(HsmError::DdiDecodeFailed);
        }

        // The decoder is now positioned at the request data map; the selected
        // handler owns it from here.
        match hdr.op {
            #[cfg(feature = "mcr_test_hooks")]
            DDI_OP_TEST_ACTION => test_action::dispatch(pal, io, &hdr, &mut decoder, request_len),
            #[cfg(feature = "fips_validation_hooks")]
            DDI_OP_GET_PRIV_KEY => get_priv_key::dispatch(pal, io, &hdr, &mut decoder, request_len),
            #[cfg(feature = "fips_validation_hooks")]
            DDI_OP_RAW_KEY_IMPORT => {
                raw_key_import::dispatch(pal, io, &hdr, &mut decoder, request_len).await
            }
            _ => Err(HsmError::UnsupportedCmd),
        }
    }
    .await;

    #[cfg(feature = "fips_validation_hooks")]
    if hdr.op == DDI_OP_RAW_KEY_IMPORT {
        // Once the header identifies RawKeyImport, wipe the complete inbound
        // request on every later exit. This includes malformed or truncated
        // data-field IDs as well as request-body decode and dispatch failures.
        req.zeroize();
    }

    result
}
