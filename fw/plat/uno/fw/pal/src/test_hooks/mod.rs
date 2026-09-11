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
//! core table, the wire types are in no core crate, and `mcr_test_hooks`
//! — the feature that turns the command on — is declared in this crate
//! alone. Without it this module is compiled out and uno's
//! `mbor_dispatch` rejects every opcode, so a production build answers
//! exactly as it would if the hook had never been added.
//!
//! # Layout
//!
//! - [`common`] — the `{0: hdr, 1: data}` envelope shared by every opcode.
//! - [`mbor_dispatch`] — the router: it decodes the envelope once, checks
//!   the opcode, and hands the body to the matching handler.
//! - [`test_action`] — the `TestAction` (`DdiOp` 2004) handler.
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
//! `TestAction` (`DdiOp` 2004) and its request / response types mirror
//! `mcr-hsm`'s definitions field-for-field, so the existing host-side
//! test suite drives either firmware unchanged.

mod common;
mod test_action;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::pal::UnoHsmPal;
use common::ReqHdr;

/// `DdiOp::TestAction` — matches `mcr-hsm`'s discriminant so the same
/// host tooling drives both firmwares.
const DDI_OP_TEST_ACTION: u32 = 2004;

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
/// - `Err(HsmError::DdiDecodeFailed)` — claimed, but the envelope or body
///   is malformed.
pub(crate) fn mbor_dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    req: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
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

    let hdr = ReqHdr::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    // Not ours. Give back the same answer the core would have.
    if hdr.op != DDI_OP_TEST_ACTION {
        return Err(HsmError::UnsupportedCmd);
    }

    let key = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if key != 1 {
        return Err(HsmError::DdiDecodeFailed);
    }

    // The decoder is now positioned at the body map; the handler owns it
    // from here.
    test_action::dispatch(pal, io, &hdr, &mut decoder, req_len)
}
