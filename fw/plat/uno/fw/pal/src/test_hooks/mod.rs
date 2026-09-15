// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Below-PAL test / validation-hook DDI commands, reached through the
//! [`HsmCustomDispatch`](azihsm_fw_hsm_pal_traits::HsmCustomDispatch)
//! PAL hook.
//!
//! The core matches an incoming opcode against its own handlers first,
//! and offers the request here when that yields `UnsupportedCmd`. That
//! status usually means "no handler matched", but a handler for a known
//! opcode can return it too, so this module claims strictly by opcode
//! and answers `UnsupportedCmd` for anything else — which is what keeps
//! it from shadowing a real command.
//!
//! Nothing above the PAL knows any of this exists: the opcodes are in no
//! core table, the wire types are in no core crate, and the feature that
//! turns the commands on is declared in this crate alone. Without it this
//! module is compiled out and uno's `mbor_dispatch` rejects every opcode,
//! so a production build answers exactly as it would if the hook had
//! never been added.
//!
//! # Structure
//!
//! One flat module per opcode plus a shared [`common`] envelope, all
//! routed by [`mbor_dispatch`]. The opcodes are grouped by feature
//! family rather than directory. This module is currently gated on
//! `fips_validation_hooks` alone, so only that family is compiled in.
//!
//! A second family (e.g. `mcr_test_hooks`) is added by widening both
//! `#[cfg]` sites in lockstep — the `mod test_hooks` gate in `lib.rs`
//! and the matching gate on the `crate::test_hooks::mbor_dispatch` call
//! in `pal.rs` — then declaring its opcode modules here and adding their
//! router arms.
//!
//! # Families
//!
//! - `fips_validation_hooks` — `GetPrivKey` (2005), `RawKeyImport` (2008).
//!
//! # These are in-session commands
//!
//! The core classifies any opcode it does not know as
//! `SessionCtrl::InSession` (the `_` arm of `SessionCtrl::from_op`), and
//! the IO layer runs session validation before dispatch. So a request
//! sent without a live session fails that check and never reaches this
//! module — it surfaces as a session error rather than anything from
//! here.
//!
//! # Wire compatibility
//!
//! Each opcode's request / response types mirror `mcr-hsm`'s definitions
//! field-for-field, so the existing host-side Known-Answer-Test suite
//! drives either firmware unchanged. `DdiOp` and `DdiStatus` values are
//! carried as raw `u32` here rather than the core enums: every value is
//! an unsigned integer on the wire, so the bytes are identical.

mod common;
mod get_priv_key;
mod raw_key_import;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use common::ReqHdr;

use crate::pal::UnoHsmPal;

/// `GetPrivKey` — the wire opcode `mcr-hsm` assigns this command.
const DDI_OP_GET_PRIV_KEY: u32 = 2005;

/// `RawKeyImport` — the wire opcode `mcr-hsm` assigns this command.
const DDI_OP_RAW_KEY_IMPORT: u32 = 2008;

/// Route an MBOR request the core did not claim.
///
/// Re-parses the envelope the core already parsed — telling the core
/// anything about these commands is precisely what the hook exists to
/// avoid — then dispatches strictly by opcode. Returns
/// [`HsmError::UnsupportedCmd`] for anything not handled here, which the
/// core surfaces to the host exactly as if no hook existed.
pub(crate) async fn mbor_dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    req: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req_len = req.len();
    let mut decoder = MborDecoder::new(req);

    let count = MborMap::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if count.0 != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let key = u8::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if key != 0 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let hdr = ReqHdr::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    match hdr.op {
        DDI_OP_GET_PRIV_KEY => get_priv_key::get_priv_key(pal, io, &mut decoder, &hdr, req_len),
        DDI_OP_RAW_KEY_IMPORT => {
            raw_key_import::raw_key_import(pal, io, &mut decoder, &hdr, req_len).await
        }
        _ => Err(HsmError::UnsupportedCmd),
    }
}
