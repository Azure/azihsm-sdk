// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FIPS-validation-only DDI commands, reached through the
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
//! core table, the wire types are in no core crate, and
//! `fips_validation_hooks` — the feature that turns the commands on — is
//! declared in this crate alone. Without it this module is compiled out
//! and uno's `mbor_dispatch` rejects every opcode, so a production build
//! answers exactly as it would if the hook had never been added.
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
//! `GetPrivKey` (`DdiOp` 2005) and `RawKeyImport` (`DdiOp` 2008) and
//! their request / response types mirror `mcr-hsm`'s definitions
//! field-for-field, so the existing host-side Known-Answer-Test suite
//! drives either firmware unchanged.
//!
//! The on-wire `DdiOp` and `DdiStatus` values are carried as raw `u32`
//! here rather than as the core enums: every value is an unsigned integer
//! on the wire, so the bytes are identical.

mod get_priv_key;
mod raw_key_import;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::pal::UnoHsmPal;

/// `GetPrivKey` — the wire opcode `mcr-hsm` assigns this command.
const DDI_OP_GET_PRIV_KEY: u32 = 2005;

/// `RawKeyImport` — the wire opcode `mcr-hsm` assigns this command.
const DDI_OP_RAW_KEY_IMPORT: u32 = 2008;

/// `DdiStatus::Success`.
const DDI_STATUS_SUCCESS: u32 = 0;

/// Mirrors the core's `DdiApiRev`.
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
struct FipsApiRev {
    #[ddi(id = 1)]
    major: u32,
    #[ddi(id = 2)]
    minor: u32,
}

/// The request header, mirroring the core's `DdiReqHdr` on the wire.
///
/// Redeclared here rather than imported: the core types crate must not
/// gain these opcodes, and this module must not be the reason a crate
/// above the PAL grows a dependency or a feature.
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
struct FipsReqHdr {
    /// API revision — decoded to advance the cursor, echoed in the
    /// response, not otherwise inspected.
    #[ddi(id = 1)]
    rev: Option<FipsApiRev>,
    /// Opcode, carried as a raw `u32` (`DdiOp` is `repr(u32)`).
    #[ddi(id = 2)]
    op: u32,
    /// Session id, if any.
    #[ddi(id = 3)]
    sess_id: Option<u16>,
}

/// The response header, mirroring the core's `DdiRespHdr` on the wire.
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
struct FipsRespHdr {
    #[ddi(id = 1)]
    rev: Option<FipsApiRev>,
    /// Opcode, carried as a raw `u32` (`DdiOp` is `repr(u32)`).
    #[ddi(id = 2)]
    op: u32,
    #[ddi(id = 3)]
    sess_id: Option<u16>,
    /// Status, carried as a raw `u32` (`DdiStatus` is `u32`).
    #[ddi(id = 4)]
    status: u32,
    #[ddi(id = 5)]
    fips_approved: bool,
}

/// Build a success response header echoing the request's revision and
/// carrying the live session id.
fn success_hdr_sess(req: &FipsReqHdr, op: u32, sess_id: u16) -> FipsRespHdr {
    FipsRespHdr {
        rev: req.rev,
        op,
        sess_id: Some(sess_id),
        status: DDI_STATUS_SUCCESS,
        fips_approved: false,
    }
}

/// Encode a response as the map `{0: hdr, 1: data}`, mirroring the
/// core's `encode_resp`.
fn encode_resp<H, D>(hdr: &H, data: &D, smem: &mut [u8]) -> HsmResult<usize>
where
    H: MborEncode,
    D: MborEncode,
{
    let mut encoder = MborEncoder::new(smem);
    MborMap(2).mbor_encode(&mut encoder)?;
    0u8.mbor_encode(&mut encoder)?;
    hdr.mbor_encode(&mut encoder)?;
    1u8.mbor_encode(&mut encoder)?;
    data.mbor_encode(&mut encoder)?;
    Ok(encoder.position())
}

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

    let hdr = FipsReqHdr::mbor_decode(&mut decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    match hdr.op {
        DDI_OP_GET_PRIV_KEY => get_priv_key::get_priv_key(pal, io, &mut decoder, &hdr, req_len),
        DDI_OP_RAW_KEY_IMPORT => {
            raw_key_import::raw_key_import(pal, io, &mut decoder, &hdr, req_len).await
        }
        _ => Err(HsmError::UnsupportedCmd),
    }
}
