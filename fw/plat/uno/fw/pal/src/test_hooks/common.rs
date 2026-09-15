// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire envelope shared by the below-PAL test-hook commands.
//!
//! Every test-hook request and response is the MBOR map `{0: hdr, 1: data}`,
//! where `hdr` mirrors the core's `DdiReqHdr` / `DdiRespHdr` field-for-field.
//! The header types and the response helpers live here so each opcode
//! handler decodes the same envelope and encodes the same reply; the router
//! in [`super`] reads the request envelope once and hands the body to the
//! matching handler.
//!
//! The types are redeclared rather than imported from the core DDI crate on
//! purpose: nothing about a test-only command may reach a crate above the PAL,
//! so the core types crate must not gain a test opcode and this crate must not
//! be the reason a crate above the PAL grows a dependency or a feature.

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborMap;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::HsmResult;

/// `DdiStatus::Success`.
pub(super) const DDI_STATUS_SUCCESS: u32 = 0;

/// Mirrors the core's `DdiApiRev`.
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
pub(super) struct ApiRev {
    #[ddi(id = 1)]
    pub(super) major: u32,
    #[ddi(id = 2)]
    pub(super) minor: u32,
}

/// The request header, mirroring the core's `DdiReqHdr` on the wire.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub(super) struct ReqHdr {
    /// API revision — decoded to advance the cursor, not inspected.
    #[ddi(id = 1)]
    pub(super) rev: Option<ApiRev>,
    /// Opcode.
    #[ddi(id = 2)]
    pub(super) op: u32,
    /// Session id, if any.
    #[ddi(id = 3)]
    pub(super) sess_id: Option<u16>,
}

/// The response header, mirroring the core's `DdiRespHdr` on the wire.
///
/// Redeclared here for the same reason as [`ReqHdr`]: the response path
/// stays entirely below the PAL, so nothing about a test command reaches
/// the core's DDI types.
#[derive(Debug, Ddi)]
#[ddi(map)]
pub(super) struct RespHdr {
    #[ddi(id = 1)]
    pub(super) rev: Option<ApiRev>,
    /// Opcode, carried as a raw `u32` (`DdiOp` is `repr(u32)`).
    #[ddi(id = 2)]
    pub(super) op: u32,
    #[ddi(id = 3)]
    pub(super) sess_id: Option<u16>,
    /// Status, carried as a raw `u32` (`DdiStatus` is a `u32`).
    #[ddi(id = 4)]
    pub(super) status: u32,
    #[ddi(id = 5)]
    pub(super) fips_approved: bool,
}

/// Build a success response header echoing the request's revision and
/// opcode.
///
/// `sess_id` is `None`: a `TestAction` neither opens nor closes a session,
/// so its response carries no session id — matching the core's
/// `success_hdr`.
pub(super) fn success_hdr(hdr: &ReqHdr) -> RespHdr {
    RespHdr {
        rev: hdr.rev,
        op: hdr.op,
        sess_id: None,
        status: DDI_STATUS_SUCCESS,
        fips_approved: false,
    }
}

/// Encode a response as the map `{0: hdr, 1: data}`, mirroring the core's
/// `encode_resp`, and return the encoded length.
pub(super) fn encode_resp<H, D>(hdr: &H, data: &D, smem: &mut [u8]) -> HsmResult<usize>
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
