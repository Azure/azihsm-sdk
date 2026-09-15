// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared DDI wire envelope for the below-PAL test / validation hooks.
//!
//! Every opcode served under `test_hooks/` shares one request / response
//! header shape and one response encoder, declared here so no opcode
//! module redeclares them.
//!
//! The types mirror the core's `DdiReqHdr` / `DdiRespHdr` on the wire but
//! are redeclared below the PAL rather than imported: the core types
//! crate must not gain these opcodes, and this module must not be the
//! reason a crate above the PAL grows a dependency or a feature.
//!
//! The on-wire `DdiOp` and `DdiStatus` values are carried as raw `u32`
//! here rather than as the core enums: every value is an unsigned integer
//! on the wire, so the bytes are identical.

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
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
pub(super) struct ReqHdr {
    /// API revision — decoded to advance the cursor, echoed in the
    /// response, not otherwise inspected.
    #[ddi(id = 1)]
    pub(super) rev: Option<ApiRev>,
    /// Opcode, carried as a raw `u32` (`DdiOp` is `repr(u32)`).
    #[ddi(id = 2)]
    pub(super) op: u32,
    /// Session id, if any.
    #[ddi(id = 3)]
    pub(super) sess_id: Option<u16>,
}

/// The response header, mirroring the core's `DdiRespHdr` on the wire.
#[derive(Debug, Ddi, Clone, Copy)]
#[ddi(map)]
pub(super) struct RespHdr {
    #[ddi(id = 1)]
    pub(super) rev: Option<ApiRev>,
    /// Opcode, carried as a raw `u32` (`DdiOp` is `repr(u32)`).
    #[ddi(id = 2)]
    pub(super) op: u32,
    #[ddi(id = 3)]
    pub(super) sess_id: Option<u16>,
    /// Status, carried as a raw `u32` (`DdiStatus` is `u32`).
    #[ddi(id = 4)]
    pub(super) status: u32,
    #[ddi(id = 5)]
    pub(super) fips_approved: bool,
}

/// Build a success response header echoing the request's revision and
/// carrying the live session id.
pub(super) fn success_hdr_sess(req: &ReqHdr, op: u32, sess_id: u16) -> RespHdr {
    RespHdr {
        rev: req.rev,
        op,
        sess_id: Some(sess_id),
        status: DDI_STATUS_SUCCESS,
        fips_approved: false,
    }
}

/// Encode a response as the map `{0: hdr, 1: data}`, mirroring the
/// core's `encode_resp`.
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
