// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host wire types and helper for the `GetPrivKey` validation command.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;
use pastey::paste;

/// FIPS-validation read-back of a key's private material.
pub const DDI_OP_GET_PRIV_KEY: DdiOp = DdiOp(2005);

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyReq {
    #[ddi(id = 1)]
    pub key_id: u16,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyResp {
    #[ddi(id = 1)]
    pub key_kind: DdiKeyType,
    #[ddi(id = 2)]
    pub key_data: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiGetPrivKey);

/// Read back a key's private material from validation firmware.
#[cfg(feature = "helpers")]
pub fn helper_get_priv_key(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: Option<u16>,
    key_id: u16,
) -> azihsm_ddi::DdiResult<DdiGetPrivKeyCmdResp> {
    use azihsm_ddi::DdiDev;

    let req = DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_GET_PRIV_KEY,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}
