// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host wire types and helper for the `GetPrivKey` validation command.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;

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

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyCmdReq {
    #[ddi(id = 0)]
    pub hdr: DdiReqHdr,
    #[ddi(id = 1)]
    pub data: crate::DdiTestActionReq,
    #[ddi(id = 2)]
    pub ext: Option<DdiReqExt>,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyCmdResp {
    #[ddi(id = 0)]
    pub hdr: DdiRespHdr,
    #[ddi(id = 1)]
    pub data: DdiGetPrivKeyResp,
    #[ddi(id = 2)]
    pub ext: Option<DdiRespExt>,
}

impl DdiOpReq for DdiGetPrivKeyCmdReq {
    type OpResp = DdiGetPrivKeyCmdResp;

    fn get_opcode(&self) -> DdiOp {
        self.hdr.op
    }

    fn get_session_id(&self) -> Option<u16> {
        self.hdr.sess_id
    }
}

/// Read back a key's private material from validation firmware.
pub fn helper_get_priv_key(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: Option<u16>,
    key_id: u16,
) -> azihsm_ddi::DdiResult<DdiGetPrivKeyCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    let payload = crate::test_action::encode_action_payload(&DdiGetPrivKeyReq { key_id })
        .map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: crate::DDI_OP_TEST_ACTION,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: crate::DdiTestActionReq {
            action: crate::DdiTestAction::GetPrivKey,
            payload,
        },
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}
