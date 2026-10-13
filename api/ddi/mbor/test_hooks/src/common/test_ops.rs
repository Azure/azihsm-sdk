// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI request, response, and command-envelope wire types for test hooks.
//!
//! `GetPrivKey` and `RawKeyImport` have distinct typed responses, but both use
//! the common TestAction opcode and request envelope. The request type selects
//! the response decoder through [`DdiOpReq::OpResp`].

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;
use pastey::paste;
use zeroize::Zeroize;

use super::encode_action_payload;
use super::DdiTestAction;
use super::DdiTestActionPayload;
use super::TEST_ACTION_PAYLOAD_MAX;

/// `DdiOp::TestAction`, claimed only by platform test-hook dispatch.
pub const DDI_OP_TEST_ACTION: DdiOp = DdiOp(2004);

/// Common TestAction request data encoded as `{1: action, 2: payload}`.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionReq {
    /// Action selector.
    #[ddi(id = 1)]
    pub action: DdiTestAction,

    /// MBOR encoding of the action-specific request map.
    ///
    /// The literal `MborByteArray` type is required by the `Ddi` derive.
    #[ddi(id = 2)]
    pub payload: MborByteArray<TEST_ACTION_PAYLOAD_MAX>,
}

impl DdiTestActionReq {
    pub(crate) fn encode<T: MborEncode>(
        action: DdiTestAction,
        value: &T,
    ) -> Result<Self, MborEncodeError> {
        let mut payload = encode_action_payload(value)?;
        let request = Self { action, payload };
        payload.data_mut().zeroize();
        Ok(request)
    }

    pub(crate) fn with_payload(action: DdiTestAction, mut payload: DdiTestActionPayload) -> Self {
        let request = Self { action, payload };
        payload.data_mut().zeroize();
        request
    }

    pub(crate) fn empty(action: DdiTestAction) -> Result<Self, MborEncodeError> {
        let payload =
            DdiTestActionPayload::from_slice(&[]).map_err(|_| MborEncodeError::BufferOverflow)?;
        Ok(Self { action, payload })
    }
}

/// TestAction response data.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionResp {
    /// Optional reusable result returned by actions that produce a scalar.
    #[ddi(id = 1)]
    pub result: Option<u32>,
}

ddi_op_req_resp!(DdiTestAction);

/// Action-specific request for `GetPrivKey`.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyReq {
    /// Vault key identifier.
    #[ddi(id = 1)]
    pub key_id: u16,
}

/// Typed response data returned by `GetPrivKey`.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyResp {
    /// Key type reported by the validation firmware.
    #[ddi(id = 1)]
    pub key_kind: DdiKeyType,
    /// Raw private key material.
    #[ddi(id = 2)]
    pub key_data: MborByteArray<3072>,
}

/// Command envelope for the `GetPrivKey` TestAction.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyCmdReq {
    #[ddi(id = 0)]
    pub hdr: DdiReqHdr,
    #[ddi(id = 1)]
    pub data: DdiTestActionReq,
    #[ddi(id = 2)]
    pub ext: Option<DdiReqExt>,
}

/// Command response envelope for the `GetPrivKey` TestAction.
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

/// Action-specific request for `RawKeyImport`.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportReq {
    /// Raw key material.
    #[ddi(id = 1)]
    pub raw: MborByteArray<3072>,
    /// Requested key type.
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
    /// Optional key tag.
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,
    /// Target key properties.
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties,
}

/// Typed response data returned by `RawKeyImport`.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportResp {
    /// Imported vault key identifier.
    #[ddi(id = 1)]
    pub key_id: u16,
    /// Associated bulk-key identifier, when applicable.
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,
    /// Masked-key representation of the imported key.
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

/// Command envelope for the `RawKeyImport` TestAction.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportCmdReq {
    #[ddi(id = 0)]
    pub hdr: DdiReqHdr,
    #[ddi(id = 1)]
    pub data: DdiTestActionReq,
    #[ddi(id = 2)]
    pub ext: Option<DdiReqExt>,
}

/// Command response envelope for the `RawKeyImport` TestAction.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportCmdResp {
    #[ddi(id = 0)]
    pub hdr: DdiRespHdr,
    #[ddi(id = 1)]
    pub data: DdiRawKeyImportResp,
    #[ddi(id = 2)]
    pub ext: Option<DdiRespExt>,
}

impl DdiOpReq for DdiRawKeyImportCmdReq {
    type OpResp = DdiRawKeyImportCmdResp;

    fn get_opcode(&self) -> DdiOp {
        self.hdr.op
    }

    fn get_session_id(&self) -> Option<u16> {
        self.hdr.sess_id
    }
}

pub(crate) fn test_action_header(session_id: Option<u16>) -> DdiReqHdr {
    DdiReqHdr {
        op: DDI_OP_TEST_ACTION,
        sess_id: session_id,
        rev: Some(DdiApiRev { major: 1, minor: 0 }),
    }
}
