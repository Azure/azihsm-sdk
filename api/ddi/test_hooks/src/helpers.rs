// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side send helpers for the `TestAction` command family.
//!
//! These build a `DdiTestActionCmdReq` for a chosen action and execute
//! it against a device. A firmware built without `mcr_test_hooks`
//! answers with `DdiStatus::UnsupportedCmd`, which callers treat as a
//! graceful skip.

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::DdiApiRev;
use azihsm_ddi_mbor_types::DdiReqHdr;

use crate::*;

/// Action-specific payload carried by a `TestAction` request.
///
/// Each variant sets exactly one optional field of [`DdiTestActionReq`];
/// [`DdiTestActionContext::None`] sends an action that needs no extra
/// data (for example `ClearUserCredentials`).
pub enum DdiTestActionContext {
    /// No action-specific data.
    None,
    /// Crash-injection parameters.
    CrashInfo(DdiTestActionCrashReqInfo),
    /// Negative self-test identifier.
    NegTestId(u32),
    /// Pin-policy override (or clear when `None`).
    PinPolicyConfig(Option<DdiTestActionPinPolicyConfig>),
    /// Forced PKA instance id.
    ForcePkaInstance(u8),
    /// FSMs to skip before the negative PCT action fires.
    NegPctSkipCnt(u8),
    /// ECC-error-injection parameters.
    EccErrorInfo(DdiTestActionEccErrorInfo),
    /// TDISP/interrupt simulation type.
    TdispInterruptType(DdiTestActionInterruptSimulationType),
    /// New SVN value.
    UpdatedSvn(u64),
    /// GDMA-error-injection type.
    GdmaErrorType(DdiTestActionGDMAErrorType),
    /// Stack-validation-injection parameters.
    StackValidationInfo(DdiTestActionStackValidationReqInfo),
    /// UCD-error-injection type.
    UcdErrorInfo(DdiTestActionUCDErrorType),
}

impl DdiTestActionContext {
    /// Build the request body for `action`, placing this context in its
    /// matching optional field and leaving the rest `None`.
    fn into_req(self, action: DdiTestAction) -> DdiTestActionReq {
        let mut req = DdiTestActionReq {
            action,
            crash_info: None,
            neg_test_id: None,
            pin_policy_config: None,
            force_pka_instance: None,
            neg_pct_skip_cnt: None,
            ecc_error_info: None,
            tdisp_interrupt_type: None,
            updated_svn: None,
            gdma_error_type: None,
            stack_validation_info: None,
            ucd_error_type: None,
        };
        match self {
            DdiTestActionContext::None => {}
            DdiTestActionContext::CrashInfo(info) => req.crash_info = Some(info),
            DdiTestActionContext::NegTestId(id) => req.neg_test_id = Some(id),
            DdiTestActionContext::PinPolicyConfig(config) => req.pin_policy_config = config,
            DdiTestActionContext::ForcePkaInstance(instance) => {
                req.force_pka_instance = Some(instance)
            }
            DdiTestActionContext::NegPctSkipCnt(cnt) => req.neg_pct_skip_cnt = Some(cnt),
            DdiTestActionContext::EccErrorInfo(info) => req.ecc_error_info = Some(info),
            DdiTestActionContext::TdispInterruptType(ty) => req.tdisp_interrupt_type = Some(ty),
            DdiTestActionContext::UpdatedSvn(svn) => req.updated_svn = Some(svn),
            DdiTestActionContext::GdmaErrorType(ty) => req.gdma_error_type = Some(ty),
            DdiTestActionContext::StackValidationInfo(info) => {
                req.stack_validation_info = Some(info)
            }
            DdiTestActionContext::UcdErrorInfo(ty) => req.ucd_error_type = Some(ty),
        }
        req
    }
}

/// Send a `TestAction` command on an open session and return the decoded
/// response.
///
/// Returns `Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))` when the
/// firmware is built without the test-hook feature or does not implement
/// the requested action; callers use that to skip.
pub fn helper_test_action_cmd(
    dev: &mut <AzihsmDdi as Ddi>::Dev,
    session_id: u16,
    action: DdiTestAction,
    context: DdiTestActionContext,
) -> DdiResult<DdiTestActionCmdResp> {
    let req = DdiTestActionCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_TEST_ACTION,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: context.into_req(action),
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

/// Read back a key's private material via `GetPrivKey` (`DdiOp` 2005).
///
/// Only answered by firmware built with `fips_validation_hooks`;
/// otherwise returns `Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))`.
pub fn helper_get_priv_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
) -> DdiResult<DdiGetPrivKeyCmdResp> {
    let req = DdiGetPrivKeyCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_GET_PRIV_KEY,
            sess_id,
            rev,
        },
        data: DdiGetPrivKeyReq { key_id },
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

/// Import raw key material via `RawKeyImport` (`DdiOp` 2008).
///
/// `raw` is a fixed 3072-byte buffer; `key_length` is the number of
/// leading bytes that are significant. `key_properties` is given in the
/// public [`DdiKeyProperties`] form and converted to the target-key
/// representation the wire type carries.
///
/// Only answered by firmware built with `fips_validation_hooks`.
#[allow(clippy::too_many_arguments)]
pub fn helper_raw_key_import(
    dev: &mut <AzihsmDdi as Ddi>::Dev,
    session_id: Option<u16>,
    raw: [u8; 3072],
    key_length: usize,
    key_kind: DdiKeyType,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> DdiResult<DdiRawKeyImportCmdResp> {
    let req = DdiRawKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_RAW_KEY_IMPORT,
            sess_id: session_id,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiRawKeyImportReq {
            raw: MborByteArray::new(raw, key_length).map_err(|_| DdiError::InvalidParameter)?,
            key_kind,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

/// Read back a fixed-length raw secret imported earlier, asserting the
/// returned length matches `N`.
pub fn retrieve_shared_raw_key<const N: usize>(
    dev: &mut <AzihsmDdi as Ddi>::Dev,
    sess_id: u16,
    secret_key_id: u16,
) -> DdiResult<[u8; N]> {
    let resp = helper_get_priv_key(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id,
    )?;

    let raw_secret_len = resp.data.key_data.len();
    if raw_secret_len != N {
        return Err(DdiError::InvalidParameter);
    }

    let mut result = [0u8; N];
    result.copy_from_slice(&resp.data.key_data.data()[..raw_secret_len]);
    Ok(result)
}

/// Read back a variable-length raw secret imported earlier, asserting the
/// returned length matches `expected_len`.
pub fn retrieve_shared_raw_key_var(
    dev: &mut <AzihsmDdi as Ddi>::Dev,
    sess_id: u16,
    secret_key_id: u16,
    expected_len: usize,
) -> DdiResult<Vec<u8>> {
    let resp = helper_get_priv_key(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id,
    )?;

    let key_data = resp.data.key_data.as_slice();
    if key_data.len() != expected_len {
        return Err(DdiError::InvalidParameter);
    }
    Ok(key_data.to_vec())
}
