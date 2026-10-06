// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Semantic request API and execution helper for general TestAction commands.
//!
//! Wire structures are kept in `common`; this module maps each typed request
//! to its action selector and opaque action-specific payload.

use azihsm_ddi_mbor_codec::MborEncode;
use azihsm_ddi_mbor_codec::MborEncodeError;

use crate::common::*;

/// Typed TestAction request that keeps each action paired with its payload.
#[derive(Debug)]
pub enum TestActionRequest {
    Level1SkipIo,
    SetLevel2SkipIo,
    ClearLevel2SkipIo,
    InvalidateCertSizeCache,
    TriggerIoFailure,
    TriggerDmaOutFailure,
    TriggerDmaEndFailure,
    TriggerCrash(DdiTestActionCrashReqInfo),
    ExecuteNegativeSelfTest(u32),
    PinPolicyOverride(DdiTestActionPinPolicyConfig),
    PinPolicyClear,
    ForcePkaInstance(Option<u8>),
    TriggerRngHwFailure,
    ToggleFipsApprovedState,
    TriggerNegativePctFailure(u8),
    TriggerEccError(DdiTestActionEccErrorInfo),
    TriggerTdispInterrupt(DdiTestActionInterruptSimulationType),
    ClearUserCredentials,
    ClearProvisioningState,
    UpdateSvn(u64),
    TriggerGdmaError(DdiTestActionGDMAErrorType),
    ClearBk3,
    TriggerStackValidation(DdiTestActionStackValidationReqInfo),
    TriggerUcdError(DdiTestActionUCDErrorType),
}

/// Restricts semantic TestAction conversion to the defined payload maps.
trait TestActionPayload: MborEncode {}

impl TestActionPayload for DdiTestActionCrashReqInfo {}
impl TestActionPayload for DdiTestActionNegativeSelfTestReqInfo {}
impl TestActionPayload for DdiTestActionPinPolicyConfig {}
impl TestActionPayload for DdiTestActionForcePkaInstanceReqInfo {}
impl TestActionPayload for DdiTestActionNegativePctFailureReqInfo {}
impl TestActionPayload for DdiTestActionEccErrorInfo {}
impl TestActionPayload for DdiTestActionInterruptReqInfo {}
impl TestActionPayload for DdiTestActionUpdateSvnReqInfo {}
impl TestActionPayload for DdiTestActionGdmaErrorReqInfo {}
impl TestActionPayload for DdiTestActionStackValidationReqInfo {}
impl TestActionPayload for DdiTestActionUcdErrorReqInfo {}

fn encode_test_action_payload<T: TestActionPayload>(
    request_info: &T,
) -> Result<DdiTestActionPayload, MborEncodeError> {
    encode_action_payload(request_info)
}

impl TryFrom<TestActionRequest> for DdiTestActionReq {
    type Error = MborEncodeError;

    fn try_from(request: TestActionRequest) -> Result<Self, Self::Error> {
        let (action, payload) = match request {
            TestActionRequest::Level1SkipIo => (DdiTestAction::Level1SkipIo, None),
            TestActionRequest::SetLevel2SkipIo => (DdiTestAction::SetLevel2SkipIo, None),
            TestActionRequest::ClearLevel2SkipIo => (DdiTestAction::ClearLevel2SkipIo, None),
            TestActionRequest::InvalidateCertSizeCache => {
                (DdiTestAction::InvalidateCertSizeCache, None)
            }
            TestActionRequest::TriggerIoFailure => (DdiTestAction::TriggerIoFailure, None),
            TestActionRequest::TriggerDmaOutFailure => (DdiTestAction::TriggerDmaOutFailure, None),
            TestActionRequest::TriggerDmaEndFailure => (DdiTestAction::TriggerDmaEndFailure, None),
            TestActionRequest::TriggerCrash(value) => (
                DdiTestAction::TriggerCrash,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::ExecuteNegativeSelfTest(value) => (
                DdiTestAction::ExecuteNegativeSelfTest,
                Some(encode_test_action_payload(
                    &DdiTestActionNegativeSelfTestReqInfo { neg_test_id: value },
                )?),
            ),
            TestActionRequest::PinPolicyOverride(value) => (
                DdiTestAction::PinPolicyOverride,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::PinPolicyClear => (DdiTestAction::PinPolicyClear, None),
            TestActionRequest::ForcePkaInstance(value) => {
                let payload = value
                    .map(|force_pka_instance| {
                        encode_test_action_payload(&DdiTestActionForcePkaInstanceReqInfo {
                            force_pka_instance,
                        })
                    })
                    .transpose()?;
                (DdiTestAction::ForcePkaInstance, payload)
            }
            TestActionRequest::TriggerRngHwFailure => (DdiTestAction::TriggerRngHwFailure, None),
            TestActionRequest::ToggleFipsApprovedState => {
                (DdiTestAction::ToggleFipsApprovedState, None)
            }
            TestActionRequest::TriggerNegativePctFailure(value) => (
                DdiTestAction::TriggerNegativePctFailure,
                Some(encode_test_action_payload(
                    &DdiTestActionNegativePctFailureReqInfo {
                        neg_pct_skip_cnt: value,
                    },
                )?),
            ),
            TestActionRequest::TriggerEccError(value) => (
                DdiTestAction::TriggerEccError,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerTdispInterrupt(value) => (
                DdiTestAction::TriggerTdispInterrupt,
                Some(encode_test_action_payload(
                    &DdiTestActionInterruptReqInfo {
                        interrupt_type: value,
                    },
                )?),
            ),
            TestActionRequest::ClearUserCredentials => (DdiTestAction::ClearUserCredentials, None),
            TestActionRequest::ClearProvisioningState => {
                (DdiTestAction::ClearProvisioningState, None)
            }
            TestActionRequest::UpdateSvn(value) => (
                DdiTestAction::UpdateSvn,
                Some(encode_test_action_payload(
                    &DdiTestActionUpdateSvnReqInfo { updated_svn: value },
                )?),
            ),
            TestActionRequest::TriggerGdmaError(value) => (
                DdiTestAction::TriggerGdmaError,
                Some(encode_test_action_payload(
                    &DdiTestActionGdmaErrorReqInfo {
                        gdma_error_type: value,
                    },
                )?),
            ),
            TestActionRequest::ClearBk3 => (DdiTestAction::ClearBk3, None),
            TestActionRequest::TriggerStackValidation(value) => (
                DdiTestAction::TriggerStackValidation,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerUcdError(value) => (
                DdiTestAction::TriggerUcdError,
                Some(encode_test_action_payload(&DdiTestActionUcdErrorReqInfo {
                    ucd_error_type: value,
                })?),
            ),
        };

        match payload {
            Some(payload) => Ok(Self::with_payload(action, payload)),
            None => Self::empty(action),
        }
    }
}

/// Execute a typed TestAction request against validation firmware.
pub fn helper_test_action_cmd(
    dev: &mut <azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: u16,
    request: TestActionRequest,
) -> azihsm_ddi::DdiResult<DdiTestActionCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    let data = DdiTestActionReq::try_from(request).map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiTestActionCmdReq {
        hdr: test_action_header(Some(session_id)),
        data,
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_mbor_codec::MborDecode;
    use azihsm_ddi_mbor_codec::MborDecoder;
    use azihsm_ddi_mbor_codec::MborMap;

    use super::*;

    #[test]
    fn parameterized_actions_use_map_payloads() {
        let requests = [
            TestActionRequest::TriggerCrash(DdiTestActionCrashReqInfo {
                crash_type: DdiTestActionCrashType::Panic,
                cpu_id: DdiTestActionSocCpuId::Hsm,
            }),
            TestActionRequest::ExecuteNegativeSelfTest(1),
            TestActionRequest::PinPolicyOverride(DdiTestActionPinPolicyConfig {
                delay_increment: Some(1),
                state: None,
                delay: None,
                allowed_attempts: None,
                lockout_delay: None,
            }),
            TestActionRequest::ForcePkaInstance(Some(1)),
            TestActionRequest::TriggerNegativePctFailure(1),
            TestActionRequest::TriggerEccError(DdiTestActionEccErrorInfo {
                ecc_error_type: DdiTestActionEccErrorType::DtcmDoubleBit,
                cpu_id: DdiTestActionSocCpuId::Hsm,
            }),
            TestActionRequest::TriggerTdispInterrupt(DdiTestActionInterruptSimulationType::Tdisp),
            TestActionRequest::UpdateSvn(1),
            TestActionRequest::TriggerGdmaError(DdiTestActionGDMAErrorType::GdmaDataAccessErrorBit),
            TestActionRequest::TriggerStackValidation(DdiTestActionStackValidationReqInfo {
                stack_error_type: DdiTestStackErrorType::StackOverflow,
                cpu_id: DdiTestActionSocCpuId::Hsm,
            }),
            TestActionRequest::TriggerUcdError(DdiTestActionUCDErrorType::UcdIbDflOverflowError),
        ];

        for request in requests {
            let wire = DdiTestActionReq::try_from(request).expect("payload must encode");
            let mut decoder = MborDecoder::new(wire.payload.as_slice(), false);
            MborMap::mbor_decode(&mut decoder).expect("payload must start with an MBOR map");
        }
    }

    #[test]
    fn parameterless_actions_use_empty_payloads() {
        let requests = [
            TestActionRequest::ClearUserCredentials,
            TestActionRequest::ForcePkaInstance(None),
        ];

        for request in requests {
            let wire = DdiTestActionReq::try_from(request).expect("request must encode");
            assert!(wire.payload.is_empty());
        }
    }
}
