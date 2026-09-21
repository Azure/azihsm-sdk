// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire types for the `TestAction` (`DdiOp` 2004) test-hook command
//! family. These mirror, field-for-field, the request the platform
//! handler decodes below the PAL.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use azihsm_ddi_mbor_types::*;
use open_enum::open_enum;
use pastey::paste;

/// `DdiOp::TestAction` — not a core opcode; claimed only by the platform
/// test-hook dispatch below the PAL.
pub const DDI_OP_TEST_ACTION: DdiOp = DdiOp(2004);

/// DDI Test Action
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestAction {
    /// Skip IO with Level-1 Abort trigger
    Level1SkipIo = 1,

    /// Set Skip IO with Level-2 Abort Trigger
    SetLevel2SkipIo = 2,

    /// Clear Skip IO with Level-2 Abort Trigger
    ClearLevel2SkipIo = 3,

    /// Invalidate Cert size cache in partition
    InvalidateCertSizeCache = 4,

    /// Trigger IO failure
    TriggerIoFailure = 5,

    /// Trigger DMA out failure
    TriggerDmaOutFailure = 6,

    /// Trigger DMA End failure
    TriggerDmaEndFailure = 7,

    /// Trigger crash dump
    TriggerCrash = 8,

    /// Execute negative self test
    ExecuteNegativeSelfTest = 9,

    /// Override pin policy context
    PinPolicyOverride = 10,

    /// Clear pin policy
    PinPolicyClear = 11,

    /// Force PKA instance
    ForcePkaInstance = 12,

    /// Trigger RNG HW failure
    TriggerRngHwFailure = 13,

    /// Toggle FIPS approved state
    ToggleFipsApprovedState = 14,

    /// Trigger Negative PCT failure
    TriggerNegativePctFailure = 15,

    /// Trigger ECC error
    TriggerEccError = 16,

    /// Trigger TDISP interrupt
    TriggerTdispInterrupt = 17,

    /// Clear User Credentials
    ClearUserCredentials = 18,

    /// Clear Provisioning State
    ClearProvisioningState = 19,

    /// Update SVN value
    UpdateSvn = 20,

    /// Trigger GDMA Error
    TriggerGdmaError = 21,

    /// Clear BK3 info (masked bk boot and sealed bk3)
    ClearBk3 = 22,

    /// Trigger Stack Validation error
    TriggerStackValidation = 23,

    /// Trigger UCD Error
    TriggerUcdError = 24,
}

/// Test action crash type.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionCrashType {
    /// Trigger Hard Fault
    HardFault = 1,

    /// Trigger Explicit Crash
    ExplicitCrash = 2,

    /// Trigger Panic
    Panic = 3,

    /// Trigger Core Hang.
    Hang = 4,
}

/// Test action ECC Error type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionEccErrorType {
    /// DTCM Double Bit
    DtcmDoubleBit = 1,

    /// ITCM Double Bit
    ItcmDoubleBit = 2,

    /// GSRAM Double Bit
    GsramDoubleBit = 3,

    /// CDMA Single Bit
    CdmaSingleBit = 4,

    /// CDMA Single Bit ECC error threshold exceeded Interrupt count
    CdmaEccErrIntrCount = 5,
}

/// Test action GDMA Error type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionGDMAErrorType {
    /// GDMA Data Structure Error Bit
    GdmaDataStructureErrorBit = 1,

    /// GDMA Data Access Error Bit
    GdmaDataAccessErrorBit = 2,

    /// GDMA Delivery Queue Error Bit
    GdmaDeliveryQueueErrorBit = 3,

    /// GDMA Completion Queue Error Bit
    GdmaCompletionQueueErrorBit = 4,
}

/// Test action UCD Error type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionUCDErrorType {
    /// UCD IB DFL Overflow Error
    UcdIbDflOverflowError = 1,

    /// UCD IB Queue Overflow Error
    UcdIbQueueOverflowError = 2,

    /// UCD OB queue full Error
    UcdObQueueFullError = 3,

    /// UCD IB Data path Parity Error
    UcdIbDataParityError = 4,

    /// UCD IB Completion Queue Full Error
    UcdIbCqFullError = 5,
}

/// Test action interrupt type.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq, Default)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionInterruptSimulationType {
    /// Trigger TDISP Interrupt
    Tdisp = 1,

    /// Trigger IDE Interrupt
    Ide = 2,

    /// Trigger FLR Interrupt
    Flr = 3,

    /// Trigger Perst Up Interrupt
    PerstUp = 4,

    /// Trigger Perst Down Interrupt
    PerstDown = 5,
}

/// Test action stack error type
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestStackErrorType {
    /// Trigger Stack Overflow (MemManage fault)
    StackOverflow = 1,

    /// Stack guard violation (MemManage fault)
    StackGuardViolation = 2,
}

/// Test action SoC CPU type.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionSocCpuId {
    /// Admin core
    Admin = 0,

    /// HSM core
    Hsm = 1,

    /// FP0 core
    Fp0 = 2,

    /// FP1 core
    Fp1 = 3,

    /// FP2 core
    Fp2 = 4,
}

/// Test action crash request info
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionCrashReqInfo {
    /// Crash type.
    #[ddi(id = 1)]
    pub crash_type: DdiTestActionCrashType,

    /// CPU ID
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// Test action stack validation request info
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionStackValidationReqInfo {
    /// Stack error type.
    #[ddi(id = 1)]
    pub stack_error_type: DdiTestStackErrorType,

    /// CPU ID
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// Test action ECC error request info
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionEccErrorInfo {
    /// ECC Error type.
    #[ddi(id = 1)]
    pub ecc_error_type: DdiTestActionEccErrorType,

    /// CPU ID
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// DDI Test Action Pin Policy Config
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionPinPolicyConfig {
    /// Pin policy delay override
    #[ddi(id = 1)]
    pub delay_increment: Option<u16>,

    /// Pin policy state
    #[ddi(id = 2)]
    pub state: Option<bool>,

    /// Pin policy delay
    #[ddi(id = 3)]
    pub delay: Option<u16>,

    /// Pin policy allowed attempts
    #[ddi(id = 4)]
    pub allowed_attempts: Option<u16>,

    /// Pin policy lockout delay
    #[ddi(id = 5)]
    pub lockout_delay: Option<u32>,
}

/// Maximum size, in bytes, of a `TestAction` opaque payload — the MBOR
/// encoding of an action's own request-info body.
///
/// Sized with generous headroom over the current largest body
/// ([`DdiTestActionPinPolicyConfig`]); this is only the buffer capacity,
/// and just the significant bytes travel on the wire, so the ceiling is
/// free. Because every action shares this one container, growing it here
/// is the only change a larger action needs — the opcode's wire schema is
/// unaffected.
pub const TEST_ACTION_PAYLOAD_MAX: usize = 64;

/// Opaque, action-specific `TestAction` payload.
///
/// Carries the MBOR encoding of an action's own request-info struct as a
/// byte string, so the `TestAction` request map stays fixed at
/// `{1: action, 2: payload?}` regardless of the action. Build one with
/// [`encode_test_action_payload`].
pub type DdiTestActionPayload = MborByteArray<TEST_ACTION_PAYLOAD_MAX>;

/// MBOR-encode an action-specific body into the opaque payload container.
///
/// `body` is any of the per-action request-info types (for example
/// [`DdiTestActionCrashReqInfo`]) or a bare scalar the action expects; it
/// is encoded exactly as it would have been as a typed map entry, then
/// wrapped as the opaque byte string the firmware re-decodes.
pub fn encode_test_action_payload<T: MborEncode>(
    body: &T,
) -> Result<DdiTestActionPayload, MborEncodeError> {
    let mut buf = [0u8; TEST_ACTION_PAYLOAD_MAX];
    // The workspace pins `azihsm_ddi_mbor_types` (hence the codec) with
    // `pre_encode` on, so `MborEncoder::new` always takes this flag here.
    // `false`: an opaque payload is plain bytes and needs no pre-encode
    // transform.
    let mut encoder = MborEncoder::new(&mut buf, false);
    body.mbor_encode(&mut encoder)?;
    let len = encoder.position();
    DdiTestActionPayload::from_slice(&buf[..len]).map_err(|_| MborEncodeError::BufferOverflow)
}

/// A typed `TestAction` request that keeps the action and payload together.
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

/// DDI Test Action request.
///
/// Uses the opaque-payload shape `{1: action, 2: payload?}`: every action's
/// parameters travel in the single [`DdiTestActionPayload`] byte string, so
/// adding an action never changes this opcode's wire schema. `payload` is
/// `None` for actions that take no parameters (for example
/// `ClearUserCredentials`).
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionReq {
    /// Test Action
    #[ddi(id = 1)]
    pub action: DdiTestAction,

    /// Opaque, action-specific payload — the MBOR encoding of the action's
    /// request-info body. See [`encode_test_action_payload`].
    ///
    /// Spelled as `MborByteArray<..>` rather than the [`DdiTestActionPayload`]
    /// alias because the `Ddi` derive recognises a byte-array field by that
    /// type name; an alias would be treated as an ordinary field and fail to
    /// compile.
    #[ddi(id = 2)]
    pub payload: Option<MborByteArray<TEST_ACTION_PAYLOAD_MAX>>,
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
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::PinPolicyOverride(value) => (
                DdiTestAction::PinPolicyOverride,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::PinPolicyClear => (DdiTestAction::PinPolicyClear, None),
            TestActionRequest::ForcePkaInstance(value) => (
                DdiTestAction::ForcePkaInstance,
                value.as_ref().map(encode_test_action_payload).transpose()?,
            ),
            TestActionRequest::TriggerRngHwFailure => (DdiTestAction::TriggerRngHwFailure, None),
            TestActionRequest::ToggleFipsApprovedState => {
                (DdiTestAction::ToggleFipsApprovedState, None)
            }
            TestActionRequest::TriggerNegativePctFailure(value) => (
                DdiTestAction::TriggerNegativePctFailure,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerEccError(value) => (
                DdiTestAction::TriggerEccError,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerTdispInterrupt(value) => (
                DdiTestAction::TriggerTdispInterrupt,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::ClearUserCredentials => (DdiTestAction::ClearUserCredentials, None),
            TestActionRequest::ClearProvisioningState => {
                (DdiTestAction::ClearProvisioningState, None)
            }
            TestActionRequest::UpdateSvn(value) => (
                DdiTestAction::UpdateSvn,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerGdmaError(value) => (
                DdiTestAction::TriggerGdmaError,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::ClearBk3 => (DdiTestAction::ClearBk3, None),
            TestActionRequest::TriggerStackValidation(value) => (
                DdiTestAction::TriggerStackValidation,
                Some(encode_test_action_payload(&value)?),
            ),
            TestActionRequest::TriggerUcdError(value) => (
                DdiTestAction::TriggerUcdError,
                Some(encode_test_action_payload(&value)?),
            ),
        };

        Ok(Self { action, payload })
    }
}

/// DDI Test Action response
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionResp {
    /// Optional 4-byte reusable result parameter returned by certain test actions
    #[ddi(id = 1)]
    pub result: Option<u32>,
}

ddi_op_req_resp!(DdiTestAction);

/// Execute a typed `TestAction` request against validation firmware.
pub fn helper_test_action_cmd(
    dev: &mut <azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: u16,
    request: TestActionRequest,
) -> azihsm_ddi::DdiResult<DdiTestActionCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    let data = DdiTestActionReq::try_from(request).map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiTestActionCmdReq {
        hdr: DdiReqHdr {
            op: DDI_OP_TEST_ACTION,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data,
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}
