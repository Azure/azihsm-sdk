// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TestAction selectors, action-specific payload schemas, and payload encoding.
//!
//! Every command in this family uses opcode 2004 and the stable outer request
//! shape `{1: action, 2: payload}`. Parameterized actions encode their own
//! `#[ddi(map)]` request into the opaque payload; parameterless actions use an
//! empty byte string.

use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_derive::Ddi;
use open_enum::open_enum;
use zeroize::Zeroize;

/// Maximum encoded size of a TestAction action-specific payload.
///
/// The largest current payload is a maximum RawKeyImport request (3252
/// encoded bytes). The capacity includes additional headroom; only the
/// significant bytes are transmitted.
pub const TEST_ACTION_PAYLOAD_MAX: usize = 3584;

/// Opaque MBOR-encoded data for one TestAction.
pub type DdiTestActionPayload = MborByteArray<TEST_ACTION_PAYLOAD_MAX>;

/// DDI TestAction selector.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestAction {
    /// Skip IO with a level-1 abort trigger.
    Level1SkipIo = 1,
    /// Set skip IO with a level-2 abort trigger.
    SetLevel2SkipIo = 2,
    /// Clear skip IO with a level-2 abort trigger.
    ClearLevel2SkipIo = 3,
    /// Invalidate the partition certificate-size cache.
    InvalidateCertSizeCache = 4,
    /// Trigger an IO failure.
    TriggerIoFailure = 5,
    /// Trigger a DMA-out failure.
    TriggerDmaOutFailure = 6,
    /// Trigger a DMA-end failure.
    TriggerDmaEndFailure = 7,
    /// Trigger a crash.
    TriggerCrash = 8,
    /// Execute a negative self-test.
    ExecuteNegativeSelfTest = 9,
    /// Override the PIN policy context.
    PinPolicyOverride = 10,
    /// Clear the PIN policy override.
    PinPolicyClear = 11,
    /// Force a PKA instance.
    ForcePkaInstance = 12,
    /// Trigger an RNG hardware failure.
    TriggerRngHwFailure = 13,
    /// Toggle the FIPS-approved state.
    ToggleFipsApprovedState = 14,
    /// Trigger a negative PCT failure.
    TriggerNegativePctFailure = 15,
    /// Trigger an ECC error.
    TriggerEccError = 16,
    /// Trigger a TDISP interrupt.
    TriggerTdispInterrupt = 17,
    /// Clear user credentials.
    ClearUserCredentials = 18,
    /// Clear the provisioning state.
    ClearProvisioningState = 19,
    /// Update the SVN value.
    UpdateSvn = 20,
    /// Trigger a GDMA error.
    TriggerGdmaError = 21,
    /// Clear BK3 information.
    ClearBk3 = 22,
    /// Trigger a stack-validation error.
    TriggerStackValidation = 23,
    /// Trigger a UCD error.
    TriggerUcdError = 24,
    /// Read back private key material.
    GetPrivKey = 25,
    /// Import raw key material.
    RawKeyImport = 26,
}

/// Crash type used by [`DdiTestAction::TriggerCrash`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionCrashType {
    /// Trigger a hard fault.
    HardFault = 1,
    /// Trigger an explicit crash.
    ExplicitCrash = 2,
    /// Trigger a panic.
    Panic = 3,
    /// Hang the selected core.
    Hang = 4,
}

/// ECC error type used by [`DdiTestAction::TriggerEccError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionEccErrorType {
    /// DTCM double-bit error.
    DtcmDoubleBit = 1,
    /// ITCM double-bit error.
    ItcmDoubleBit = 2,
    /// GSRAM double-bit error.
    GsramDoubleBit = 3,
    /// CDMA single-bit error.
    CdmaSingleBit = 4,
    /// CDMA ECC-error interrupt-count threshold exceeded.
    CdmaEccErrIntrCount = 5,
}

/// GDMA error type used by [`DdiTestAction::TriggerGdmaError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionGDMAErrorType {
    /// GDMA data-structure error bit.
    GdmaDataStructureErrorBit = 1,
    /// GDMA data-access error bit.
    GdmaDataAccessErrorBit = 2,
    /// GDMA delivery-queue error bit.
    GdmaDeliveryQueueErrorBit = 3,
    /// GDMA completion-queue error bit.
    GdmaCompletionQueueErrorBit = 4,
}

/// UCD error type used by [`DdiTestAction::TriggerUcdError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionUCDErrorType {
    /// UCD inbound DFL overflow error.
    UcdIbDflOverflowError = 1,
    /// UCD inbound queue overflow error.
    UcdIbQueueOverflowError = 2,
    /// UCD outbound queue-full error.
    UcdObQueueFullError = 3,
    /// UCD inbound data-path parity error.
    UcdIbDataParityError = 4,
    /// UCD inbound completion-queue-full error.
    UcdIbCqFullError = 5,
}

/// Interrupt type used by [`DdiTestAction::TriggerTdispInterrupt`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq, Default)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionInterruptSimulationType {
    /// Trigger a TDISP interrupt.
    Tdisp = 1,
    /// Trigger an IDE interrupt.
    Ide = 2,
    /// Trigger an FLR interrupt.
    Flr = 3,
    /// Trigger a PERST-up interrupt.
    PerstUp = 4,
    /// Trigger a PERST-down interrupt.
    PerstDown = 5,
}

/// Stack error type used by [`DdiTestAction::TriggerStackValidation`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestStackErrorType {
    /// Trigger a stack overflow.
    StackOverflow = 1,
    /// Trigger a stack-guard violation.
    StackGuardViolation = 2,
}

/// SoC core targeted by a TestAction.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiTestActionSocCpuId {
    /// Admin core.
    Admin = 0,
    /// HSM core.
    Hsm = 1,
    /// Fast-path core 0.
    Fp0 = 2,
    /// Fast-path core 1.
    Fp1 = 3,
    /// Fast-path core 2.
    Fp2 = 4,
}

/// Payload for [`DdiTestAction::TriggerCrash`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionCrashReqInfo {
    /// Crash type.
    #[ddi(id = 1)]
    pub crash_type: DdiTestActionCrashType,
    /// Target core.
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// Payload for [`DdiTestAction::ExecuteNegativeSelfTest`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionNegativeSelfTestReqInfo {
    /// Negative self-test identifier.
    #[ddi(id = 1)]
    pub neg_test_id: u32,
}

/// Payload for [`DdiTestAction::PinPolicyOverride`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionPinPolicyConfig {
    /// PIN-policy delay-increment override.
    #[ddi(id = 1)]
    pub delay_increment: Option<u16>,
    /// PIN-policy state override.
    #[ddi(id = 2)]
    pub state: Option<bool>,
    /// PIN-policy delay override.
    #[ddi(id = 3)]
    pub delay: Option<u16>,
    /// PIN-policy allowed-attempts override.
    #[ddi(id = 4)]
    pub allowed_attempts: Option<u16>,
    /// PIN-policy lockout-delay override.
    #[ddi(id = 5)]
    pub lockout_delay: Option<u32>,
}

/// Payload for [`DdiTestAction::ForcePkaInstance`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionForcePkaInstanceReqInfo {
    /// PKA instance to use.
    #[ddi(id = 1)]
    pub force_pka_instance: u8,
}

/// Payload for [`DdiTestAction::TriggerNegativePctFailure`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionNegativePctFailureReqInfo {
    /// Number of pairwise consistency tests to skip.
    #[ddi(id = 1)]
    pub neg_pct_skip_cnt: u8,
}

/// Payload for [`DdiTestAction::TriggerEccError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionEccErrorInfo {
    /// ECC error type.
    #[ddi(id = 1)]
    pub ecc_error_type: DdiTestActionEccErrorType,
    /// Target core.
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// Payload for [`DdiTestAction::TriggerTdispInterrupt`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionInterruptReqInfo {
    /// Interrupt to simulate.
    #[ddi(id = 1)]
    pub interrupt_type: DdiTestActionInterruptSimulationType,
}

/// Payload for [`DdiTestAction::UpdateSvn`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionUpdateSvnReqInfo {
    /// Security version number to install.
    #[ddi(id = 1)]
    pub updated_svn: u64,
}

/// Payload for [`DdiTestAction::TriggerGdmaError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionGdmaErrorReqInfo {
    /// GDMA error to inject.
    #[ddi(id = 1)]
    pub gdma_error_type: DdiTestActionGDMAErrorType,
}

/// Payload for [`DdiTestAction::TriggerStackValidation`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionStackValidationReqInfo {
    /// Stack error type.
    #[ddi(id = 1)]
    pub stack_error_type: DdiTestStackErrorType,
    /// Target core.
    #[ddi(id = 2)]
    pub cpu_id: DdiTestActionSocCpuId,
}

/// Payload for [`DdiTestAction::TriggerUcdError`].
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionUcdErrorReqInfo {
    /// UCD error to inject.
    #[ddi(id = 1)]
    pub ucd_error_type: DdiTestActionUCDErrorType,
}

/// Encode an action-specific map into the opaque TestAction payload.
pub(crate) fn encode_action_payload<T: MborEncode>(
    request_info: &T,
) -> Result<DdiTestActionPayload, MborEncodeError> {
    let mut buf = [0u8; TEST_ACTION_PAYLOAD_MAX];
    let mut encoder = MborEncoder::new(&mut buf, false);
    if let Err(err) = request_info.mbor_encode(&mut encoder) {
        buf.zeroize();
        return Err(err);
    }

    let len = encoder.position();
    let payload = DdiTestActionPayload::new(buf, len).map_err(|_| MborEncodeError::BufferOverflow);
    buf.zeroize();
    payload
}
