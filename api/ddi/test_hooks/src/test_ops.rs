// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire types for the `TestAction` (`DdiOp` 2004) test-hook command
//! family. These mirror, field-for-field, the request the platform
//! handler decodes below the PAL.

use pastey::paste;

use crate::*;

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

    /// GDMA Devlivery Queue Error Bit
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

/// DDI Test Action request
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionReq {
    /// Test Action
    #[ddi(id = 1)]
    pub action: DdiTestAction,

    /// Crash type.
    #[ddi(id = 2)]
    pub crash_info: Option<DdiTestActionCrashReqInfo>,

    /// Negative Self test ID.
    #[ddi(id = 3)]
    pub neg_test_id: Option<u32>,

    /// Pin policy override.
    /// This is used to override the pin policy context.
    #[ddi(id = 4)]
    pub pin_policy_config: Option<DdiTestActionPinPolicyConfig>,

    /// Force PKA instance to a fixed instance ID or reset it by supplying None.
    /// This is used for FIPS validation only with the device fw is built with validation hooks.
    #[ddi(id = 5)]
    pub force_pka_instance: Option<u8>,

    /// Count of FSMs to skip before triggering the negative PCT action.
    #[ddi(id = 6)]
    pub neg_pct_skip_cnt: Option<u8>,

    /// ECC Error Info
    #[ddi(id = 7)]
    pub ecc_error_info: Option<DdiTestActionEccErrorInfo>,

    /// Trigger Tdisp Interrupt Type
    #[ddi(id = 8)]
    pub tdisp_interrupt_type: Option<DdiTestActionInterruptSimulationType>,

    /// SVN value to be updated
    #[ddi(id = 9)]
    pub updated_svn: Option<u64>,

    /// GDMA Error Type
    #[ddi(id = 10)]
    pub gdma_error_type: Option<DdiTestActionGDMAErrorType>,

    /// Stack Validation Info
    #[ddi(id = 11)]
    pub stack_validation_info: Option<DdiTestActionStackValidationReqInfo>,

    /// UCD Error Type
    #[ddi(id = 12)]
    pub ucd_error_type: Option<DdiTestActionUCDErrorType>,
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

/// `DdiOp::GetPrivKey` — FIPS-validation read-back of a key's private
/// material. Served below the PAL under `fips_validation_hooks`; not a
/// core opcode.
pub const DDI_OP_GET_PRIV_KEY: DdiOp = DdiOp(2005);

/// `DdiOp::RawKeyImport` — FIPS-validation import of raw key material.
/// Served below the PAL under `fips_validation_hooks`; not a core opcode.
pub const DDI_OP_RAW_KEY_IMPORT: DdiOp = DdiOp(2008);

/// DDI Get Private Key request.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,
}

/// DDI Get Private Key response.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyResp {
    /// Key type
    #[ddi(id = 1)]
    pub key_kind: DdiKeyType,

    /// Private key data. Supports ECC and RSA (including RSA CRT) private
    /// keys, as well as raw secret material.
    #[ddi(id = 2)]
    pub key_data: MborByteArray<2564>,
}

ddi_op_req_resp!(DdiGetPrivKey);

/// DDI RAW Key Import (test operation) request.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportReq {
    /// RAW format key material.
    #[ddi(id = 1)]
    pub raw: MborByteArray<3072>,

    /// Key type.
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,

    /// Key tag (optional). May only be used with app keys. The tag must be
    /// unique within the app; a tag of `0x0000` is not allowed.
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,

    /// Key properties.
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI RAW Key Import (test operation) response.
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional bulk key ID.
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,

    /// Masked key.
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiRawKeyImport);
