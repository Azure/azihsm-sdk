// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// Test - Reset Function Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiResetFunctionReq {}

/// Test - Reset Function Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiResetFunctionResp {}

ddi_op_req_resp!(DdiResetFunction);

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

/// Test action crash request info
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

/// DDI Test Action
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

    /// Pin policy override
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
}

/// Test - Skip IO Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiTestActionResp {
    /// Optional 4‑byte reusable result parameter returned by certain test actions
    #[ddi(id = 1)]
    pub result: Option<u32>,
}

ddi_op_req_resp!(DdiTestAction);

/// DDI DER Key Import (Test Operation) Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiDerKeyImportReq {
    /// DER-encoded key
    #[ddi(id = 1)]
    pub der: MborByteArray<3072>,

    /// Key Class
    #[ddi(id = 2)]
    pub key_class: DdiKeyClass,

    /// Key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,

    /// Key properties
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI DER Key Import (Test Operation) Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiDerKeyImportResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional Public Key
    #[ddi(id = 2)]
    pub pub_key: Option<DdiDerPublicKey>,

    /// Optional Bulk Key ID
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,

    /// Key Type
    #[ddi(id = 4)]
    pub key_type: DdiKeyType,

    /// Masked Key
    #[ddi(id = 5)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiDerKeyImport);

/// DDI Get Perf Log (Test Operation) Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiGetPerfLogChunkReq {
    /// Chunk Id
    #[ddi(id = 1)]
    pub chunk_id: u16,
}

/// DDI Get Perf Log Chunk (Test Operation) Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiGetPerfLogChunkResp {
    /// Chunk blob
    #[ddi(id = 1)]
    pub chunk: [u8; 2048usize],

    /// Length in bytes of the chunk
    #[ddi(id = 2)]
    pub chunk_len: u16,
}

ddi_op_req_resp!(DdiGetPerfLogChunk);

/// DDI Get Private Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,
}

/// DDI Get Private Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetPrivKeyResp {
    /// Key type
    #[ddi(id = 1)]
    pub key_kind: DdiKeyType,

    /// Private key Data
    /// Supports ECC and RSA (including RSA CRT) private keys.
    #[ddi(id = 2)]
    pub key_data: MborByteArray<2564>,
}

ddi_op_req_resp!(DdiGetPrivKey);

/// DDI SHA Digest Generate Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiShaDigestGenerateReq {
    /// Sha digest mode
    #[ddi(id = 1)]
    pub sha_mode: DdiHashAlgorithm,

    #[ddi(id = 2)]
    pub msg: MborByteArray<1024>,
}

/// DDI SHA Digest Generate Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiShaDigestGenerateResp {
    /// Output digest
    #[ddi(id = 1)]
    pub digest: MborByteArray<64>,
}

ddi_op_req_resp!(DdiShaDigestGenerate);

/// DDI Get Random Number Generate Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetRngGenerateReq {
    /// Get random number length in Bytes
    #[ddi(id = 1)]
    pub rng_len: u8,
}

/// DDI Get Random Number Generate Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetRngGenerateResp {
    /// Output Random Number - Max 64 Bytes.
    #[ddi(id = 1)]
    pub rng_number: MborByteArray<64>,
}

ddi_op_req_resp!(DdiGetRngGenerate);

/// DDI RAW Key Import (Test Operation) Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportReq {
    /// RAW Format key
    #[ddi(id = 1)]
    pub raw: MborByteArray<3072>,

    /// Key Type
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,

    /// Key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 3)]
    pub key_tag: Option<u16>,

    /// Key properties
    #[ddi(id = 4)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI RAW Key Import (Test Operation) Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRawKeyImportResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional Bulk Key ID
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,

    /// Masked Key
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiRawKeyImport);

/// Aes Key Unwrap Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSoftAesReq {
    #[ddi(id = 1)]
    pub key: MborByteArray<32>,

    #[ddi(id = 2)]
    pub inout: MborByteArray<1024>,

    #[ddi(id = 3)]
    pub op: DdiSoftAesOp,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiSoftAesOp {
    /// Key Wrap with Padding Op
    Kwp = 0,

    /// AES ECB Decrypt Op
    EcbDecrypt = 1,
}

/// Aes Key Unwrap Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSoftAesResp {
    /// Output data
    #[ddi(id = 1)]
    pub plaintext: MborByteArray<1024>,
}

crate::ddi_op_req_resp!(DdiSoftAes);

impl DdiRsaUnwrapKekReq {
    #[cfg(feature = "pre_encode")]
    pub fn wrapped_blob_pre_encode(
        &self,
        input_array: &MborByteArray<3072>,
    ) -> Result<MborByteArray<3072>, MborEncodeError> {
        let mut output_array = [0u8; 3072];

        let rsa_size = 256;
        let len = input_array.len();
        let data = input_array.data();

        if len > data.len() || len > output_array.len() || len < rsa_size {
            return Err(MborEncodeError::InvalidLen);
        }

        // Change endianness for just the rsa size chunk
        reverse_copy(&mut output_array[..rsa_size], &data[..rsa_size]);

        // Copy rest of data
        output_array[rsa_size..input_array.len()]
            .copy_from_slice(&data[rsa_size..input_array.len()]);

        Ok(MborByteArray::new(output_array, input_array.len())?)
    }
}

/// DDI RSA Unwrap KEK Operation Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaUnwrapKekReq {
    /// Unwrapping Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Wrapped blob
    #[ddi(id = 2)]
    #[ddi(pre_encode_fn = "wrapped_blob_pre_encode")]
    pub wrapped_blob: MborByteArray<3072>,

    /// Padding
    #[ddi(id = 3)]
    pub wrapped_blob_padding: DdiRsaCryptoPadding,

    /// Hash Algorithm
    #[ddi(id = 4)]
    pub wrapped_blob_hash_algorithm: DdiHashAlgorithm,
}

/// DDI RSA Unwrap KEK Test Operation Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiRsaUnwrapKekResp {
    /// Decoded KEK
    #[ddi(id = 1)]
    pub kek: MborByteArray<256>,
}

crate::ddi_op_req_resp!(DdiRsaUnwrapKek);
