// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decode and execute `TestAction::TriggerCrash` for the CP1 HSM core.
//!
//! The wire enums and request map mirror the host test-hooks definitions
//! locally so the PAL remains independent of the host crate.

use core::convert::Infallible;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncodeError;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborLen;
use azihsm_fw_ddi_mbor::MborLenAccumulator;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use open_enum::open_enum;

use super::test_action::decode_payload;

/// On-wire crash mechanism, matching the host `DdiTestActionCrashType`.
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
enum DdiTestActionCrashType {
    /// Trigger a HardFault.
    HardFault = 1,
    /// Trigger the explicit-crash panic path.
    ExplicitCrash = 2,
    /// Trigger a panic.
    Panic = 3,
    /// Stop core forward progress.
    Hang = 4,
}

// Open-enum values are encoded as their `u32` discriminants. Implement the
// firmware MBOR traits locally so the request map can retain typed fields
// without depending on the host codec or a core-owned test-hook type.
impl<'a> MborDecode<'a> for DdiTestActionCrashType {
    fn mbor_decode(
        decoder: &mut MborDecoder<'a>,
    ) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError> {
        Ok(Self(u32::mbor_decode(decoder)?))
    }
}

impl MborEncode for DdiTestActionCrashType {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        self.0.mbor_encode(encoder)
    }
}

impl MborLen for DdiTestActionCrashType {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        self.0.mbor_len(acc);
    }
}

/// On-wire target processor, matching the host `DdiTestActionSocCpuId`.
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
enum DdiTestActionSocCpuId {
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

// See `DdiTestActionCrashType` for the local codec rationale.
impl<'a> MborDecode<'a> for DdiTestActionSocCpuId {
    fn mbor_decode(
        decoder: &mut MborDecoder<'a>,
    ) -> Result<Self, azihsm_fw_ddi_mbor::MborDecodeError> {
        Ok(Self(u32::mbor_decode(decoder)?))
    }
}

impl MborEncode for DdiTestActionSocCpuId {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        self.0.mbor_encode(encoder)
    }
}

impl MborLen for DdiTestActionSocCpuId {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        self.0.mbor_len(acc);
    }
}

/// Wire request for `TestAction::TriggerCrash`.
///
/// Mirrors the host test-hooks `DdiTestActionCrashReqInfo` field-for-field
/// without introducing a PAL-to-host dependency.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionCrashReqInfo {
    /// Requested crash mechanism.
    #[ddi(id = 1)]
    crash_type: DdiTestActionCrashType,
    /// Processor that should execute the crash.
    #[ddi(id = 2)]
    cpu_id: DdiTestActionSocCpuId,
}

/// Validated crash request for the local CP1 HSM core.
#[derive(Debug, Copy, Clone)]
struct CrashRequest {
    /// Crash mechanism to execute.
    crash_type: DdiTestActionCrashType,
}

/// Decode, validate, and execute `TestAction::TriggerCrash`.
pub(super) fn dispatch(
    decoder: &mut MborDecoder,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<Infallible> {
    let request = decode_request(decoder, request_field_count, request_len)?;
    execute(request)
}

fn decode_request(
    decoder: &mut MborDecoder,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<CrashRequest> {
    let wire_request: DdiTestActionCrashReqInfo =
        decode_payload(decoder, request_field_count, request_len)?;

    if wire_request.cpu_id != DdiTestActionSocCpuId::Hsm {
        return Err(HsmError::UnsupportedCmd);
    }

    match wire_request.crash_type {
        DdiTestActionCrashType::HardFault
        | DdiTestActionCrashType::ExplicitCrash
        | DdiTestActionCrashType::Panic
        | DdiTestActionCrashType::Hang => Ok(CrashRequest {
            crash_type: wire_request.crash_type,
        }),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Execute a validated local crash request.
#[allow(clippy::empty_loop)]
fn execute(request: CrashRequest) -> HsmResult<Infallible> {
    match request.crash_type {
        DdiTestActionCrashType::Hang => loop {},
        DdiTestActionCrashType::Panic => {
            panic!("crash injected by TestAction::TriggerCrash");
        }
        DdiTestActionCrashType::ExplicitCrash => {
            panic!("explicit crash injected by TestAction::TriggerCrash");
        }
        DdiTestActionCrashType::HardFault => {
            // SAFETY: The undefined instruction intentionally faults this
            // core and never returns.
            #[cfg(target_arch = "arm")]
            unsafe {
                core::arch::asm!("udf #0", options(noreturn));
            }
            #[cfg(not(target_arch = "arm"))]
            panic!("hard fault injected by TestAction::TriggerCrash");
        }
        _ => Err(HsmError::InvalidArg),
    }
}
