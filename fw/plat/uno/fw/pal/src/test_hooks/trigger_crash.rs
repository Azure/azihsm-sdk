// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inject a crash into the CP1 HSM core.

use core::convert::Infallible;

use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

use super::test_action::decode_payload;

/// On-wire CPU identifier for the CP1 HSM core.
const CPU_ID_HSM: u32 = 1;

/// Mirrors the host test-hooks `DdiTestActionCrashReqInfo` MBOR
/// representation without introducing a PAL-to-host dependency.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionCrashReqInfo {
    /// Requested crash mechanism.
    #[ddi(id = 1)]
    crash_type: u32,
    /// Target processor.
    #[ddi(id = 2)]
    cpu_id: u32,
}

/// Validated crash request for the local CP1 HSM core.
#[derive(Debug, Copy, Clone)]
struct CrashRequest {
    /// Crash mechanism to execute.
    crash_type: CrashType,
}

/// Crash mechanisms supported by the CP1 HSM core.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum CrashType {
    /// Execute an undefined instruction.
    HardFault = 1,
    /// Trigger the firmware panic path.
    Explicit = 2,
    /// Trigger the firmware panic path.
    Panic = 3,
    /// Stop making forward progress.
    Hang = 4,
}

impl TryFrom<u32> for CrashType {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::HardFault as u32 => Ok(Self::HardFault),
            value if value == Self::Explicit as u32 => Ok(Self::Explicit),
            value if value == Self::Panic as u32 => Ok(Self::Panic),
            value if value == Self::Hang as u32 => Ok(Self::Hang),
            _ => Err(HsmError::InvalidArg),
        }
    }
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

    if wire_request.cpu_id != CPU_ID_HSM {
        return Err(HsmError::UnsupportedCmd);
    }

    Ok(CrashRequest {
        crash_type: CrashType::try_from(wire_request.crash_type)?,
    })
}

#[allow(clippy::empty_loop)]
fn execute(request: CrashRequest) -> HsmResult<Infallible> {
    match request.crash_type {
        CrashType::Hang => loop {},
        CrashType::Panic | CrashType::Explicit => {
            panic!("crash injected by TestAction::TriggerCrash");
        }
        CrashType::HardFault => {
            // SAFETY: The undefined instruction intentionally faults this
            // core and never returns.
            #[cfg(target_arch = "arm")]
            unsafe {
                core::arch::asm!("udf #0", options(noreturn));
            }
            #[cfg(not(target_arch = "arm"))]
            panic!("hard fault injected by TestAction::TriggerCrash");
        }
    }
}
