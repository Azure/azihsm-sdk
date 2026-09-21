// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction::TriggerCrash` handler.
//!
//! Accepts the legacy body `{1: action, 2: crash_info}`, validates that
//! CP1 is the requested target, and injects the selected crash.

use core::convert::Infallible;

use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

const CPU_ID_HSM: u32 = 1;

/// Mirrors the host test-hooks `DdiTestActionCrashReqInfo` MBOR
/// representation without introducing a PAL-to-host dependency.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionCrashReqInfo {
    #[ddi(id = 1)]
    crash_type: u32,
    #[ddi(id = 2)]
    cpu_id: u32,
}

#[derive(Debug, Copy, Clone)]
struct CrashRequest {
    crash_type: CrashType,
}

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum CrashType {
    HardFault = 1,
    Explicit = 2,
    Panic = 3,
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

/// Validate and execute `TriggerCrash`.
pub(super) fn dispatch(
    decoder: &mut MborDecoder,
    body_count: u8,
    req_len: usize,
) -> HsmResult<Infallible> {
    let request = decode_request(decoder, body_count, req_len)?;
    execute(request)
}

fn decode_request(
    decoder: &mut MborDecoder,
    body_count: u8,
    req_len: usize,
) -> HsmResult<CrashRequest> {
    if body_count == 1 && decoder.position() == req_len {
        return Err(HsmError::InvalidArg);
    }

    if body_count != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let crash_info_key = u8::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if crash_info_key != 2 {
        return Err(HsmError::DdiDecodeFailed);
    }

    let wire_request =
        DdiTestActionCrashReqInfo::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;
    if decoder.position() != req_len {
        return Err(HsmError::DdiDecodeFailed);
    }

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
