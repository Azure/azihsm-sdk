// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decode and execute `TestAction::TriggerCrash` for the HSM and Admin cores.
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
use crate::ipc::CrashType;
use crate::ipc::SocCpuId;
use crate::ipc::encode_trigger_crash;
use crate::pal::IpcChannel;
use crate::pal::UnoHsmPal;

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

/// Validated crash request.
#[derive(Debug, Copy, Clone)]
struct CrashRequest {
    /// Crash mechanism to execute.
    crash_type: DdiTestActionCrashType,
    /// Core that should execute the crash.
    cpu_id: DdiTestActionSocCpuId,
}

/// Decode, validate, and execute `TestAction::TriggerCrash`.
pub(super) async fn dispatch(
    pal: &UnoHsmPal,
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<Infallible> {
    let request = decode_request(decoder, request_field_count, request_len)?;
    execute(pal, request).await
}

fn decode_request(
    decoder: &mut MborDecoder,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<CrashRequest> {
    let wire_request: DdiTestActionCrashReqInfo =
        decode_payload(decoder, request_field_count, request_len)?;

    // All five SoC cores are reachable: the HSM crashes itself, Admin over
    // the HSM→Admin channel, and the three fast-path cores over the HSM→FP
    // channel. Anything else is a malformed core id, which the reference
    // rejects as an invalid argument rather than an unsupported command.
    match wire_request.cpu_id {
        DdiTestActionSocCpuId::Hsm
        | DdiTestActionSocCpuId::Admin
        | DdiTestActionSocCpuId::Fp0
        | DdiTestActionSocCpuId::Fp1
        | DdiTestActionSocCpuId::Fp2 => {}
        _ => return Err(HsmError::InvalidArg),
    }

    match wire_request.crash_type {
        DdiTestActionCrashType::HardFault
        | DdiTestActionCrashType::ExplicitCrash
        | DdiTestActionCrashType::Panic
        | DdiTestActionCrashType::Hang => Ok(CrashRequest {
            crash_type: wire_request.crash_type,
            cpu_id: wire_request.cpu_id,
        }),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Route a validated request to the core that should crash.
async fn execute(pal: &UnoHsmPal, request: CrashRequest) -> HsmResult<Infallible> {
    match request.cpu_id {
        DdiTestActionSocCpuId::Admin => {
            execute_remote(
                pal,
                IpcChannel::AdminRequest,
                SocCpuId::Admin,
                request.crash_type,
            )
            .await
        }
        DdiTestActionSocCpuId::Fp0 => {
            execute_remote(
                pal,
                IpcChannel::FpMessage,
                SocCpuId::Fp0,
                request.crash_type,
            )
            .await
        }
        DdiTestActionSocCpuId::Fp1 => {
            execute_remote(
                pal,
                IpcChannel::FpMessage,
                SocCpuId::Fp1,
                request.crash_type,
            )
            .await
        }
        DdiTestActionSocCpuId::Fp2 => {
            execute_remote(
                pal,
                IpcChannel::FpMessage,
                SocCpuId::Fp2,
                request.crash_type,
            )
            .await
        }
        _ => execute_local(request),
    }
}

/// Map the host-facing crash mechanism onto the HSM↔Admin IPC wire enum.
///
/// The two enums share discriminants today but are separate contracts, so the
/// mapping is written out rather than transmuted.
fn ipc_crash_type(crash_type: DdiTestActionCrashType) -> CrashType {
    match crash_type {
        DdiTestActionCrashType::HardFault => CrashType::HardFault,
        DdiTestActionCrashType::ExplicitCrash => CrashType::ExplicitCrash,
        DdiTestActionCrashType::Panic => CrashType::Panic,
        DdiTestActionCrashType::Hang => CrashType::Hang,
        _ => CrashType::HardFault,
    }
}

/// Tag carried on the crash request. The reply is discarded, so this only
/// has to be a value the responder echoes back unchanged.
const CRASH_REQUEST_TAG: u8 = 0;

/// Ask a remote core to crash itself, then stop.
///
/// `channel` selects the transport and `target` the core that should go down:
/// `AdminRequest` carries Admin crashes over the GSRAM HSM↔Admin rings, and
/// `FpMessage` carries fast-path crashes over the PSRAM HSM↔FP rings. Both
/// mirror the reference `send_crashdump_request`, which picks
/// `hsm_to_admin_ipc_channel` or `fp_ipc_channel` off the same `cpu_id`.
///
/// The request is sent without waiting for a reply, mirroring the reference
/// firmware: its HSM core moves the command to `State::Final` and returns
/// `HsmErr::Pending` as soon as the IPC send succeeds, and has no FSM state
/// that consumes a crash acknowledgement. The remote core does still reply
/// before crashing, but nothing on the requesting side depends on that, so a
/// remote change that stops replying cannot silently disable this path.
///
/// The command must never produce a completion: the remote core is going down
/// and the SP will reset the whole CP, so answering the host would race that
/// reset and could hand back a success. `HsmErr::Pending` is how the
/// reference parks the command; here the equivalent is a future that never
/// resolves, which also keeps this core free to serve other work until the
/// reset lands. The host observes the resulting IO abort, which is what the
/// crash-recovery test asserts.
async fn execute_remote(
    pal: &UnoHsmPal,
    channel: IpcChannel,
    target: SocCpuId,
    crash_type: DdiTestActionCrashType,
) -> HsmResult<Infallible> {
    let msg = encode_trigger_crash(CRASH_REQUEST_TAG, target, ipc_crash_type(crash_type));

    // `reply` is this pair's fire-and-forget transmit: copy into the TX ring,
    // advance PI, ring the doorbell. Unlike `send` it allocates no slot and
    // leaves `in_flight` clear, so the remote acknowledgement arrives with no
    // waiter and is discarded.
    pal.ipc.reply(channel as u8, &msg);

    core::future::pending().await
}

/// Execute a validated crash request on this core.
#[allow(clippy::empty_loop)]
fn execute_local(request: CrashRequest) -> HsmResult<Infallible> {
    match request.crash_type {
        DdiTestActionCrashType::Hang => loop {},
        DdiTestActionCrashType::Panic => {
            panic!("crash injected by TestAction::TriggerCrash");
        }
        // Distinct from `Panic` on purpose: this records
        // `FailureCode::ExplicitFailure` rather than `FailureCode::Panic`, so
        // an injected crash stays distinguishable from a genuine firmware
        // panic in the shared SP-side crash log.
        DdiTestActionCrashType::ExplicitCrash => {
            azihsm_fw_uno_fault::explicit_crash(Some(
                "Triggered by DDI TestAction::TriggerCrash (Explicit)",
            ));
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
