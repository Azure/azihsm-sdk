// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Boot handshake helpers for Uno firmware.
//!
//! Provides the same boot-status signalling primitives as azihsm's
//! `app/src/boot_handshake.rs`. The full Admin↔HSM IPC protocol
//! (NormalBoot/Start) is NOT executed here because the platform does
//! not yet implement an Admin-side peer. Once an Admin peer exists,
//! this module can grow `run_boot_handshake()` to mirror azihsm verbatim.
//!
//! Current usage from `main.rs`:
//!
//! 1. `pal.pre_init()`           — IPC ready
//! 2. `set_boot_status(Done)`    — silicon-faithful signal
//! 3. `pal.init()`               — bring up rest of PAL
//! 4. `set_boot_status(Run)`     — silicon-faithful signal
//!
//! See `sdk/fw/plat/.../boot_handshake.rs` (azihsm) for the full
//! Admin-coordinated flow.

use azihsm_fw_uno_pal::IoProcessorBootState;
use azihsm_fw_uno_reg_soc::io_gsram::BOOT_STATUS_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;

/// Sets the boot status word in GSRAM for an Admin peer to poll.
///
/// Writes a single 32-bit volatile store; safe to call from any
/// async or synchronous context.
pub fn set_boot_status(status: IoProcessorBootState) {
    // SAFETY: BOOT_HANDSHAKE_BASE + BOOT_STATUS_OFFSET addresses a
    // 4-byte word in the GSRAM region reserved by `hsm_status.rdl`.
    // The region is not aliased with any other firmware state.
    unsafe {
        ((IO_GSRAM_BASE + BOOT_STATUS_OFFSET) as *mut u32).write_volatile(status.0);
    }
}
