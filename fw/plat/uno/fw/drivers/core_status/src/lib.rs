// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! Core status driver — writes the HSM core liveliness heartbeat to DTCM.
//!
//! Mirrors the [`boot_status`](azihsm_fw_uno_drivers_boot_status) driver:
//! a tiny typed API over a single status register, here the
//! `CORE_RUN_STATUS` slot in HSM DTCM.
//!
//! The Service Processor (SP) polls `CORE_RUN_STATUS` and zeroes it each
//! cycle. The HSM core writes [`ALIVE`](CoreStatus::Alive) periodically;
//! if the SP reads zero on the next poll, it declares the core hung.

use azihsm_fw_uno_reg_soc::hsm_dtcm::CORE_RUN_STATUS_OFFSET;
use azihsm_fw_uno_reg_soc::hsm_dtcm::HSM_DTCM_BASE;

/// Core run status values written to DTCM for the SP to poll.
#[repr(u32)]
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum CoreStatus {
    /// Core made forward progress since the SP last zeroed the slot.
    Alive = 1,
}

/// Write `status` to the DTCM `CORE_RUN_STATUS` register.
#[inline]
pub fn set(status: CoreStatus) {
    unsafe {
        ((HSM_DTCM_BASE + CORE_RUN_STATUS_OFFSET) as *mut u32).write_volatile(status as u32);
    }
}
