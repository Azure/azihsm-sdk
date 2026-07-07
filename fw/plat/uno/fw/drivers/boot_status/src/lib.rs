// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! Boot status driver — writes the HSM boot status to GSRAM for Admin polling.

use azihsm_fw_uno_reg_soc::io_gsram::BOOT_STATUS_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;

/// Boot status values written to GSRAM for Admin to poll.
#[repr(u32)]
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum BootStatus {
    /// IO processor boot phase completed.
    Done = 2,
    /// IO processor is in run state.
    Run = 3,
}

/// Write the boot status to the GSRAM mailbox register.
#[inline]
pub fn set(status: BootStatus) {
    unsafe {
        ((IO_GSRAM_BASE + BOOT_STATUS_OFFSET) as *mut u32).write_volatile(status as u32);
    }
}
