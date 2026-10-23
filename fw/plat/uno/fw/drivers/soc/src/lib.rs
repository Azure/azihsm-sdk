// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! SoC driver — reads the boot-processor-published SoC reset reason.
//!
//! Mirrors the [`core_status`](azihsm_fw_uno_drivers_core_status) driver: a
//! tiny typed API over a single PSRAM word, here the `RESET_TYPE` slot the
//! Service Processor (SP) publishes before releasing the CP cores.
//!
//! The HSM reads [`reset_type`] once at boot to decide whether this is a
//! cold (power-on) boot or a warm / fw-update recovery boot. On a warm reset
//! the destructive partition-store init is skipped so GSRAM-resident state
//! survives — this is the entry point for recovery boot.
//!
//! Mirrors the reference firmware's `SocResetType` / `SocInfo::reset_type`.

use azihsm_fw_uno_reg_soc::psram::PSRAM_BASE;
use azihsm_fw_uno_reg_soc::psram::RESET_TYPE_OFFSET;

/// Manticore SoC reset reason, published by the boot processor (SP).
#[derive(Default, PartialEq, Eq)]
pub enum SocResetType {
    /// Power-on reset (cold boot).
    #[default]
    Por = 0,

    /// Warm reset, issued during any fault recovery.
    WarmReset = 1,

    /// Firmware-update warm reset.
    FwUpdateWarmReset = 2,
}

impl From<u32> for SocResetType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::WarmReset,
            2 => Self::FwUpdateWarmReset,
            _ => Self::default(),
        }
    }
}

/// Read the SoC reset reason from the PSRAM `RESET_TYPE` word.
///
/// The SP writes this word (abs `0xA3E0_3AFC`) before releasing the CP
/// cores, so it is stable for the lifetime of the boot. Mirrors the
/// reference's volatile `PsRamMemMap::reset_type` read.
#[inline]
pub fn reset_type() -> SocResetType {
    // SAFETY: `PSRAM_BASE + RESET_TYPE_OFFSET` is the fixed, SP-published
    // reset-reason word (abs 0xA3E0_3AFC) in persistent SRAM. It is valid
    // for the device lifetime and only read here; a volatile read matches
    // the reference's volatile PSRAM access.
    let raw = unsafe { ((PSRAM_BASE + RESET_TYPE_OFFSET) as *const u32).read_volatile() };
    raw.into()
}
