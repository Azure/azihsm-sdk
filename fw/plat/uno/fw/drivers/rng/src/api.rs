// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `RngDriver` — synchronous polled wrapper over the SoC RNG block.
//!
//! Ported from azihsm-sdk (`fw/drivers/rng`); preserves the
//! calibration sequence, polling discipline, and fault-recovery
//! pattern.
//!
//! Differences from azihsm:
//!
//! * Returns `HsmResult<()>` from `fill_bytes` to match the existing
//!   `HsmRng` trait shape used by the Uno PAL.
//! * The post-enable settling delay is reduced from 100 ms to a
//!   nominal value — see `RNG_INIT_DELAY_NOPS` below for rationale.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_reg_soc::rng::regs::RngRegs;
use azihsm_fw_uno_reg_soc::rng::APT_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::CHISQ_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::CLK_DIV_MSB;
use azihsm_fw_uno_reg_soc::rng::CTRL;
use azihsm_fw_uno_reg_soc::rng::REPCNT_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::RNG_BASE;
use azihsm_fw_uno_reg_soc::rng::RN_DATA;
use azihsm_fw_uno_reg_soc::rng::STATUS;
use cortex_m::asm::nop;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

/// MMIO register overlay for the RNG peripheral.
const REGS: StaticRef<RngRegs> = unsafe { StaticRef::new(RNG_BASE as *const RngRegs) };

/// Settling delay (in `nop` iterations) applied after `CTRL.ENABLE`.
///
/// On real silicon, the analog TRBG clock may require 100 ms
/// (≈22.5 M nops at 450 MHz) to stabilize. This Uno PAL reduces the
/// delay to a token value to keep boot time bounded — production
/// builds running on the actual analog block must raise this back to
/// the silicon-recommended 100 ms.
const RNG_INIT_DELAY_NOPS: u32 = 64;

/// TRBG / DRBG calibration parameters.
///
/// [`RngCalibration::DEFAULT`] provides the silicon-specific values
/// required to bring up the RNG before any PKA command can be issued.
#[derive(Debug, Clone, Copy)]
pub struct RngCalibration {
    /// Lower 8 bits of the TRBG ring-oscillator clock divider
    /// (written to `CTRL.CLK_DIV`).
    pub clk_div: u8,

    /// Upper 2 bits of the TRBG ring-oscillator clock divider
    /// (written to `CLK_DIV_MSB.VALUE`).
    pub clk_div_msb: u8,

    /// Repetition Count Test cutoff (written to
    /// `REPCNT_CUTOFF.VALUE`, 10 bits).
    pub repcnt: u32,

    /// Adaptive Proportion Test cutoff (written to
    /// `APT_CUTOFF.VALUE`, 10 bits).
    pub apt: u32,

    /// Chi-Square Test cutoff (written to `CHISQ_CUTOFF.VALUE`,
    /// 10 bits).
    pub chisq: u32,
}

impl RngCalibration {
    /// Default calibration for this silicon. Required for the PKA
    /// engines to function correctly.
    pub const DEFAULT: Self = Self {
        clk_div: 0x60,
        clk_div_msb: 0,
        repcnt: 0x29,
        apt: 0x318,
        chisq: 0x82,
    };
}

/// Synchronous CTR_DRBG-style RNG driver.
///
/// Stateless — all coordination lives in the hardware's `STATUS`
/// register.
#[derive(Debug, Default)]
pub struct RngDriver;

impl RngDriver {
    /// Construct a new driver handle. Does not touch hardware.
    pub const fn new() -> Self {
        Self
    }

    /// Calibrate and enable the RNG block with default calibration values.
    pub fn init(&self) {
        self.init_calibrated(&RngCalibration::DEFAULT);
    }

    /// Calibrate and enable the RNG block.
    ///
    /// Calibrate the RNG block in the required programming order:
    ///
    /// 1. `CTRL.ENABLE = 0` (so calibration writes are accepted).
    /// 2. Modify `CTRL.CLK_DIV` (CLK_DIV field only — other bits
    ///    preserved).
    /// 3. Write `CLK_DIV_MSB`, `APT_CUTOFF`, `CHISQ_CUTOFF`,
    ///    `REPCNT_CUTOFF` in that order.
    /// 4. `CTRL.ENABLE = 1` followed by the settling delay.
    pub fn init_calibrated(&self, calibration: &RngCalibration) {
        Self::set_enable(false);

        REGS.ctrl
            .modify(CTRL::CLK_DIV.val(u32::from(calibration.clk_div)));
        REGS.clk_div_msb
            .write(CLK_DIV_MSB::VALUE.val(u32::from(calibration.clk_div_msb)));
        REGS.apt_cutoff
            .write(APT_CUTOFF::VALUE.val(calibration.apt));
        REGS.chisq_cutoff
            .write(CHISQ_CUTOFF::VALUE.val(calibration.chisq));
        REGS.repcnt_cutoff
            .write(REPCNT_CUTOFF::VALUE.val(calibration.repcnt));

        Self::set_enable(true);
    }

    /// Fill `buf` with random bytes by repeatedly polling for fresh
    /// entropy and consuming one 32-bit word per loop iteration.
    ///
    /// The final chunk may be shorter than 4 bytes; the unused tail of
    /// the last word is discarded. Always returns `Ok(())` —
    /// transient TRBG/DRBG faults are transparently recovered inside
    /// `wait_for_random_data`; the call only returns once `buf` is
    /// fully written.
    pub fn fill_bytes(&self, buf: &mut DmaBuf) -> HsmResult<()> {
        for chunk in buf.chunks_mut(core::mem::size_of::<u32>()) {
            Self::wait_for_random_data();
            let word = REGS.rn_data.read(RN_DATA::DATA);
            let bytes = word.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }

    /// Toggle `CTRL.ENABLE`. On the rising edge, stall briefly so the
    /// analog TRBG clock and DRBG state machine can settle.
    fn set_enable(enable: bool) {
        REGS.ctrl.modify(CTRL::ENABLE.val(u32::from(enable)));
        if enable {
            for _ in 0..RNG_INIT_DELAY_NOPS {
                nop();
            }
        }
    }

    /// Wait until the RNG has random data ready to read; restart on
    /// any TRBG/DRBG fault. This includes the deliberate treatment of
    /// `DRBG_INST_BUSY` and `DRBG_RESEED_BUSY` as triggers for a full
    /// reset rather than fault flags. Infallible — only returns once
    /// `STATUS.BUSY` is clear.
    fn wait_for_random_data() {
        loop {
            let status = REGS.status.extract();
            if status.is_set(STATUS::APT_FAULT_ERROR)
                || status.is_set(STATUS::CHISQ_FAULT_ERROR)
                || status.is_set(STATUS::DRBG_FAULT_ERROR)
                || status.is_set(STATUS::DRBG_INST_BUSY)
                || status.is_set(STATUS::DRBG_RESEED_BUSY)
                || status.is_set(STATUS::RBG_FAULT_ERROR)
                || status.is_set(STATUS::REPCNT_FAULT_ERROR)
            {
                Self::set_enable(false);
                Self::set_enable(true);
            }
            if REGS.status.read(STATUS::BUSY) == 0 {
                break;
            }
        }
    }
}
