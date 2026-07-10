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
//! * The post-enable settling delay matches the reference firmware's
//!   `cpu_stall(100_000 µs)` (≈100 ms) — see `RNG_INIT_DELAY_NOPS`
//!   below for rationale.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_error::HsmError;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_reg_soc::rng::regs::RngRegs;
use azihsm_fw_uno_reg_soc::rng::APT_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::CHISQ_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::CLK_DIV_MSB;
use azihsm_fw_uno_reg_soc::rng::CTRL;
use azihsm_fw_uno_reg_soc::rng::FWIN_DATA;
use azihsm_fw_uno_reg_soc::rng::FWOUT_DATA;
use azihsm_fw_uno_reg_soc::rng::GENERATE_INTERVAL;
use azihsm_fw_uno_reg_soc::rng::REPCNT_CUTOFF;
use azihsm_fw_uno_reg_soc::rng::RESEED_INTERVAL;
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
/// On real silicon the analog TRBG clock requires ~100 ms to stabilize
/// after the RNG is enabled.
///
/// At the 450 MHz core clock, counting ~2 cycles per `nop` loop iteration
/// (one `nop` + the loop's subtract/branch), that is:
///
/// ```text
///   100_000 µs × 450 MHz ÷ 2 = 22_500_000 iterations
/// ```
///
/// An insufficient delay here lets `wait_for_random_data` re-enable the
/// block before it settles; under sustained load (e.g. rapid key
/// generation) this degenerates into a tight enable/disable toggle loop
/// and an imprecise bus fault on the `CTRL` MMIO write.
const RNG_INIT_DELAY_NOPS: u32 = 100_000 * 450 / 2;

/// Upper bound on wait-loop poll iterations in [`RngDriver::self_test`].
///
/// The reference firmware bounds each DRBG wait with a ~4 µs `Tcon::tsc()`
/// counter that Uno has no equivalent for. This poll-iteration budget is the
/// stand-in: generous enough never to trip during a healthy DRBG run (which
/// completes in microseconds), but finite so a stuck engine fails the CAST at
/// the boot gate instead of hanging forever.
const RNG_SELF_TEST_MAX_SPINS: u32 = 1_000_000;

/// DRBG generate interval (in generate cycles) used during the FW-mode KAT.
const DRBG_GENERATE_INTERVAL: u32 = 2;

/// DRBG reseed interval (in generate cycles) used during the FW-mode KAT.
const DRBG_RESEED_INTERVAL: u32 = 2;

/// DRBG FW-mode self-test input vector (seed material).
///
/// Ported byte-for-byte from the reference firmware
/// (`drivers/crypto/rng/src/rng.rs::RNG_SELF_TEST_INPUT`).
const RNG_SELF_TEST_INPUT: [u32; 16] = [
    0x2cb8_5c71,
    0xdef8_49bf,
    0x5346_88e3,
    0x03bf_f6bd,
    0x9923_dfd1,
    0x28e0_a0d7,
    0xf38f_606c,
    0xcd88_cb0b,
    0xd41f_21da,
    0x16b2_d32f,
    0x041b_8db2,
    0xb5b5_2b5b,
    0x1700_01ef,
    0x602d_910b,
    0x5a17_e20f,
    0xf9a0_b0b9,
];

/// Expected DRBG FW-mode generate output for [`RNG_SELF_TEST_INPUT`].
///
/// Ported byte-for-byte from the reference firmware
/// (`RNG_SELF_TEST_EXPECTED_OUTPUT`).
const RNG_SELF_TEST_EXPECTED_OUTPUT: [u32; 16] = [
    0x2df5_26c1,
    0x4ed2_fea1,
    0xe03e_4e33,
    0x773b_820d,
    0x5363_125e,
    0x5731_b848,
    0xf922_7325,
    0x8364_e0f5,
    0xc0fd_533e,
    0x1572_b04f,
    0x678f_4cdc,
    0xf989_cd2b,
    0x580a_18c2,
    0xe9d9_8573,
    0x4789_01b9,
    0xf6aa_61ed,
];

/// DRBG FW-mode self-test reseed input vector.
///
/// Ported byte-for-byte from the reference firmware
/// (`RNG_SELF_TEST_RESEED_INPUT`).
const RNG_SELF_TEST_RESEED_INPUT: [u32; 16] = [
    0x9fc0_ef1b,
    0x69bd_5cee,
    0x0536_d040,
    0x84e3_24ac,
    0xe803_252f,
    0x51f6_cb45,
    0x9f42_5836,
    0x85a1_550b,
    0x1ebf_fe37,
    0xcca0_724b,
    0x77ec_8fcc,
    0x1cd9_9781,
    0x0022_6942,
    0x3add_2d04,
    0xb677_7a10,
    0xac8f_0743,
];

/// Expected DRBG FW-mode reseed output for [`RNG_SELF_TEST_RESEED_INPUT`].
///
/// Ported byte-for-byte from the reference firmware
/// (`RNG_SELF_TEST_EXPECTED_RESEED_OUTPUT`).
const RNG_SELF_TEST_EXPECTED_RESEED_OUTPUT: [u32; 16] = [
    0xa6fc_aa14,
    0xd9cb_3539,
    0x9ba9_b84e,
    0x9864_e8ff,
    0x079b_82c3,
    0x32d3_18f6,
    0x8fac_5900,
    0x73fd_9211,
    0xe2bd_a914,
    0xaafe_a144,
    0x523b_af42,
    0x97f2_049e,
    0x3221_4767,
    0xa1fd_de1c,
    0x141d_a708,
    0x14b6_5a29,
];

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

    /// DRBG FW-mode known-answer self-test (pre-operational CAST).
    ///
    /// Ported as-is from the reference firmware
    /// (`drivers/crypto/rng/src/rng.rs::self_test`). Drives the DRBG through
    /// its firmware-mode back door: seeds the FW input FIFO with a fixed
    /// vector, runs instantiate + generate, and compares the FW output FIFO
    /// against the expected known answer; then exercises the reseed path with
    /// a second fixed vector. The production DRBG registers (control word and
    /// generate/reseed intervals) are saved on entry and restored before
    /// return, so the RNG is left in its normal operating mode on both the
    /// success and failure paths.
    ///
    /// # Returns
    /// * `Ok(())` if both the generate and reseed outputs match their vectors.
    ///
    /// # Errors
    /// * [`HsmError::SelfTestKatMismatch`] on any output mismatch, DRBG fault,
    ///   or wait-loop timeout.
    ///
    /// # Timeout
    /// The reference bounds each wait with a ~4 µs `Tcon::tsc()` counter that
    /// Uno lacks; here each wait loop is bounded by [`RNG_SELF_TEST_MAX_SPINS`]
    /// poll iterations instead. Exhausting the budget fails the test (never a
    /// hang), so a stuck DRBG surfaces a clean CAST failure at the boot gate.
    pub fn self_test(&self) -> HsmResult<()> {
        // Before switching to FW mode, ensure the DRBG is not actively reading
        // entropy — FW mode cannot be entered while an entropy read is in
        // flight.
        Self::spin_while(|| REGS.status.is_set(STATUS::ENTROPY_FIFO_READ))?;

        // Save the production register state so it can be restored on exit.
        let saved_generate_interval = REGS.generate_interval.get();
        let saved_reseed_interval = REGS.reseed_interval.get();
        let saved_ctrl = REGS.ctrl.get();

        // Shorten the generate/reseed intervals so the KAT exercises a reseed.
        REGS.generate_interval
            .write(GENERATE_INTERVAL::VALUE.val(DRBG_GENERATE_INTERVAL));
        REGS.reseed_interval
            .write(RESEED_INTERVAL::VALUE.val(DRBG_RESEED_INTERVAL));

        // Enter FW mode and kick off instantiate + generate.
        REGS.ctrl.modify(
            CTRL::ENABLE::SET
                + CTRL::FW_MODE::SET
                + CTRL::DRBG_INSTANTIATE::SET
                + CTRL::DRBG_GENERATE::SET
                + CTRL::DRBG_UNINSTANTIATE::CLEAR,
        );

        // Restore the RNG to normal mode; run on every early-exit path.
        let cleanup = || {
            REGS.ctrl.modify(
                CTRL::DRBG_GENERATE::CLEAR + CTRL::DRBG_INSTANTIATE::CLEAR + CTRL::FW_MODE::CLEAR,
            );
            REGS.generate_interval.set(saved_generate_interval);
            REGS.reseed_interval.set(saved_reseed_interval);
        };

        // Fill the input FIFO; once full the DRBG starts processing it.
        for word in RNG_SELF_TEST_INPUT {
            REGS.fwin_data.write(FWIN_DATA::DATA.val(word));
        }

        Self::wait_for_drbg_instantiate().inspect_err(|_e| cleanup())?;
        Self::wait_for_drbg_generate().inspect_err(|_e| cleanup())?;
        Self::compare_output(&RNG_SELF_TEST_EXPECTED_OUTPUT).inspect_err(|_e| cleanup())?;

        // Reseed path: wait for the DRBG to request a reseed, feed it the
        // reseed vector, then wait for it to complete.
        Self::wait_till_status_is_set_to_busy().inspect_err(|_e| cleanup())?;
        Self::wait_till_reseed_is_set().inspect_err(|_e| cleanup())?;

        for word in RNG_SELF_TEST_RESEED_INPUT {
            REGS.fwin_data.write(FWIN_DATA::DATA.val(word));
        }

        Self::wait_for_reseed_clear().inspect_err(|_e| cleanup())?;
        Self::wait_for_busy_status_clear().inspect_err(|_e| cleanup())?;

        // Compare the reseed output (the reference does not discard here).
        for word in RNG_SELF_TEST_EXPECTED_RESEED_OUTPUT {
            if REGS.fwout_data.read(FWOUT_DATA::DATA) != word {
                cleanup();
                return Err(HsmError::SelfTestKatMismatch);
            }
        }

        // Restore the RNG to its normal operating mode.
        REGS.generate_interval.set(saved_generate_interval);
        REGS.reseed_interval.set(saved_reseed_interval);
        REGS.ctrl.set(saved_ctrl);
        REGS.ctrl.modify(
            CTRL::FW_MODE::CLEAR + CTRL::DRBG_INSTANTIATE::CLEAR + CTRL::DRBG_GENERATE::CLEAR,
        );

        Ok(())
    }

    /// Poll `busy` until it returns `false`, bounded by
    /// [`RNG_SELF_TEST_MAX_SPINS`]. Returns [`HsmError::SelfTestKatMismatch`]
    /// if the budget is exhausted (the Uno stand-in for the reference's
    /// `Tcon::tsc()` timeout).
    fn spin_while<F: Fn() -> bool>(busy: F) -> HsmResult<()> {
        let mut budget = RNG_SELF_TEST_MAX_SPINS;
        while busy() {
            budget -= 1;
            if budget == 0 {
                return Err(HsmError::SelfTestKatMismatch);
            }
        }
        Ok(())
    }

    /// Wait for the DRBG instantiate operation to finish, failing early on a
    /// DRBG fault.
    fn wait_for_drbg_instantiate() -> HsmResult<()> {
        let mut budget = RNG_SELF_TEST_MAX_SPINS;
        while REGS.status.is_set(STATUS::DRBG_INST_BUSY) {
            if REGS.status.is_set(STATUS::DRBG_FAULT_ERROR) {
                return Err(HsmError::SelfTestKatMismatch);
            }
            budget -= 1;
            if budget == 0 {
                return Err(HsmError::SelfTestKatMismatch);
            }
        }
        Ok(())
    }

    /// Wait for the DRBG generate operation to complete (`STATUS.BUSY` clear).
    fn wait_for_drbg_generate() -> HsmResult<()> {
        Self::spin_while(|| REGS.status.is_set(STATUS::BUSY))
    }

    /// Wait for `STATUS.BUSY` to be set (a reseed request is pending).
    fn wait_till_status_is_set_to_busy() -> HsmResult<()> {
        Self::spin_while(|| !REGS.status.is_set(STATUS::BUSY))
    }

    /// Wait for the DRBG reseed-busy flag to be set.
    fn wait_till_reseed_is_set() -> HsmResult<()> {
        Self::spin_while(|| !REGS.status.is_set(STATUS::DRBG_RESEED_BUSY))
    }

    /// Wait for the DRBG reseed-busy flag to clear.
    fn wait_for_reseed_clear() -> HsmResult<()> {
        Self::spin_while(|| REGS.status.is_set(STATUS::DRBG_RESEED_BUSY))
    }

    /// Wait for `STATUS.BUSY` to clear.
    fn wait_for_busy_status_clear() -> HsmResult<()> {
        Self::spin_while(|| REGS.status.is_set(STATUS::BUSY))
    }

    /// Read and discard the first 16 FW-output words, then compare the next 16
    /// against `expected`. Mirrors the reference `compare_output`.
    fn compare_output(expected: &[u32; 16]) -> HsmResult<()> {
        for _ in 0..expected.len() {
            let _ = REGS.fwout_data.read(FWOUT_DATA::DATA);
        }
        for &word in expected {
            if REGS.fwout_data.read(FWOUT_DATA::DATA) != word {
                return Err(HsmError::SelfTestKatMismatch);
            }
        }
        Ok(())
    }
}
