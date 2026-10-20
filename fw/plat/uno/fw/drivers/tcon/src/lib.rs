// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! TCON driver — cross-core crash-notification via wakeup timer 1.
//!
//! Ported from the reference firmware's `mcr-tcon` driver, trimmed to the
//! wakeup1 control path used by crash recovery. On a fatal fault the
//! faulting core calls [`Tcon::fire_wakeup_timer1`], which arms wakeup1 as
//! a one-shot level interrupt. That raises `tcon_wakeup1_irq` (NVIC 89) on
//! the peer core, whose handler collects its own crash dump and halts. The
//! receiver disarms the timer via [`Tcon::disable_wakeup_timer1`].
//!
//! Each `WAKEUP_CTRL` field is 2 bits wide — bit `[0]` is wakeup0, bit
//! `[1]` is wakeup1 — so every write is a read-modify-write that preserves
//! the wakeup0 bit, exactly as the reference driver does. The reference
//! TSC (`timer_lo`/`timer_hi`) and wakeup0 periodic tick are not ported:
//! uno keeps time via SysTick / Embassy.

use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::tcon::regs::TconRegs;
use azihsm_fw_uno_reg_soc::tcon::TCON_BASE;
use azihsm_fw_uno_reg_soc::tcon::WAKEUP1_CNT;
use azihsm_fw_uno_reg_soc::tcon::WAKEUP_CTRL;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

/// MMIO register overlay for the TCON peripheral.
const REGS: StaticRef<TconRegs> = unsafe { StaticRef::new(TCON_BASE as *const TconRegs) };

/// Bit mask selecting wakeup0 within a 2-bit `WAKEUP_CTRL` field.
const WAKEUP0_BIT: u32 = 0b01;

/// Bit mask selecting wakeup1 within a 2-bit `WAKEUP_CTRL` field.
const WAKEUP1_BIT: u32 = 0b10;

/// Timer Controller — wakeup1 crash-notification interface.
///
/// Stateless: all coordination lives in the hardware `WAKEUP_CTRL` and
/// `WAKEUP1_CNT` registers.
#[derive(Clone)]
pub struct Tcon;

impl Tcon {
    /// Disable the wakeup1 timer if it is currently armed.
    ///
    /// Clears `WAKEUP_CTRL.WAKEUP_ENABLE[1]` while preserving the wakeup0
    /// enable bit. Called by the `tcon_wakeup1_irq` receiver before it
    /// collects its crash dump, so the notification does not re-fire.
    pub fn disable_wakeup_timer1() {
        let enable = REGS.wakeup_ctrl.read(WAKEUP_CTRL::WAKEUP_ENABLE);
        REGS.wakeup_ctrl
            .modify(WAKEUP_CTRL::WAKEUP_ENABLE.val(enable & WAKEUP0_BIT));
    }

    /// Fire the wakeup1 timer to notify the peer core of a crash.
    ///
    /// Mirrors the reference `fire_wakeup_timer1`: configure wakeup1 as a
    /// one-shot level interrupt, load a count of 1 so it expires on the
    /// next tick, then enable it. Every `WAKEUP_CTRL` update preserves the
    /// unrelated wakeup0 bit.
    pub fn fire_wakeup_timer1() {
        // wakeup1 = level output (hold the interrupt asserted).
        let level = REGS.wakeup_ctrl.read(WAKEUP_CTRL::WKINTR_LEVEL_EN);
        REGS.wakeup_ctrl
            .modify(WAKEUP_CTRL::WKINTR_LEVEL_EN.val(level | WAKEUP1_BIT));

        // wakeup1 = one-shot (clear periodic repeat).
        let repeat = REGS.wakeup_ctrl.read(WAKEUP_CTRL::WKINTR_RPT_EN);
        REGS.wakeup_ctrl
            .modify(WAKEUP_CTRL::WKINTR_RPT_EN.val(repeat & WAKEUP0_BIT));

        // Fire on the next tick.
        REGS.wakeup1_cnt.write(WAKEUP1_CNT::VALUE.val(1));

        // Enable wakeup1.
        let enable = REGS.wakeup_ctrl.read(WAKEUP_CTRL::WAKEUP_ENABLE);
        REGS.wakeup_ctrl
            .modify(WAKEUP_CTRL::WAKEUP_ENABLE.val(enable | WAKEUP1_BIT));
    }
}
