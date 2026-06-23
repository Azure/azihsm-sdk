// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_pac::Interrupt;
use azihsm_fw_uno_reg_cortex_m::nvic::regs::NvicRegs;
use azihsm_fw_uno_reg_cortex_m::nvic::NVIC_BASE;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

const NVIC: StaticRef<NvicRegs> = unsafe { StaticRef::new(NVIC_BASE as *const NvicRegs) };

/// Firmware NVIC helper — static methods for interrupt management.
#[derive(Debug)]
pub struct Nvic;

impl Nvic {
    /// Enable an interrupt in the NVIC.
    #[inline(always)]
    pub fn enable(irq: Interrupt) {
        let n = irq as u32;
        NVIC.iser[(n / 32) as usize].set(1 << (n % 32));
    }

    /// Disable an interrupt in the NVIC.
    #[inline(always)]
    pub fn disable(irq: Interrupt) {
        let n = irq as u32;
        NVIC.icer[(n / 32) as usize].set(1 << (n % 32));
    }

    /// Check whether an interrupt is pending.
    #[inline(always)]
    pub fn is_pending(irq: Interrupt) -> bool {
        let n = irq as u32;
        NVIC.ispr[(n / 32) as usize].get() & (1 << (n % 32)) != 0
    }

    /// Set an interrupt as pending.
    #[inline(always)]
    pub fn pend(irq: Interrupt) {
        let n = irq as u32;
        NVIC.ispr[(n / 32) as usize].set(1 << (n % 32));
    }

    /// Clear a pending interrupt.
    #[inline(always)]
    pub fn unpend(irq: Interrupt) {
        Self::unpend_raw(irq as u16);
    }

    /// Clear a pending interrupt by raw IRQ number.
    #[inline(always)]
    pub fn unpend_raw(irq: u16) {
        let n = irq as u32;
        NVIC.icpr[(n / 32) as usize].set(1 << (n % 32));
    }

    /// Read a raw ISPR register (32 pending bits per register).
    ///
    /// `reg` is the register index (0–7). Returns the full 32-bit
    /// pending bitmask for IRQs `reg*32 .. reg*32+31`.
    #[inline(always)]
    pub fn pending_bits(reg: usize) -> u32 {
        NVIC.ispr[reg].get()
    }
}
