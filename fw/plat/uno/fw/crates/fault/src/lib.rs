// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Panic and CPU-exception handlers for the Uno HSM firmware.
//!
//! Installs the firmware's single `#[panic_handler]` plus overrides for the
//! ARMv7-M `HardFault` and `DefaultHandler` exceptions. The goal is fault
//! *visibility*: the default `cortex-m-rt` HardFault handler is a silent
//! infinite loop, so a bus fault (for example, a stray write to a read-only
//! peripheral register) escalates to HardFault and hangs the core with no
//! output. These handlers instead dump the fault cause — decoded `CFSR`
//! bits, the faulting address (`BFAR`/`MMFAR`), the stacked register frame,
//! and `MSP` — so a future fault is diagnosable from the serial log alone.
//!
//! Output goes through [`sink::FaultWriter`] (the SoC UART today), which is
//! compiled unconditionally and therefore works even in production builds
//! that ship without a trace backend.
//!
//! # Linking
//!
//! The panic and exception symbols only take effect if this crate is part
//! of the final binary's dependency graph. The application forces that with
//! `use azihsm_fw_uno_fault as _;` (the `panic-halt` pattern).
//!
//! # Scope
//!
//! This is deliberately a CPU-fault *reporter*. Cross-core crash
//! notification, persistent crash dumps, and peripheral-error ISRs (present
//! in the mcr-hsm `exception-handlers` crate) depend on infrastructure the
//! Uno port does not yet have (Tcon mailbox, crashdump store) and are out of
//! scope here.

#![no_std]
#![allow(unsafe_code)]

mod decode;
mod sink;

use azihsm_fw_uno_reg_cortex_m::scb::regs::ScbRegs;
use azihsm_fw_uno_reg_cortex_m::scb::CFSR;
use azihsm_fw_uno_reg_cortex_m::scb::HFSR;
use azihsm_fw_uno_reg_cortex_m::scb::SCB_BASE;
use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
pub use sink::FaultWriter;
use tock_registers::interfaces::Readable;

/// Borrow the System Control Block MMIO register block.
///
/// # Safety
///
/// `SCB_BASE` is a fixed architectural address that is always mapped on
/// ARMv7-M, so the dereference is sound. Called only from fault context
/// where the firmware is already halting, so aliasing is not a concern.
#[inline(always)]
fn scb() -> &'static ScbRegs {
    unsafe { &*(SCB_BASE as *const ScbRegs) }
}

/// Terminate the firmware after a fault has been reported.
///
/// On emulator builds (`semihosting`) this issues `SYS_EXIT(-1)` so the
/// host stops; on silicon it spins forever (the core is already wedged).
fn halt() -> ! {
    #[cfg(feature = "semihosting")]
    // Semihosting SYS_EXIT status -1 (failure).
    azihsm_fw_uno_drivers_semihosting::sys_exit(u32::MAX);

    loop {
        cortex_m::asm::nop();
    }
}

/// Firmware panic handler.
///
/// Emits the panic location and message (via [`core::panic::PanicInfo`]'s
/// `Display`, which already includes `file:line:col` plus the formatted
/// message) to the fault sink, then halts.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println_fault!("");
    println_fault!("#### PANIC ####");
    println_fault!("{}", info);
    halt();
}

/// HardFault exception handler.
///
/// Reads the SCB fault-status registers, classifies the fault, and dumps:
/// decoded `CFSR` bits, the faulting address when valid, the stacked
/// [`ExceptionFrame`] (R0-R3, R12, LR, PC, xPSR), and `MSP`. A stack
/// overflow (`HFSR.FORCED` + `CFSR.MSTKERR`/`STKERR`) is reported specially
/// because exception stacking failed and the frame is unreliable.
///
/// # Safety
///
/// Required to be an `unsafe fn` by `cortex-m-rt`. Invoked only by the
/// hardware exception mechanism on a HardFault and must never be called
/// directly; it reads fixed architectural SCB registers and the
/// hardware-supplied exception frame, then halts.
#[exception]
unsafe fn HardFault(ef: &ExceptionFrame) -> ! {
    let scb = scb();
    let cfsr = scb.cfsr.get();
    let hfsr = scb.hfsr.get();
    let msp = cortex_m::register::msp::read();

    let forced = scb.hfsr.is_set(HFSR::FORCED);
    // Exception-entry stacking can fail via either a MemManage fault
    // (MSTKERR, e.g. an MPU stack-guard hit on overflow) or a BusFault
    // (STKERR); both escalate to HardFault and leave the pushed register
    // frame unreliable.
    let mstkerr = scb.cfsr.is_set(CFSR::MSTKERR);
    let stkerr = scb.cfsr.is_set(CFSR::STKERR);

    println_fault!("");
    println_fault!("#### HardFault ####");

    if forced && (mstkerr || stkerr) {
        // Exception-entry stacking failed and escalated to HardFault: the
        // CPU could not push {R0-R3,R12,LR,PC,xPSR}, so `ef` is garbage. The
        // faulting PC/LR are unrecoverable on ARMv7-M; only MSP locates
        // where the stack was when it overran its guard region.
        println_fault!("cause: stack overflow (exception frame unreliable)");
        println_fault!("MSP={:#010x} CFSR={:#010x} HFSR={:#010x}", msp, cfsr, hfsr);
    } else {
        decode::report_cfsr(scb);

        if scb.cfsr.is_set(CFSR::BFARVALID) {
            println_fault!("BFAR={:#010x}  (faulting bus address)", scb.bfar.get());
        }
        if scb.cfsr.is_set(CFSR::MMARVALID) {
            println_fault!("MMFAR={:#010x} (faulting memory address)", scb.mmfar.get());
        }

        println_fault!("CFSR={:#010x} HFSR={:#010x} MSP={:#010x}", cfsr, hfsr, msp);
        println_fault!("frame: {:#?}", ef);

        #[cfg(feature = "fault-stackdump")]
        unsafe {
            stack_dump(msp);
        }
    }

    halt();
}

/// Catch-all handler for any exception/interrupt without a dedicated
/// handler. Reports the offending exception number so an unexpected or
/// spurious interrupt is no longer silent, then halts.
///
/// # Safety
///
/// Required to be an `unsafe fn` by `cortex-m-rt`. Invoked only by the
/// hardware exception mechanism for an otherwise-unhandled exception/IRQ
/// and must never be called directly.
#[exception]
unsafe fn DefaultHandler(irqn: i16) -> ! {
    println_fault!("");
    println_fault!("#### Unexpected exception/IRQ: {} ####", irqn);
    halt();
}

/// Dump `WORDS` 32-bit words of raw stack memory starting at `sp`.
///
/// Development aid behind the `fault-stackdump` feature — useful for
/// eyeballing return addresses and locals near the fault, at the cost of
/// reading memory that may extend past the live stack.
///
/// # Safety
///
/// Performs volatile reads of arbitrary stack addresses; the range may run
/// past valid RAM. Intended for debug builds on hardware only.
#[cfg(feature = "fault-stackdump")]
unsafe fn stack_dump(sp: u32) {
    const WORDS: usize = 32;
    // `read_volatile::<u32>` requires a 4-byte-aligned pointer; `sp` may be
    // corrupted or misaligned at the fault, so align the base down first to
    // avoid undefined behaviour while keeping the dump word-oriented.
    let base = sp & !0b11;
    println_fault!("stack dump @ {:#010x}:", base);
    for i in 0..WORDS {
        let addr = base.wrapping_add((i * 4) as u32);
        let val = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if i % 4 == 0 {
            print_fault!("\n  {:#010x}:", addr);
        }
        print_fault!(" {:08x}", val);
    }
    println_fault!("");
}
