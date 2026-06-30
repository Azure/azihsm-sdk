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
//! and `MSP` — so a fault is diagnosable from the serial log.
//!
//! # Output via the tracing facade
//!
//! Diagnostics are emitted through `azihsm_fw_hsm_core_tracing` (`error!`),
//! the same facade the rest of the firmware uses, rather than a bespoke
//! sink. This keeps faults on one logging path: they share the backend,
//! formatting, and (future) debug-log/token routing as every other trace.
//! As with all tracing, the messages are present only when a trace level is
//! enabled in the final image (e.g. the `trace-uart` bring-up build); a
//! trace-disabled production build emits nothing here until an always-on
//! logging backend (HSP debug-log) is brought up — at which point faults
//! gain it uniformly with the rest of the firmware.
//!
//! Each handler logs at error level with an exception-specific `HsmError`
//! code — [`HsmError::Panic`], [`HsmError::HardFault`], or
//! [`HsmError::UnexpectedException`] — so fault output is greppable by code
//! and exception type. The `trace-uart` / `trace-semihosting` features select
//! `level-info`, which compiles `error!` in.
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

use azihsm_fw_hsm_core_tracing::error;
// `HsmError` is referenced only inside `error!`, which compiles out when no
// trace level is enabled (production); the import is then unused.
#[allow(unused_imports)]
use azihsm_fw_uno_error::HsmError;
use azihsm_fw_uno_reg_cortex_m::scb::regs::ScbRegs;
use azihsm_fw_uno_reg_cortex_m::scb::CFSR;
use azihsm_fw_uno_reg_cortex_m::scb::HFSR;
use azihsm_fw_uno_reg_cortex_m::scb::SCB_BASE;
use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;
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
/// message) through the tracing facade, then halts.
//
// `info` is consumed only by `error!`, which compiles out when no trace
// level is enabled (production builds); allow that case to stay warning-free.
#[allow(unused_variables)]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    error!("panic", HsmError::Panic, "#### PANIC ####");
    error!("panic", HsmError::Panic, "{}", info);
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
//
// The captured registers are consumed only by `error!`, which compiles out
// when no trace level is enabled (production builds); allow keeps that build
// warning-free.
#[allow(unused_variables)]
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

    error!("fault", HsmError::HardFault, "#### HardFault ####");

    if forced && (mstkerr || stkerr) {
        // Exception-entry stacking failed and escalated to HardFault: the
        // CPU could not push {R0-R3,R12,LR,PC,xPSR}, so `ef` is garbage. The
        // faulting PC/LR are unrecoverable on ARMv7-M; only MSP locates
        // where the stack was when it overran its guard region.
        error!(
            "fault",
            HsmError::HardFault,
            "cause: stack overflow (exception frame unreliable)"
        );
        error!(
            "fault",
            HsmError::HardFault,
            "MSP={:#010x} CFSR={:#010x} HFSR={:#010x}",
            msp,
            cfsr,
            hfsr
        );
    } else {
        decode::report_cfsr(scb, HsmError::HardFault);

        if scb.cfsr.is_set(CFSR::BFARVALID) {
            error!(
                "fault",
                HsmError::HardFault,
                "BFAR={:#010x}  (faulting bus address)",
                scb.bfar.get()
            );
        }
        if scb.cfsr.is_set(CFSR::MMARVALID) {
            error!(
                "fault",
                HsmError::HardFault,
                "MMFAR={:#010x} (faulting memory address)",
                scb.mmfar.get()
            );
        }

        error!(
            "fault",
            HsmError::HardFault,
            "CFSR={:#010x} HFSR={:#010x} MSP={:#010x}",
            cfsr,
            hfsr,
            msp
        );
        error!("fault", HsmError::HardFault, "frame: {:#?}", ef);

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
//
// `irqn` is consumed only by `error!`, which compiles out when no trace level
// is enabled (production builds); allow keeps that build warning-free.
#[allow(unused_variables)]
#[exception]
unsafe fn DefaultHandler(irqn: i16) -> ! {
    error!(
        "fault",
        HsmError::UnexpectedException,
        "#### Unexpected exception/IRQ: {} ####",
        irqn
    );
    halt();
}

/// Dump 32 words of raw stack memory (four per line) starting at `sp`.
///
/// Development aid behind the `fault-stackdump` feature — useful for
/// eyeballing return addresses and locals near the fault, at the cost of
/// reading memory that may extend past the live stack.
///
/// # Safety
///
/// Performs volatile reads of arbitrary stack addresses; the range may run
/// past valid RAM. Intended for debug builds on hardware only.
//
// Reads are consumed only by `error!`, which compiles out when no trace level
// is enabled; allow keeps a `fault-stackdump`-without-trace build clean.
#[cfg(feature = "fault-stackdump")]
#[allow(unused_variables)]
unsafe fn stack_dump(sp: u32) {
    const ROWS: u32 = 8;
    // `read_volatile::<u32>` requires a 4-byte-aligned pointer; `sp` may be
    // corrupted or misaligned at the fault, so align the base down first to
    // avoid undefined behaviour while keeping the dump word-oriented.
    let base = sp & !0b11;
    error!("fault", HsmError::HardFault, "stack dump @ {:#010x}:", base);
    for row in 0..ROWS {
        let addr = base.wrapping_add(row * 16);
        let p = addr as *const u32;
        let w0 = unsafe { core::ptr::read_volatile(p) };
        let w1 = unsafe { core::ptr::read_volatile(p.add(1)) };
        let w2 = unsafe { core::ptr::read_volatile(p.add(2)) };
        let w3 = unsafe { core::ptr::read_volatile(p.add(3)) };
        error!(
            "fault",
            HsmError::HardFault,
            "  {:#010x}: {:08x} {:08x} {:08x} {:08x}",
            addr,
            w0,
            w1,
            w2,
            w3
        );
    }
}
