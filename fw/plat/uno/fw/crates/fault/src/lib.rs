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
//! HardFault and Panic are full crash-recovery participants: besides
//! reporting the fault, they capture a persistent crash dump (into the
//! reserved HSM DTCM slot via [`azihsm_fw_uno_crashdump`]) and notify the
//! peer core over TCON wakeup1. This crate also installs the **`tcon_wakeup1`
//! receiver** — a real NVIC-vectored assembly trampoline (`drivers/pac`
//! `__INTERRUPTS[89]`) that captures *this* core's dump when a peer core
//! signals a crash. The remaining exception handlers (`MemManagement` and the
//! peripheral-error ISRs present in the mcr-hsm `exception-handlers` crate)
//! are wired in later units of the crash-recovery port.

#![no_std]
#![allow(unsafe_code)]

mod decode;

use core::arch::global_asm;

use azihsm_fw_hsm_core_tracing::error;
use azihsm_fw_uno_crashdump::crash_format::CpuRegisterContext;
use azihsm_fw_uno_crashdump::crashdump_save;
use azihsm_fw_uno_crashdump::crashdump_save_fmt;
use azihsm_fw_uno_crashdump::failure_code::FailureCode;
use azihsm_fw_uno_drivers_nvic::Nvic;
use azihsm_fw_uno_drivers_tcon::Tcon;
// `HsmError` is referenced only inside `error!`, which compiles out when no
// trace level is enabled (production); the import is then unused.
#[allow(unused_imports)]
use azihsm_fw_uno_error::HsmError;
use azihsm_fw_uno_pac::Interrupt;
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
/// Reports the panic through the tracing facade, notifies the peer core of
/// the crash over TCON wakeup1, and captures a persistent crash dump before
/// halting.
///
/// The crash-dump register-context fields are overloaded to carry the panic
/// site to the shared SP parser, exactly as the reference `mcr-hsm` handler
/// does: `lr` = pointer to the file name, `pc` = line number, and `sp` =
/// pointer to the message (only when the message is a plain `&str`). All are
/// offsets within the CP `.text` image.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // Disable our own wakeup1 receiver before firing it at the peer core, so
    // the notification we are about to raise cannot recurse back into this
    // already-crashing core.
    Nvic::disable(Interrupt::TCON_WAKEUP1);

    error!("panic", HsmError::Panic, "#### PANIC ####");
    error!("panic", HsmError::Panic, "{}", info);

    // Notify the peer core of the crash.
    Tcon::fire_wakeup_timer1();

    // Overload the register context to describe the panic site (see fn docs).
    let mut context = CpuRegisterContext::default();
    if let Some(location) = info.location() {
        context.lr = location.file().as_ptr() as u32;
        context.pc = location.line();
    }
    if let Some(message) = info.message().as_str() {
        context.sp = message.as_ptr() as u32;
    }

    // Capture the panic text directly into the reserved crash-dump tail.
    // `crashdump_save_fmt` renders `format_args!` through a bounded sink (no
    // allocator — uno is pure `no_std`), so both literal *and formatted*
    // panics are recorded, truncated to the region's tail capacity. The
    // file/line/message pointers packed into the register context above remain
    // as a complement. (Divergence from reference decision #5, which appended
    // `info.message().to_string()` via the reference's heap allocator that uno
    // lacks.)
    crashdump_save_fmt(&context, FailureCode::Panic, format_args!("{info}"));

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
/// After reporting, it notifies the peer core over TCON wakeup1 and captures
/// a persistent crash dump (mirroring the reference `mcr-hsm` handler) before
/// halting.
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

    // ---- Crash capture + cross-core notify -------------------------------
    // Mirrors the reference `mcr-hsm` `exception_handlers::HardFault`.
    // Classification uses the reference's FORCED+MSTKERR predicate so the
    // shared SP parser records the same `failure_code`; note the diagnostic
    // logging above intentionally treats the broader FORCED+(MSTKERR|STKERR)
    // as an unreliable-frame overflow for operator visibility.
    let failure_code = if forced && mstkerr {
        FailureCode::MemoryFault
    } else {
        FailureCode::HardFault
    };

    // Disable our own wakeup1 receiver before firing it at the peer core, so
    // the notification cannot recurse back into this already-crashing core.
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    Tcon::fire_wakeup_timer1();

    let context = if forced && mstkerr {
        // Exception stacking hit the MPU guard: the pushed frame is garbage,
        // so record MSP (the approximate stack location at fault) instead.
        CpuRegisterContext {
            sp: msp,
            ..Default::default()
        }
    } else {
        // The `sp` inside the frame is post-stacking; the real SP at the fault
        // is the frame address plus the frame size. uno targets soft-float
        // (`thumbv7em-none-eabi`, FPU disabled), so the hardware always pushes
        // the basic 32-byte frame — `ef + size_of::<ExceptionFrame>()` is exact.
        let mut ctx = CpuRegisterContext::from_exception_frame(ef);
        ctx.sp = ef as *const _ as u32 + core::mem::size_of::<ExceptionFrame>() as u32;
        ctx
    };
    crashdump_save(&context, failure_code, None);

    halt();
}

// tcon wakeup1 receiver ISR.
//
// This is the cross-core crash *receiver*: a peer core that faults arms TCON
// wakeup1 (see the `fire_wakeup_timer1` calls in the panic / HardFault
// handlers above), which raises IRQ89 on this core. The vector has to preempt
// a core that may be spinning or halted, so it is a real NVIC-vectored entry
// (`drivers/pac` `__INTERRUPTS[89]`) rather than a cooperatively-polled
// `WAKE_TABLE` driver.
//
// Implemented as an assembly trampoline (mirroring the reference `mcr-hsm`
// `tcon_wakeup1_irq`) so it can capture the *interrupted* code's stack frame:
// EXC_RETURN bit 2 selects which stack (MSP/PSP) was active at preemption, and
// that stack pointer — the base of the hardware-stacked exception frame — is
// passed to `collect_crash_dump_tcon_irq` in `r0`.
global_asm!(
    ".global TCON_WAKEUP1
     .type TCON_WAKEUP1,%function
     .thumb_func
     .cfi_startproc
     TCON_WAKEUP1:",
    "mov r0, lr
     movs r1, #4
     tst r0, r1
     bne 0f
     mrs r0, MSP
     b collect_crash_dump_tcon_irq
     0:
     mrs r0, PSP
     b collect_crash_dump_tcon_irq",
    ".cfi_endproc
     .size TCON_WAKEUP1, . - TCON_WAKEUP1",
);

/// Collect a crash dump on receipt of a peer core's TCON wakeup1
/// notification, then halt.
///
/// Tail-called from the `TCON_WAKEUP1` assembly trampoline with `ef` pointing
/// at the exception frame stacked on whichever stack (MSP/PSP) was active when
/// the notification preempted this core. Disarms the wakeup timer and the IRQ
/// (so the notification cannot re-fire), records the interrupted context under
/// [`FailureCode::OtherCore`], and halts.
///
/// # ABI
///
/// `#[no_mangle]` + AAPCS: the single `&ExceptionFrame` argument arrives in
/// `r0`, matching the `b collect_crash_dump_tcon_irq` tail-call from the
/// trampoline. Must never be called from Rust directly.
#[allow(dead_code)]
#[no_mangle]
fn collect_crash_dump_tcon_irq(ef: &ExceptionFrame) -> ! {
    // Disarm the wakeup timer and our own IRQ line so the peer's notification
    // cannot re-fire while (or after) we capture the dump.
    Tcon::disable_wakeup_timer1();
    Nvic::disable(Interrupt::TCON_WAKEUP1);
    Nvic::unpend(Interrupt::TCON_WAKEUP1);

    // The `sp` inside the stacked frame is post-stacking; the real SP at
    // preemption is the frame address plus the frame size. uno targets
    // soft-float (`thumbv7em-none-eabi`, FPU disabled), so the hardware always
    // pushes the basic 32-byte frame — `ef + size_of::<ExceptionFrame>()` is
    // exact.
    let mut context = CpuRegisterContext::from_exception_frame(ef);
    context.sp = ef as *const _ as u32 + core::mem::size_of::<ExceptionFrame>() as u32;
    crashdump_save(&context, FailureCode::OtherCore, None);

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
