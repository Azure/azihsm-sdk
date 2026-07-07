// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Mailbox helpers for firmware profiling.
//!
//! Gated behind the `trace` feature (on by default). When disabled,
//! all functions compile to nothing — zero instructions per IO.
//!
//! Independently of the emulator-only mailbox profiling, this module also
//! tracks the currently executing task. The embassy trace hooks keep both
//! a portable in-memory atomic and the TraceMailbox up to date;
//! [`current_task_id`] returns whichever source matches the active trace
//! backend (mailbox for `backend-semihosting` on the emulator, atomic for
//! `backend-uart` on silicon).

#[cfg(feature = "trace")]
use azihsm_fw_static_ref::StaticRef;
#[cfg(feature = "trace")]
use azihsm_fw_uno_reg_soc::trace_mailbox::regs::TraceMailboxRegs;
#[cfg(feature = "trace")]
use azihsm_fw_uno_reg_soc::trace_mailbox::TRACE_MAILBOX_BASE;
use portable_atomic::AtomicU32;
use portable_atomic::Ordering;
#[cfg(feature = "trace")]
use tock_registers::interfaces::Readable;
#[cfg(feature = "trace")]
use tock_registers::interfaces::Writeable;

#[cfg(feature = "trace")]
const TRACE: StaticRef<TraceMailboxRegs> =
    unsafe { StaticRef::new(TRACE_MAILBOX_BASE as *const TraceMailboxRegs) };

/// Portable record of the currently executing Embassy task ID.
///
/// Updated unconditionally by the embassy trace hooks (regardless of the
/// `trace` feature or target), so it is valid on both the emulator and
/// real silicon. `0` means the executor is idle.
static CURRENT_TASK_ID: AtomicU32 = AtomicU32::new(0);

/// Returns the ID of the currently executing Embassy task, or `0` when
/// the executor is idle.
///
/// The source depends on the selected trace output backend:
///
/// - `backend-semihosting` (emulator): reads word 0 of the TraceMailbox
///   MMIO, which the emulator keeps in sync for per-task profiling.
/// - otherwise (e.g. `backend-uart` on silicon, where no TraceMailbox
///   exists): reads the portable in-memory atomic maintained by the
///   embassy trace hooks.
#[cfg(feature = "backend-semihosting")]
#[inline]
pub fn current_task_id() -> u32 {
    // Word 0 of the TraceMailbox holds the active task ID.
    unsafe {
        core::ptr::read_volatile(
            azihsm_fw_uno_reg_soc::trace_mailbox::TRACE_MAILBOX_BASE as *const u32,
        )
    }
}

/// Returns the ID of the currently executing Embassy task, or `0` when
/// the executor is idle. See the `backend-semihosting` variant for the
/// task-ID source rationale.
#[cfg(not(feature = "backend-semihosting"))]
#[inline]
pub fn current_task_id() -> u32 {
    CURRENT_TASK_ID.load(Ordering::Relaxed)
}

/// Records the currently executing Embassy task ID.
#[inline]
pub(crate) fn set_current_task_id(id: u32) {
    CURRENT_TASK_ID.store(id, Ordering::Relaxed);
}

/// Record a task execution begin event.
#[cfg(feature = "trace")]
#[inline(never)]
pub fn task_begin(task_id: u32) {
    let r = TRACE;
    r.task_id.set(task_id);
    r.event.set(1);
    r.last_begin_task.set(task_id);
    let n = r.begin_count.get();
    r.begin_count.set(n + 1);
}

/// Record a task execution begin event.
#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn task_begin(_task_id: u32) {}

/// Record a task execution end event.
#[cfg(feature = "trace")]
#[inline(never)]
pub fn task_end() {
    let r = TRACE;
    r.task_id.set(0);
    r.event.set(2);
}

/// Record a task execution end event.
#[cfg(not(feature = "trace"))]
#[inline(always)]
pub fn task_end() {}

/// Record a task created event.
#[inline(always)]
pub fn task_new() {
    #[cfg(feature = "trace")]
    TRACE.event.set(3);
}

/// Record a task completed event.
#[inline(always)]
pub fn task_complete() {
    #[cfg(feature = "trace")]
    TRACE.event.set(4);
}

/// Clear the active task (executor idle).
#[inline(always)]
pub fn idle() {
    #[cfg(feature = "trace")]
    TRACE.task_id.set(0);
}
