// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tracing backend and Embassy task hooks for the std PAL.
//!
//! Provides the `__hsm_trace_emit` linker symbol that the core tracing
//! facade calls, plus Embassy executor trace hooks that track the current
//! task ID in a thread-local.
//!
//! Format: `[L TIMESTAMP TARGET  :TASKID  ] message`
//!
//! - `L` — level character (`T`/`D`/`I`/`W`/`E`)
//! - `TIMESTAMP` — microseconds since process start (decimal, right-aligned)
//! - `TARGET` — module name (left-padded to 8 chars)
//! - `TASKID` — active Embassy task pointer (hex), or `--------` if idle

use std::cell::Cell;
use std::fmt;
use std::fmt::Write;
use std::sync::OnceLock;
use std::time::Instant;

/// Process start time for relative timestamps.
static START: OnceLock<Instant> = OnceLock::new();

thread_local! {
    /// Current Embassy task ID set by executor trace hooks.
    static TASK_ID: Cell<u32> = const { Cell::new(0) };
}

/// Microseconds elapsed since process start.
fn elapsed_us() -> u64 {
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_micros() as u64
}

/// Platform trace emitter — outputs via `eprintln!`.
///
/// This function is resolved at link time by the core tracing facade's
/// `extern "Rust" { fn __hsm_trace_emit(...); }` declaration.
#[no_mangle]
fn __hsm_trace_emit(level: u8, target: &str, args: fmt::Arguments<'_>) {
    let us = elapsed_us();
    let task_id = TASK_ID.get();
    let mut buf = String::with_capacity(128);
    let _ = write!(buf, "[{} {:010} {:<8}:", level as char, us, target);
    if task_id == 0 {
        let _ = write!(buf, "--------");
    } else {
        let _ = write!(buf, "{:08x}", task_id);
    }
    let _ = write!(buf, "] {}", args);
    eprintln!("{buf}");
}

// ── Embassy executor trace hooks ────────────────────────────────────

/// Called by the Embassy executor when a task begins polling.
#[no_mangle]
fn _embassy_trace_task_exec_begin(_executor_id: u32, task_id: u32) {
    TASK_ID.set(task_id);
}

/// Called by the Embassy executor when a task finishes polling.
#[no_mangle]
fn _embassy_trace_task_exec_end(_executor_id: u32, _task_id: u32) {
    TASK_ID.set(0);
}

/// Called when a new task is spawned.
#[no_mangle]
fn _embassy_trace_task_new(_executor_id: u32, _task_id: u32) {}

/// Called when a task is dropped.
#[no_mangle]
fn _embassy_trace_task_end(_executor_id: u32, _task_id: u32) {}

/// Called when a task becomes ready.
#[no_mangle]
fn _embassy_trace_task_ready_begin(_executor_id: u32, _task_id: u32) {}

/// Called when the executor starts a poll cycle.
#[no_mangle]
fn _embassy_trace_poll_start(_executor_id: u32) {}

/// Called when the executor is idle (no tasks to poll).
#[no_mangle]
fn _embassy_trace_executor_idle(_executor_id: u32) {
    TASK_ID.set(0);
}
