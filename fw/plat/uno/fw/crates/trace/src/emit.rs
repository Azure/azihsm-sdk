// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trace event emitter with a pluggable output backend.
//!
//! Formats trace events as:
//! ```text
//! [L TTTTTTTT TARGET  :TASKID  ] message
//! ```
//!
//! - `L` — level character (`T`/`D`/`I`/`W`/`E`)
//! - `TTTTTTTT` — tick count (hex, from the Embassy time driver)
//! - `TARGET` — module name (left-padded to 8 chars)
//! - `TASKID` — active task ID (hex, from the trace mailbox), or
//!   `--------` if idle
//!
//! Uses a 128-byte stack buffer with auto-flush on overflow — no heap
//! allocation. The output destination is selected at compile time by the
//! mutually-exclusive `backend-uart` / `backend-semihosting` features.
//! With neither enabled, [`write_out`] is a no-op so tracing can be
//! structurally present yet produce no output.

#[cfg(all(feature = "backend-uart", feature = "backend-semihosting"))]
compile_error!(
    "features `backend-uart` and `backend-semihosting` are mutually exclusive; \
     enable at most one trace output backend"
);

use core::fmt;
use core::fmt::Write;

const BUF_SIZE: usize = 128;

/// Flush `buf[..len]` to the selected output backend.
///
/// `buf` has spare capacity at index `len` (`len < BUF_SIZE`) so the
/// semihosting backend can NUL-terminate in place.
#[cfg(feature = "backend-uart")]
fn write_out(buf: &mut [u8; BUF_SIZE], len: usize) {
    azihsm_fw_uno_drivers_uart::Uart::new().write_bytes(&buf[..len]);
}

#[cfg(all(feature = "backend-semihosting", not(feature = "backend-uart")))]
fn write_out(buf: &mut [u8; BUF_SIZE], len: usize) {
    buf[len] = 0; // NUL-terminate for SYS_WRITE0
    azihsm_fw_uno_drivers_semihosting::sys_write0(&buf[..=len]);
}

#[cfg(not(any(feature = "backend-uart", feature = "backend-semihosting")))]
fn write_out(_buf: &mut [u8; BUF_SIZE], _len: usize) {
    // No backend selected — output disabled.
}

/// Stack-buffered writer that auto-flushes to the backend when full.
struct FlushWriter {
    buf: [u8; BUF_SIZE],
    pos: usize,
}

impl FlushWriter {
    fn new() -> Self {
        Self {
            buf: [0u8; BUF_SIZE],
            pos: 0,
        }
    }

    fn flush(&mut self) {
        if self.pos > 0 {
            write_out(&mut self.buf, self.pos);
            self.pos = 0;
        }
    }
}

impl Write for FlushWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.buf[self.pos] = b;
            self.pos += 1;
            // Leave index `pos` free so the semihosting backend can
            // NUL-terminate without overflowing the buffer.
            if self.pos >= BUF_SIZE - 1 {
                self.flush();
            }
        }
        Ok(())
    }
}

impl Drop for FlushWriter {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Read the current tick count via embassy-time.
fn read_tick() -> u64 {
    embassy_time::Instant::now().as_ticks()
}

/// Read the current task ID from the profile driver, which selects the
/// correct source (TraceMailbox on the emulator, portable atomic on
/// silicon) based on the active trace backend.
fn read_task_id() -> u32 {
    azihsm_fw_uno_drivers_profile::current_task_id()
}

/// Emit a formatted trace event to the selected backend.
///
/// Called by the `azihsm_fw_hsm_core_tracing` facade macros via the
/// `__hsm_trace_emit` extern symbol.
///
/// # Arguments
///
/// * `level` — single-character level: `b'T'`, `b'D'`, `b'I'`, `b'W'`, `b'E'`
/// * `target` — short target name, e.g. `"iic"`, `"oic"`, `"core"`
/// * `args` — pre-built format arguments from `format_args!()`
#[cold]
#[inline(never)]
pub fn emit(level: u8, target: &str, args: fmt::Arguments<'_>) {
    let tick = read_tick();
    let task_id = read_task_id();

    let mut w = FlushWriter::new();

    // Format: [L TTTTTTTT TARGET  :TASKID  ]
    let _ = write!(w, "[{} {:08x} {:<8}:", level as char, tick, target);
    if task_id == 0 {
        let _ = write!(w, "--------");
    } else {
        let _ = write!(w, "{:08x}", task_id);
    }
    let _ = write!(w, "] ");
    let _ = write!(w, "{}", args);
    let _ = writeln!(w);
    // FlushWriter::drop() auto-flushes remaining bytes.
}

/// The `__hsm_trace_emit` linker symbol required by
/// `azihsm_fw_hsm_core_tracing`'s `extern "Rust"` declaration.
///
/// Delegates to [`emit`].
#[cold]
#[inline(never)]
#[no_mangle]
fn __hsm_trace_emit(level: u8, target: &str, args: fmt::Arguments<'_>) {
    emit(level, target, args);
}
