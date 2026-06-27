// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generic fault-time output sink.
//!
//! Emits diagnostic text from the panic and exception handlers. The sink
//! is intentionally named generically rather than after a transport: today
//! it writes to the SoC UART (a blocking, busy-poll MMIO path with no
//! interrupts, locks, or heap allocation — safe to call from a fault
//! context), but when the HSP debug-log channel is brought up this module
//! can route fault output there instead without touching any call site.
//!
//! Unlike the `error!`/`info!` trace macros — which compile to no-ops
//! unless a trace backend feature is enabled — this sink is **always**
//! compiled, so fault diagnostics appear even in production builds that
//! ship with tracing disabled.

use core::fmt::{self, Write};

use azihsm_fw_uno_drivers_uart::Uart;

/// Fault-time writer over the current diagnostic sink (UART today).
///
/// Implements [`core::fmt::Write`] so the `print_fault!` / `println_fault!`
/// macros can format directly into it without any intermediate buffer.
pub struct FaultWriter;

impl Write for FaultWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut uart = Uart::new();
        uart.write_bytes(s.as_bytes());
        Ok(())
    }
}

/// Emit formatted fault diagnostics (no trailing newline).
#[macro_export]
macro_rules! print_fault {
    ($($arg:tt)*) => {{
        let _ = ::core::fmt::Write::write_fmt(
            &mut $crate::sink::FaultWriter,
            ::core::format_args!($($arg)*),
        );
    }};
}

/// Emit formatted fault diagnostics followed by a newline.
#[macro_export]
macro_rules! println_fault {
    () => {{ $crate::print_fault!("\n"); }};
    ($($arg:tt)*) => {{
        let _ = ::core::fmt::Write::write_fmt(
            &mut $crate::sink::FaultWriter,
            ::core::format_args!($($arg)*),
        );
        $crate::print_fault!("\n");
    }};
}
