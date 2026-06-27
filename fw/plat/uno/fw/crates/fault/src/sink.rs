// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generic fault-time output sink.
//!
//! Emits diagnostic text from the panic and exception handlers. The sink
//! is intentionally named generically rather than after a transport. On
//! silicon it writes to the SoC UART (a blocking, busy-poll MMIO path with
//! no interrupts, locks, or heap allocation — safe to call from a fault
//! context); on the emulator (`semihosting` builds, which do not model the
//! UART) it routes through semihosting `SYS_WRITE0`. When the HSP debug-log
//! channel is brought up this module can route there instead without
//! touching any call site.
//!
//! Unlike the `error!`/`info!` trace macros — which compile to no-ops
//! unless a trace backend feature is enabled — this sink is **always**
//! compiled, so fault diagnostics appear even in production builds that
//! ship with tracing disabled.

use core::fmt::Write;
use core::fmt::{self};

#[cfg(not(feature = "semihosting"))]
use azihsm_fw_uno_drivers_uart::Uart;

/// Fault-time writer over the current diagnostic sink: the SoC UART on
/// silicon, or semihosting `SYS_WRITE0` on the emulator (`semihosting`).
///
/// Implements [`core::fmt::Write`] so the `print_fault!` / `println_fault!`
/// macros can format directly into it without any intermediate buffer.
pub struct FaultWriter;

impl Write for FaultWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // The emulator does not model the SoC UART, where `write_byte` would
        // spin forever on STATUS.TX_READY (or fault on unmapped MMIO) and
        // stall the report before `SYS_EXIT`. So `semihosting` builds route
        // through semihosting `SYS_WRITE0`, mirroring the trace backend;
        // silicon builds write the UART directly.
        #[cfg(feature = "semihosting")]
        {
            // SYS_WRITE0 needs a NUL-terminated buffer; copy into a small
            // stack buffer in chunks (64 bytes + NUL terminator).
            for chunk in s.as_bytes().chunks(64) {
                let mut buf = [0u8; 65];
                let n = chunk.len();
                buf[..n].copy_from_slice(chunk);
                buf[n] = 0;
                azihsm_fw_uno_drivers_semihosting::sys_write0(&buf[..=n]);
            }
        }
        #[cfg(not(feature = "semihosting"))]
        {
            let mut uart = Uart::new();
            uart.write_bytes(s.as_bytes());
        }
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
