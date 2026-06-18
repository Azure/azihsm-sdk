// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Synchronous UART driver for the Uno firmware.
//!
//! Provides blocking byte I/O over the SoC UART peripheral at
//! `0xB000_9000` using tock-register MMIO. Intended as a trace/console
//! backend on real silicon — the emulator does not model this
//! peripheral.
//!
//! # Usage
//!
//! ```ignore
//! use azihsm_fw_uno_drivers_uart::Uart;
//! use core::fmt::Write;
//!
//! let mut uart = Uart::new();
//! uart.write_str("Hello, HSM!\n").unwrap();
//! ```

#![no_std]

mod api;

pub use api::*;
