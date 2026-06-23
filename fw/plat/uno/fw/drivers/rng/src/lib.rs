// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
//! Synchronous firmware driver for the RNG peripheral.
//!
//! The RNG produces 32 bits of random data per request. Firmware sets
//! `CTRL.ENABLE`, polls `STATUS.BUSY` until clear, then reads `RN_DATA`.
//! No IRQ, no async — a pure polling interface.
//!
//! # Example
//!
//! ```ignore
//! use azihsm_fw_hsm_pal_traits::DmaBuf;
//!
//! let rng = RngDriver::init();
//! let mut buf = [0u8; 32];
//! let dma = unsafe { DmaBuf::from_raw_mut(&mut buf) };
//! rng.fill_bytes(dma).unwrap();
//! ```

mod api;

pub use api::*;
