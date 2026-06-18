// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the IIC (Inbound IO Controller).
//!
//! One driver instance per (controller, channel) pair. The controller
//! is resolved to an MMIO base address at init. The channel index
//! selects the ISQ and ICQ register arrays.
//!
//! # Architecture
//!
//! ```text
//! controller[0] @ 0xA128_0000
//!   ├── isq.channel[6]  — FW posts buffer addresses
//!   ├── icq.channel[5]  — HW posts completions
//!   └── iq.queue[132]   — per-queue credit counters
//! controller[1] @ 0xA128_4000
//!   └── (same layout)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use azihsm_fw_uno_drivers_iic::*;
//!
//! let iic = IicDriver::<32>::new(ChannelConfig {
//!     channel: 0,
//!     isq_base: 0x6109_0000,
//!     io_pool_base: 0x6108_0000,
//!     io_size: 64,
//!     icq_base: 0x6109_0100,
//!     icq_tail_shadow: 0x6109_0300,
//!     io_meta_base: 0x6109_0C00,
//!     interrupt: true,
//! });
//! iic.init();
//! iic.enable();
//! let slot = iic.recv().await;
//! iic.free_io(slot, queue_id);
//! ```

mod api;
mod config;
mod entry;
mod error;

pub use api::*;
pub use config::*;
pub use entry::*;
pub use error::IicError;
