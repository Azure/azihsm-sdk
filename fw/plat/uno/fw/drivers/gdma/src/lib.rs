// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the GDMA (General DMA Controller).
//!
//! One driver instance owns a single hardware channel. Queue rings and shadow
//! pointers live in DTCM and are supplied via [`ChannelConfig`]; the MMIO base
//! address comes from the generated GDMA register crate.
//!
//! # Example
//!
//! ```ignore
//! use azihsm_fw_uno_drivers_gdma::ChannelConfig;
//!
//! type Gdma = GdmaDriver<32>;
//! let gdma = static_init!(Gdma, Gdma::new(ChannelConfig {
//!     channel: 0,
//!     sq_base: 0x2003_e400,
//!     cq_base: 0x2003_ec00,
//!     cq_tail_shadow: 0x2003_ee00,
//!     sq_head_shadow: 0x2003_ee04,
//!     interrupt: true,
//! }));
//! gdma.init();
//! gdma.copy_mem(
//!     DmaBuf::Prp { prp0: DmaAddr::from_u32(0x2000_0000), prp1: DmaAddr::ZERO }, MemInterface::Device, 4096,
//!     DmaBuf::Prp { prp0: DmaAddr::from_u32(0x2000_1000), prp1: DmaAddr::ZERO }, MemInterface::Device, 4096,
//! )?.await?;
//! ```

mod api;
mod config;
mod error;
mod types;

pub use api::*;
pub use config::*;
pub use error::*;
pub use types::*;
