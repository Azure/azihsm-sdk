// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(clippy::new_without_default)]
//! Async firmware driver for the OIC (Outbound IO Controller).
//!
//! Index-based design: [`send`](OicDriver::send) takes an IO
//! index (`u16`). The driver reads the IO CQ entry address and
//! work metadata from DTCM pointers provided via [`ChannelConfig`].
//!
//! Queue rings (OSQ, OCQ) and sidecar arrays (IO_CQ, IO_META)
//! are placed at addresses in upper DTCM defined by `io_bufs.rdl`
//! and passed to the driver at init time.
//!
//! # Example
//!
//! ```ignore
//! type Oic = OicDriver<32>;
//! let oic = static_init!(Oic, Oic::new(ChannelConfig {
//!     channel: 0,
//!     osq_base: 0x2003_DD00,
//!     ocq_base: 0x2003_DF00,
//!     ocq_tail_shadow: 0x2003_E300,
//!     io_cq_base: 0x2003_E100,
//!     io_meta_base: 0x2003_DC00,
//!     interrupt: true,
//! }));
//! oic.init();
//! oic.enable();
//! oic.send(index)?.await?;
//! ```

mod api;
mod config;
mod error;
pub use api::*;
pub use config::*;
pub use error::*;
