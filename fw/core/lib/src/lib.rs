// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM core — generic application logic over a platform abstraction layer.
//!
//! This crate is a pure async library with no executor dependency.
//! The concrete PAL type and Embassy task wiring are provided by the
//! platform crate (e.g. `fw/plat/std/lib`).

#![cfg_attr(not(feature = "std"), no_std)]

mod ddi;
mod error;
mod hsm;
mod io;
mod op;
mod session;

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;
pub(crate) use error::*;
pub use hsm::Hsm;
pub(crate) use op::*;
