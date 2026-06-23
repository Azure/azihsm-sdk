// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM firmware error codes and tracing re-exports.
//!
//! Re-exports [`HsmError`] and [`HsmResult`] from `azihsm_fw_hsm_pal_traits`,
//! provides [`ComponentId`] and [`make_pal_error`] for PAL-level error
//! construction, and re-exports tracing macros.
//!
//! ## Layout
//!
//! ```text
//! 31        20 19     12 11         0
//! ┌───────────┬─────────┬────────────┐
//! │   0x08F   │component│    code    │
//! │  (12 bit) │ (8 bit) │  (12 bit)  │
//! └───────────┴─────────┴────────────┘
//! ```
//!
//! - **Facility** — `0x08F` for PAL-level errors.
//! - **Component** — 8-bit driver identifier ([`ComponentId`], 0–255).
//! - **Code** — 12-bit per-component error code (0–4095).
//!
//! # Usage
//!
//! ```ignore
//! use azihsm_fw_uno_error::{make_component_error, ComponentId, HsmError};
//!
//! pub const MY_ERROR: HsmError = make_component_error(ComponentId::GDMA, 1);
//! ```

#![no_std]

mod component;
mod error;

pub use component::ComponentId;
pub use error::make_component_error;
pub use error::make_pal_error;
pub use error::HsmError;
pub use error::HsmResult;
