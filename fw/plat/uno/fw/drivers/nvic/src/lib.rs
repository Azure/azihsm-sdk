// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
#![allow(clippy::new_without_default)]
//!
//! Provides a safe, typed API over raw NVIC register operations.
//! All methods take [`Interrupt`] enum values — no raw IRQ numbers.
//!
//! ```ignore
//! use azihsm_fw_uno_pac::interrupt::Interrupt;
//!
//! Nvic::enable(Interrupt::IIC_ICQ);
//! if Nvic::is_pending(Interrupt::IIC_ICQ) { ... }
//! ```

mod nvic;
pub use nvic::*;
