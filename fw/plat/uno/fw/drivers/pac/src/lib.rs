// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Uno SoC Peripheral Access Crate (PAC).
//!
//! Minimal PAC providing interrupt definitions for the Uno SoC.
//! Used with `cortex-m-rt`'s `#[interrupt]` attribute.
#![no_std]

mod pac;
pub use pac::*;
