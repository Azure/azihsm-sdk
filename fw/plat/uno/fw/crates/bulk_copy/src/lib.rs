// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! Fast bulk copy using ARM LDM/STM (load/store multiple) instructions.
//!
//! Copies `u32` slices using 8-register LDM/STM pairs, processing 32 bytes
//! per instruction pair vs 4 bytes for scalar LDR/STR.
//!
//! Falls back to `copy_from_slice` on non-ARM targets.

mod bulk_copy;
pub use bulk_copy::*;
