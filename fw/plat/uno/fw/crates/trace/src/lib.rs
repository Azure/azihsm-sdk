// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM firmware tracing.
//!
//! Re-exports the level-gated tracing macros (`trace!`, `debug!`, `info!`,
//! `warn!`, `error!`) from `azihsm_fw_hsm_core_tracing`.
//!
//! When the `tracing` feature is enabled, this crate also provides the
//! `__hsm_trace_emit` implementation that formats trace events with tick
//! count and task ID. The output destination is selected by the
//! mutually-exclusive `backend-uart` / `backend-semihosting` features;
//! with neither enabled the emitter compiles to a no-op (output disabled).
//!
//! # Usage
//!
//! ```ignore
//! use azihsm_fw_uno_trace::tracing::*;
//!
//! info!("iic", "initialized depth={}", depth);
//! debug!("gdma", "submit tag={} slot={}", tag, slot);
//! error!("core", err, "operation failed");
//! ```

#![no_std]

#[cfg(feature = "tracing")]
mod emit;

pub extern crate azihsm_fw_hsm_core_tracing as tracing;
