// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Resiliency — fault-injecting wrapper around any DDI backend.
//!
//! This crate provides a DDI implementation that wraps an inner [`azihsm_ddi_interface::Ddi`]
//! and allows tests to inject transient failures (e.g., `IoAborted`,
//! `IoAbortInProgress`) into `exec_op` calls. This is used to exercise
//! the retry / resiliency code paths in the API layer.
//!

mod ddi;
mod dev;
pub mod fault;

pub use azihsm_ddi_interface::DriverError;
pub use azihsm_ddi_types::DdiOp;
pub use azihsm_ddi_types::DdiStatus;
pub use ddi::DdiResTest;
pub use dev::DdiResTestDev;
pub use fault::*;
