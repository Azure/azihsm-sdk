// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Resiliency Mock — fault-injecting wrapper around the standard mock.
//!
//! This crate provides a DDI implementation that wraps [`azihsm_ddi_mock`]
//! and allows tests to inject transient failures (e.g., `IoAborted`,
//! `IoAbortInProgress`) into `exec_op` calls. This is used to exercise
//! the retry / resiliency code paths in the API layer.
//!

mod ddi;
mod dev;
pub mod fault;

pub use azihsm_ddi_interface::DriverError;
pub use azihsm_ddi_types::DdiOp;
pub use ddi::DdiResiliencyMock;
pub use dev::DdiResiliencyMockDev;
pub use fault::clear_faults;
pub use fault::inject_fault;
pub use fault::op_call_count;
pub use fault::FaultRule;
pub use fault::FaultTrigger;
