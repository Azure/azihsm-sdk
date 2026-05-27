// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! DDI Implementation - MCR Mock Device
//! This is used for development and testing purposes only. It bypasses the actual driver and device
//! but is able to simulate the same behavior for quick E2E development and testing.

mod ddi;
mod dev;
#[cfg(feature = "res-fi")]
mod fault;

pub use ddi::DdiMock;
pub use dev::DdiMockDev;

#[cfg(feature = "res-fi")]
mod fault_exports {
    pub use azihsm_ddi_interface::DriverError;
    pub use azihsm_ddi_types::DdiOp;
    pub use azihsm_ddi_types::DdiStatus;

    pub use super::fault::clear_faults;
    pub use super::fault::inject_fault;
    pub use super::fault::op_call_count;
    pub use super::fault::FaultAction;
    pub use super::fault::FaultError;
    pub use super::fault::FaultRule;
    pub use super::fault::FaultTrigger;
}

#[cfg(feature = "res-fi")]
pub use fault_exports::*;
