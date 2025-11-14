// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! DDI Implementation - MCR Mock Device
//! This is used for development and testing purposes only. It bypasses the actual driver and device
//! but is able to simulate the same behavior for quick E2E development and testing.

mod ddi;
mod dev;

pub use ddi::DdiMock;
pub use dev::DdiMockDev;
