// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! DDI Implementation - MCR Linux Device

#![cfg(target_os = "linux")]

mod ddi;
mod dev;

pub use ddi::DdiNix;
pub use dev::DdiNixDev;
