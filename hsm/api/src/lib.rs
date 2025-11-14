// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Azure Integrated HSM API
//!
//! This crate implements the Azure Integrated HSM API for Rust & C/C++.

mod bindings;
mod crypto;
mod ddi;
mod partition;
mod session;
mod types;

pub use bindings::*;
pub(crate) use mcr_ddi::*;
use mcr_ddi_types::*;
pub use partition::*;
pub use session::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        type HsmDdi = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        type HsmDdi = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        type HsmDdi = mcr_ddi_win::DdiWin;
    }
}

lazy_static::lazy_static! {
    pub(crate) static ref DDI: HsmDdi = HsmDdi::default();
}
