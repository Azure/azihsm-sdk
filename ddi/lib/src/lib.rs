// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use azihsm_ddi_interface::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        /// Azihsm DDI implementation
        pub type AzihsmDdi = azihsm_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        /// Azihsm DDI implementation
        pub type AzihsmDdi = azihsm_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        /// Azihsm DDI implementation
        pub type AzihsmDdi = azihsm_ddi_win::DdiWin;
    }
}
