// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use azihsm_ddi_interface::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "sim-service")] {
        /// Azihsm DDI implementation (sim-service client over UDS)
        pub type AzihsmDdi = azihsm_ddi_sim_service_client::DdiSimService;
    } else if #[cfg(feature = "mock")] {
        /// Azihsm DDI mock implementation.
        pub type AzihsmDdi = azihsm_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        /// Azihsm DDI Linux implementation.
        pub type AzihsmDdi = azihsm_ddi_nix::DdiNix;
    } else if #[cfg(target_os = "windows")] {
        /// Azihsm DDI Windows implementation.
        pub type AzihsmDdi = azihsm_ddi_win::DdiWin;
    }
}
