// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use azihsm_ddi_interface::*;

#[cfg(all(feature = "emu", feature = "mock"))]
compile_error!("features `emu` and `mock` are mutually exclusive; enable at most one");

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        /// Azihsm DDI emulator implementation (in-process firmware).
        pub type AzihsmDdi = azihsm_ddi_emu::DdiEmu;
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
