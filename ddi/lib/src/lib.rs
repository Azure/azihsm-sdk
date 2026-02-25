// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use azihsm_ddi_interface::*;

macro_rules! ddi_type {
    ($backend:ty) => {
        cfg_if::cfg_if! {
            if #[cfg(feature = "resiliency")] {
                /// Azihsm DDI implementation (with resiliency fault injection).
                pub type AzihsmDdi = azihsm_ddi_resiliency::DdiResiliency<$backend>;
            } else {
                /// Azihsm DDI implementation.
                pub type AzihsmDdi = $backend;
            }
        }
    };
}

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        ddi_type!(azihsm_ddi_mock::DdiMock);
    } else if #[cfg(target_os = "linux")] {
        ddi_type!(azihsm_ddi_nix::DdiNix);
    } else if #[cfg(target_os = "windows")] {
        ddi_type!(azihsm_ddi_win::DdiWin);
    }
}
