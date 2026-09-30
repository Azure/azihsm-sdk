// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Device Driver Interface (DDI) library

pub use azihsm_ddi_interface::*;

#[cfg(all(feature = "emu", feature = "mock"))]
compile_error!("features `emu` and `mock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "emu", feature = "sock"))]
compile_error!("features `emu` and `sock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "mock", feature = "sock"))]
compile_error!("features `mock` and `sock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "sock", not(unix)))]
compile_error!("feature `sock` requires a Unix target (azihsm_ddi_sock uses Unix-domain sockets)");

#[cfg(all(feature = "emu", feature = "vsock"))]
compile_error!("features `emu` and `vsock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "mock", feature = "vsock"))]
compile_error!("features `mock` and `vsock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "sock", feature = "vsock"))]
compile_error!("features `sock` and `vsock` are mutually exclusive; enable at most one");

#[cfg(all(feature = "vsock", not(target_os = "linux")))]
compile_error!(
    "feature `vsock` requires Linux (azihsm_ddi_vsock uses AF_VSOCK, which is Linux-only)"
);

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        /// Azihsm DDI emulator implementation (in-process firmware).
        pub type AzihsmDdi = azihsm_ddi_emu::DdiEmu;
    } else if #[cfg(all(feature = "sock", unix))] {
        /// Azihsm DDI socket implementation (firmware behind a socket server).
        pub type AzihsmDdi = azihsm_ddi_sock::DdiSock;
    } else if #[cfg(all(feature = "vsock", target_os = "linux"))] {
        /// Azihsm DDI vsock implementation (firmware behind an AF_VSOCK server).
        pub type AzihsmDdi = azihsm_ddi_vsock::DdiVsock;
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
