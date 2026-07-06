// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! Socket-based DDI transport (host-side client).
//!
//! Implements the [`Ddi`](azihsm_ddi_interface::Ddi) trait stack by
//! tunnelling DDI requests over a Unix domain socket to an emulator-side
//! server (e.g. the Uno SoC emulator's DDI server), which bridges them to
//! the real firmware. It mirrors [`azihsm_ddi_emu`] but, instead of
//! running the firmware in-process, encodes each request to MBOR/TBOR
//! bytes and exchanges them with the server using
//! [`azihsm_ddi_sock_proto`].
//!
//! The transport is selected by the device path passed to
//! [`Ddi::open_dev`](azihsm_ddi_interface::Ddi::open_dev): the path is the
//! socket to connect to. [`Ddi::dev_info_list`] reports a single device
//! whose path comes from the `AZIHSM_DDI_SOCK` environment variable,
//! falling back to [`DEFAULT_SOCK_PATH`].

// Uses Unix-domain sockets, so the crate is empty on non-Unix targets.
#![cfg(unix)]

mod ddi;
mod dev;

pub use ddi::DdiSock;
pub use dev::DdiSockDev;
pub use dev::DEFAULT_SOCK_PATH;
pub use dev::SOCK_PATH_ENV;
