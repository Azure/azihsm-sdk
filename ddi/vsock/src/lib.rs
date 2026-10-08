// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]

//! AF_VSOCK-based DDI transport (guest-side server).
//!
//! Implements the [`Ddi`](azihsm_ddi_interface::Ddi) trait stack by
//! listening for real AF_VSOCK connections from the host (e.g. `vsocksrv`
//! dialing into cloud-hypervisor's standard virtio-vsock device) and
//! tunnelling DDI requests over the accepted stream, using the same
//! [`azihsm_ddi_sock_proto`] wire protocol as [`azihsm_ddi_sock`]. Unlike
//! that crate's `DdiSockDev`, which dials *out* to a Unix-domain-socket
//! server, `DdiVsockDev` dials *in*: it binds and listens on an AF_VSOCK
//! port and accepts a connection from the host on
//! [`Ddi::open_dev`](azihsm_ddi_interface::Ddi::open_dev).
//!
//! The port is configured via the [`VSOCK_PORT_ENV`] environment
//! variable, falling back to [`DEFAULT_VSOCK_PORT`].

// AF_VSOCK is Linux-only, so the crate is empty elsewhere.
#![cfg(target_os = "linux")]

mod ddi;
mod dev;

pub use ddi::DdiVsock;
pub use dev::DdiVsockDev;
pub use dev::DEFAULT_VSOCK_PORT;
pub use dev::VSOCK_PORT_ENV;
