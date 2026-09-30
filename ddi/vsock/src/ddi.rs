// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Vsock DDI transport — top-level [`Ddi`] implementation.

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;

use crate::dev::vsock_port;
use crate::dev::DdiVsockDev;

/// Guest-side vsock DDI transport.
///
/// Constructing a `DdiVsock` is a no-op; the listening socket is bound
/// lazily and a connection accepted on
/// [`open_dev`](Ddi::open_dev).
#[derive(Default, Debug)]
pub struct DdiVsock {}

impl Ddi for DdiVsock {
    type Dev = DdiVsockDev;

    /// Returns a single device entry whose path is the configured AF_VSOCK
    /// port (`AZIHSM_DDI_VSOCK_PORT` or
    /// [`DEFAULT_VSOCK_PORT`](crate::DEFAULT_VSOCK_PORT)), stringified.
    fn dev_info_list(&self) -> Vec<DevInfo> {
        vec![DevInfo {
            path: vsock_port().to_string(),
            driver_ver: env!("CARGO_PKG_VERSION").to_owned(),
            firmware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            pci_info: String::from("0.0.0"),
            entropy_data: vec![0u8; 32],
        }]
    }

    /// Accept a connection on the port named by `path` (falling back to
    /// the configured port if `path` doesn't parse as one) and return a
    /// device handle.
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let port = path.parse().unwrap_or_else(|_| vsock_port());
        DdiVsockDev::accept(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_info_list_reports_vsock_port() {
        let ddi = DdiVsock::default();
        let devs = ddi.dev_info_list();
        assert_eq!(devs.len(), 1);
        assert!(!devs[0].path.is_empty());
    }
}
