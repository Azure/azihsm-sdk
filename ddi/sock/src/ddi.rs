// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — top-level [`Ddi`] implementation.

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;

use crate::dev::socket_path;
use crate::dev::DdiSockDev;

/// Host-side socket DDI transport.
///
/// Constructing a `DdiSock` is a no-op; the socket connection is
/// established on [`open_dev`](Ddi::open_dev).
#[derive(Default, Debug)]
pub struct DdiSock {}

impl Ddi for DdiSock {
    type Dev = DdiSockDev;

    /// Returns a single device entry whose path is the configured socket
    /// (`AZIHSM_DDI_SOCK` or [`DEFAULT_SOCK_PATH`](crate::DEFAULT_SOCK_PATH)).
    fn dev_info_list(&self) -> Vec<DevInfo> {
        vec![DevInfo {
            path: socket_path(),
            driver_ver: env!("CARGO_PKG_VERSION").to_owned(),
            firmware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            pci_info: String::from("0.0.0"),
            entropy_data: vec![0u8; 32],
        }]
    }

    /// Connect to the server at `path` and return a device handle.
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiSockDev::connect(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_info_list_reports_socket_path() {
        let ddi = DdiSock::default();
        let devs = ddi.dev_info_list();
        assert_eq!(devs.len(), 1);
        assert!(!devs[0].path.is_empty());
    }
}
