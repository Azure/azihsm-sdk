// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - Simulator Service Client - DDI Module

use azihsm_ddi_interface::*;

use std::sync::LazyLock;

use crate::dev::DdiSimServiceDev;

static G_ENTROPY_DATA: LazyLock<Vec<u8>> = LazyLock::new(|| {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32).map(|_| rng.gen()).collect()
});

/// DDI Implementation - Simulator Service Client Interface
#[derive(Default, Debug)]
pub struct DdiSimService {}

impl Ddi for DdiSimService {
    type Dev = DdiSimServiceDev;

    /// Returns the HSM device information list.
    ///
    /// Reports a single virtual device at the path `sim-service:<socket_path>`.
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let socket_path = DdiSimServiceDev::socket_path();
        let entropy_data: Vec<u8> = (*G_ENTROPY_DATA).clone();
        let devs = vec![DevInfo {
            path: format!("sim-service:{socket_path}"),
            driver_ver: String::from("0.1.0"),
            firmware_ver: String::from("0.1.0"),
            hardware_ver: String::from("0.1.0"),
            pci_info: String::from("0.0.0"),
            entropy_data,
        }];

        tracing::debug!(size = devs.len(), "Got DdiSimService device info list");
        devs
    }

    /// Open HSM device.
    ///
    /// Accepts paths of the form `sim-service:` (uses default/env socket path)
    /// or `sim-service:/path/to/socket`.
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiSimServiceDev::open(path)
    }
}
