// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - MCR Mock Device - DDI Module

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use lazy_static::lazy_static;
use rand::Rng;

use crate::dev::DdiMockDev;

lazy_static! {
    static ref G_ENTROPY_DATA: Vec<u8> = {
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen()).collect()
    };
}

/// DDI Implementation - MCR Mock Device Interface
#[derive(Default, Debug)]
pub struct DdiMock {}

impl Ddi for DdiMock {
    type Dev = DdiMockDev;

    /// Returns the HSM device information list
    ///
    /// # Returns
    /// * `Vec<DevInfo>` - HSM device information list
    #[tracing::instrument]
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let entropy_data: Vec<u8> = (*G_ENTROPY_DATA).clone();
        let devs = vec![DevInfo {
            path: String::from("/dev/mcr-hsm-mock"),
            driver_ver: String::from("0.1.0"),
            firmware_ver: String::from("0.1.0"),
            hardware_ver: String::from("0.1.0"),
            pci_info: String::from("0.0.0"),
            entropy_data,
        }];

        // Log a success message and a list of all devices
        tracing::debug!(size = devs.len(), "Got DdiMock device info list");
        for (i, dev) in devs.iter().enumerate() {
            tracing::debug!(index = i, path = ?dev.path);
        }
        tracing::trace!(devs = ?devs);

        devs
    }

    /// Open HSM device
    ///
    /// # Arguments
    /// `path` - Device path
    ///
    /// # Returns
    /// `Self::Dev` - HSM Device
    ///
    /// # Error
    /// * `DdiError` - Error encountered while opening the device
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiMockDev::open(path)
    }
}
