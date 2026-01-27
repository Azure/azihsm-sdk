// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std)]

use azihsm_fw_pal_mgmt::MgmtApp;

pub struct App;

impl MgmtApp for App {
    fn start(&self, _spawner: embassy_executor::Spawner) {
        tracing::info!("MgmtApp started");
    }

    fn stop(&self) {
        tracing::info!("MgmtApp stopped");
    }
}

azihsm_fw_pal_mgmt::mgmt_app_impl!(
    static MGMT_APP: App = App {};
);
