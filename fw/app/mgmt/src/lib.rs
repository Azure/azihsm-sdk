// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std)]

mod ctrl;

use azihsm_fw_pal_mgmt::MgmtApp;
use azihsm_fw_pal_mgmt::mgmt_plat_imports;
use embassy_executor::task;

use crate::ctrl::QueueCtrl;

mgmt_plat_imports!();

azihsm_fw_pal_mgmt::mgmt_app_impl!(
    static MGMT_APP: App = App::new();
);

pub struct App {
    ctrl: QueueCtrl,
}

impl MgmtApp for App {
    fn start(&self, spawner: embassy_executor::Spawner) {
        spawner.spawn(ctrl_task().unwrap());
        tracing::info!("MgmtApp started");
    }

    fn stop(&self) {
        tracing::info!("MgmtApp stopped");
    }

    fn on_ctrl_event(&self) {
        self.ctrl.on_ctrl_event();
    }
}

impl App {
    pub const fn new() -> Self {
        Self {
            ctrl: QueueCtrl::new(),
        }
    }
}

#[task]
async fn ctrl_task() {
    loop {
        let event = MGMT_APP.ctrl.wait_for_event().await;
        tracing::info!("Received control event: {:?}", event);
    }
}
