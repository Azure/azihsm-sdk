// Copyright (C) Microsoft Corporation. All rights reserved.

mod queue_ctrl;

use azihsm_fw_pal_mgmt::*;
use embassy_executor::Spawner;
use queue_ctrl::*;

azihsm_fw_pal_mgmt::mgmt_app_imports!();

mgmt_plat_impl!(
    pub static PLAT: StdPlat = StdPlat::new();
);

pub struct StdPlat {
    ctrl: QueueController,
}

impl MgmtPlat for StdPlat {
    fn poll_ctrl_event(&self) -> Option<MgmtQueueCtrlEvent> {
        self.ctrl.poll_ctrl_event()
    }

    fn enable_ctrl(&self, ctrl_id: MgmtCtrlId) {
        self.ctrl.enable_ctrl(ctrl_id);
    }

    fn disable_ctrl(&self, ctrl_id: MgmtCtrlId) {
        self.ctrl.disable_ctrl(ctrl_id);
    }
}

impl StdPlat {
    const fn new() -> Self {
        Self {
            ctrl: QueueController::new(),
        }
    }

    pub fn on_enable_ctrl(&self, ctrl_id: u16) {
        self.ctrl.on_enable_ctrl(ctrl_id);
    }

    pub fn on_disable_ctrl(&self, ctrl_id: u16) {
        self.ctrl.on_disable_ctrl(ctrl_id);
    }

    pub fn ctrl_ready(&self, ctrl_id: MgmtCtrlId) -> bool {
        self.ctrl.ctrl_ready(ctrl_id)
    }
}

#[embassy_executor::task]
pub async fn start(spawner: Spawner) {
    mgmt_app_start(spawner);

    let mut count = 0;
    loop {
        tracing::info!("Mgmt thread tick {count}");
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
        count += 1;
    }
}

// Events
// - Reset (reason)
// - Reset Controller (ctrl_id)
// - Enable Controller (ctrl_id)
// - Disable Controller (ctrl_id)
