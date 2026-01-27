// Copyright (C) Microsoft Corporation. All rights reserved.

// use std::sync::*;

// pub static MGMT_EMULATOR: LazyLock<MgmtEmulator> = LazyLock::new(|| MgmtEmulator::default());

// pub struct MgmtEmulator {
//     inner: Arc<RwLock<Inner>>,
// }

// impl Default for MgmtEmulator {
//     fn default() -> Self {
//         Self {
//             inner: Arc::new(RwLock::new(Inner::default())),
//         }
//     }
// }

// struct Inner {}

// impl Default for Inner {
//     fn default() -> Self {
//         Self {}
//     }
// }

use embassy_executor::Spawner;

azihsm_fw_pal_mgmt::mgmt_app_imports!();

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

pub fn stop() {
    mgmt_app_stop();
}
