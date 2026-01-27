// Copyright (C) Microsoft Corporation. All rights reserved.

use embassy_executor::Spawner;

#[embassy_executor::task]
pub async fn run(_spwaner: Spawner) {
    let mut count = 0;
    loop {
        tracing::info!("Hsm thread tick {count}");
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
        count += 1;
    }
}
