// Copyright (C) Microsoft Corporation. All rights reserved.

//! Management firmware application library.
//!
//! This crate provides the main entry point and infrastructure for the AZIHSM
//! management firmware. It initializes the Platform Abstraction Layer (PAL) and
//! runs the management application as an Embassy async task.
//!
//! # Features
//! - `pal-std`: Enables the standard PAL implementation for non-embedded environments.

#![no_std]

mod app;
mod ctrl;
mod pcie;

use app::MgmtApp;
use ctrl::*;
use embassy_executor::*;
use embassy_sync::lazy_lock::LazyLock;
use pcie::*;
use tracing::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "pal-std")] {
        use azihsm_fw_mgmt_pal_std::Pal as _;
        pub use azihsm_fw_mgmt_pal_std::*;
        /// The Platform Abstraction Layer type selected by feature flags.
        pub type Pal = azihsm_fw_mgmt_pal_std::StdPal;
    } else {
        compile_error!("No PAL implementation selected. Please enable a PAL feature.");
    }
}

/// Global lazily-initialized management application instance.
///
/// The application is initialized on first access and persists for the
/// lifetime of the firmware.
pub static MGMT_APP: LazyLock<MgmtApp> = LazyLock::new(MgmtApp::default);

/// Embassy task that runs the management application.
///
/// This async task serves as the main entry point for the management firmware,
/// driving the application's event loop and handling platform events.
///
/// # Parameters
/// - `spawner`: The Embassy task spawner for creating additional async tasks.
#[task]
pub async fn run(spawner: Spawner) {
    MGMT_APP.get().run(spawner).await;
}

/// Returns a reference to the Platform Abstraction Layer instance.
///
/// Provides access to the PAL for performing platform-specific operations
/// such as controller management, queue management, and I/O operations.
pub fn pal() -> &'static Pal {
    MGMT_APP.get().pal()
}
