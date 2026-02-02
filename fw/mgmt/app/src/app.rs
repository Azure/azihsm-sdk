// Copyright (C) Microsoft Corporation. All rights reserved.

//! Management application core implementation.
//!
//! This module contains the [`MgmtApp`] struct which orchestrates the lifecycle
//! of the management firmware, including PAL initialization, event processing,
//! and cleanup.

use futures::future::{Either, select};

use super::*;

/// The core management application structure.
///
/// Encapsulates the Platform Abstraction Layer and manages the application
/// lifecycle from initialization through event processing to shutdown.
pub struct MgmtApp {
    /// The platform abstraction layer instance.
    pal: Pal,
}

impl Default for MgmtApp {
    fn default() -> Self {
        Self {
            pal: Pal::default(),
        }
    }
}

impl MgmtApp {
    /// Runs the management application.
    ///
    /// This method performs the complete application lifecycle:
    /// 1. Initializes the PAL
    /// 2. Runs the PAL event loop until shutdown
    /// 3. Deinitializes the PAL
    ///
    /// # Parameters
    /// - `spawner`: The Embassy task spawner (reserved for future use).
    pub(crate) async fn run(&self, spawner: Spawner) {
        spawner.spawn(event_task(spawner).unwrap());

        let _ = self.pal.init();
        self.pal.run().await;
        let _ = self.pal.deinit();
    }

    /// Returns a reference to the Platform Abstraction Layer.
    pub fn pal(&self) -> &Pal {
        &self.pal
    }
}

#[task]
#[instrument("event_task", skip(_spawner))]
pub async fn event_task(_spawner: Spawner) {
    let app = MGMT_APP.get();
    loop {
        let result = select(app.pal().poll_pcie_event(), app.pal().poll_ctrl_event()).await;
        let result = match result {
            Either::Left((pcie_event, _)) => handle_pcie_event(pcie_event),
            Either::Right((ctrl_event, _)) => handle_ctrl_event(ctrl_event),
        };
        if result.is_err() {
            tracing::error!("Error handling event: {:?}", result.err());
        }
    }
}
