// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std OIC driver — sends IO completions.
//!
//! Sends the response through the per-IO reply channel and broadcasts
//! on the completion channel.

use async_channel::Sender;
use azihsm_fw_hsm_core_tracing::*;

use crate::io::StdHsmIo;
use crate::pal::HsmIoResponse;

/// Std OIC driver — outbound IO controller.
///
/// Sends IO completions through the per-IO reply channel and
/// broadcasts on the completion channel for metrics/logging.
pub struct StdOic {
    /// Broadcast channel for completion events (metrics/logging).
    complete_tx: Sender<HsmIoResponse>,
}

impl StdOic {
    /// Create a new OIC driver.
    pub fn new(complete_tx: Sender<HsmIoResponse>) -> Self {
        Self { complete_tx }
    }

    /// Send a completion response and broadcast.
    ///
    /// Takes ownership of the IO work item, consuming the reply channel
    /// and CQE.
    pub async fn send(&self, io: StdHsmIo) {
        debug!(
            "oic",
            "send part={} qid={} qidx={}", io.pid, io.qid, io.qidx
        );

        let response = HsmIoResponse {
            cqe: io.cqe,
            pid: io.pid,
            qid: io.qid,
            qidx: io.qidx,
        };

        // Broadcast for metrics/logging
        let _ = self.complete_tx.try_send(HsmIoResponse {
            cqe: io.cqe,
            pid: io.pid,
            qid: io.qid,
            qidx: io.qidx,
        });

        // Reply to submitter.
        let _ = io.tx.send(response);
    }
}
