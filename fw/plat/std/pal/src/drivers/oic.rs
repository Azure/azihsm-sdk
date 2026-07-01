// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std OIC driver — sends IO completions.
//!
//! Sends the response through the per-IO reply channel.

use azihsm_fw_hsm_core_tracing::*;

use crate::io::StdHsmIo;

/// Std OIC driver — outbound IO controller.
///
/// Sends IO completions through the per-IO reply channel.
pub struct StdOic;

impl StdOic {
    /// Create a new OIC driver.
    pub fn new() -> Self {
        Self
    }

    /// Send a completion response.
    ///
    /// Borrows the IO work item by `&mut` and `take()`s its oneshot reply
    /// sender (consumed on send) so the slot stays alive for the caller's
    /// post-completion work; the CQE is a `Copy` value.
    pub async fn send(&self, io: &mut StdHsmIo) {
        debug!(
            "oic",
            "send part={:?} qid={} qidx={}", io.pid, io.qid, io.qidx
        );

        // Reply to submitter with just the CQE (oneshot — fires at most once).
        if let Some(tx) = io.tx.take() {
            let _ = tx.send(io.cqe);
        }
    }
}
