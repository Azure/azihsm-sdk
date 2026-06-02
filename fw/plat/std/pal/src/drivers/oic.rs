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
    /// Takes ownership of the IO work item, consuming the reply channel
    /// and CQE.
    pub async fn send(&self, io: StdHsmIo) {
        debug!(
            "oic",
            "send part={:?} qid={} qidx={}", io.pid, io.qid, io.qidx
        );

        // Reply to submitter with just the CQE.
        let _ = io.tx.send(io.cqe);
    }
}
