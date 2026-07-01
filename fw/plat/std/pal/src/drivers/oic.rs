// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std OIC driver — sends IO completions.
//!
//! Sends the response through the per-IO reply channel.

use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

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

    /// Send a completion response by posting the CQE to the submitter.
    ///
    /// Borrows the IO work item by `&mut` and `take()`s its oneshot reply
    /// sender (consumed on send) so the slot stays alive for the caller's
    /// post-completion work; the CQE is a `Copy` value.
    ///
    /// Synchronous — posting to the oneshot channel does not suspend.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::CompleteIoFailure`] if the CQE could not be
    /// posted — either the oneshot receiver was dropped (the submitter is
    /// gone) or `io.tx` was already taken (a double-complete). Core treats
    /// this as `cqe_ok = false` and rolls the command back, matching the
    /// Uno OIC driver's failure semantics.
    pub fn send(&self, io: &mut StdHsmIo) -> HsmResult<()> {
        debug!(
            "oic",
            "send part={:?} qid={} qidx={}", io.pid, io.qid, io.qidx
        );

        // Reply to submitter with just the CQE (oneshot — fires at most once).
        match io.tx.take() {
            Some(tx) => tx.send(io.cqe).map_err(|_| HsmError::CompleteIoFailure),
            None => Err(HsmError::CompleteIoFailure),
        }
    }
}
