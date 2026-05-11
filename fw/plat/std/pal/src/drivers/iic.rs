// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std IIC driver — receives IO requests and manages buffer allocation.
//!
//! Receives [`HsmIoRequest`]s from the submit channel and allocates
//! buffer slots from the [`BufferPool`].

use std::sync::Arc;

use async_channel::Receiver;
use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;

use crate::buf_pool::BufferPool;
use crate::io::HsmIoRequest;

/// Std IIC driver — inbound IO controller.
///
/// Owns the submit channel receiver and buffer pool. Provides
/// `recv()` to wait for the next IO request with an allocated
/// buffer slot, and `free()` to return the slot.
pub struct StdIic {
    /// Channel receiver for incoming IO requests.
    submit_rx: Receiver<HsmIoRequest>,

    /// Shared buffer pool for NonDma and Dma buffers.
    buf_pool: Arc<BufferPool>,
}

impl StdIic {
    /// Create a new IIC driver.
    pub fn new(submit_rx: Receiver<HsmIoRequest>) -> Self {
        Self {
            submit_rx,
            buf_pool: Arc::new(BufferPool::new()),
        }
    }

    /// Wait for the next IO request and allocate a buffer slot.
    ///
    /// Returns the request and its allocated slot index. Suspends if
    /// no requests are available or if the buffer pool is exhausted.
    /// The pool resets the slot's bump-allocator watermarks before
    /// returning, so the new IO starts with empty NonDma/Dma heaps.
    pub async fn recv(&self) -> HsmResult<(HsmIoRequest, u16)> {
        let req = self.submit_rx.recv().await.map_err(|_| {
            error!("iic", HsmError::InternalError, "submit channel closed");
            HsmError::InternalError
        })?;

        let slot = self.buf_pool.alloc().await;

        debug!(
            "iic",
            "recv slot={} part={:?} qid={} qidx={}", slot, req.pid, req.qid, req.qidx
        );

        Ok((req, slot))
    }

    /// Free a buffer slot back to the pool.
    pub fn free(&self, slot: u16) {
        self.buf_pool.free(slot);
    }

    /// Borrows the buffer pool used by this IIC driver.
    ///
    /// Used by the [`HsmAlloc`](azihsm_fw_hsm_pal_traits::HsmAlloc)
    /// implementation on [`crate::StdHsmPal`] to bump-allocate from
    /// the per-slot NonDma / Dma heaps.
    pub fn pool(&self) -> &BufferPool {
        &self.buf_pool
    }
}
