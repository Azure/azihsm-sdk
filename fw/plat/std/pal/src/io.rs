// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO work item and [`HsmIoController`] implementation for the std PAL.
//!
//! Defines the request/response types and the IO work item that flows
//! through the core. The [`HsmIoController`] implementation delegates
//! to [`StdIic`](crate::drivers::iic::StdIic) for receiving and
//! [`StdOic`](crate::drivers::oic::StdOic) for completing IOs.

use std::sync::Arc;

use azihsm_fw_hsm_pal_traits::*;
use tokio::sync::oneshot::Sender as ReplySender;

use crate::buf_pool::BufferPool;
use crate::pal::HsmIoResponse;
use crate::StdHsmPal;

/// An IO submit request sent from the user thread to the Embassy thread.
///
/// Contains the SQE, metadata, and a oneshot reply channel. Host
/// source data for inbound DMA is referenced by the PRP address in
/// the SQE — the caller must keep the source buffer alive until the
/// response is received.
pub struct HsmIoRequest {
    /// Source controller identifier.
    pub pid: u8,

    /// Source queue identifier.
    pub qid: u16,

    /// Index within the source queue.
    pub qidx: u16,

    /// The 64-byte submission queue entry.
    pub sqe: HsmSqe,

    /// Oneshot channel for sending the response back to the submitter.
    pub tx: ReplySender<HsmIoResponse>,
}

/// An IO work item backed by a pool-allocated buffer slot.
///
/// Created by [`poll_io`](HsmIoController::poll_io) and consumed by
/// [`complete_io`](HsmIoController::complete_io). Flows through the
/// core's `recv_task` → `send_task` pipeline unchanged.
///
/// # Buffers
///
/// Each `StdHsmIo` holds an `Arc<BufferPool>` reference, providing safe
/// access to its slot's buffers without raw pointers:
/// - [`fast_mem()`](Self::fast_mem) — 2KB fast buffer
/// - [`mem()`](Self::mem) — 8KB large buffer
///
/// Buffers are pre-allocated in the [`BufferPool`] and reused across IOs.
pub struct StdHsmIo {
    /// Source controller identifier.
    pub(crate) pid: u8,

    /// Source queue identifier.
    pub(crate) qid: u16,

    /// Index within the source queue.
    pub(crate) qidx: u16,

    /// Index into the buffer pool (used to free the slot on completion).
    pub(crate) slot: u16,

    /// Oneshot channel for the response.
    pub(crate) tx: ReplySender<HsmIoResponse>,

    /// The 64-byte submission queue entry.
    pub(crate) sqe: HsmSqe,

    /// The 16-byte completion queue entry to be populated by the core.
    pub(crate) cqe: HsmCqe,

    /// Shared reference to the buffer pool.
    pool: Arc<BufferPool>,
}

// SAFETY: StdHsmIo is only used on the single-threaded Embassy executor.
// Arc<BufferPool> is Send+Sync; the UnsafeCell buffers inside are
// protected by the alloc/free protocol (one owner per slot at a time).
unsafe impl Send for StdHsmIo {}

impl StdHsmIo {
    /// Construct a new IO work item from a request, allocated slot, and pool.
    fn new(req: HsmIoRequest, slot: u16, pool: Arc<BufferPool>) -> Self {
        Self {
            pid: req.pid,
            qid: req.qid,
            qidx: req.qidx,
            sqe: req.sqe,
            slot,
            pool,
            tx: req.tx,
            cqe: [0; CQE_DWORDS],
        }
    }
}

impl core::fmt::Debug for StdHsmIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdHsmIo")
            .field("partition_id", &self.pid)
            .field("queue_id", &self.qid)
            .field("slot", &self.slot)
            .finish()
    }
}

impl HsmIo for StdHsmIo {
    fn part_id(&self) -> u8 {
        self.pid
    }

    fn queue_id(&self) -> u16 {
        self.qid
    }

    fn queue_idx(&self) -> u16 {
        self.qidx
    }

    fn sqe(&self) -> &HsmSqe {
        &self.sqe
    }

    fn cqe(&mut self) -> &mut HsmCqe {
        &mut self.cqe
    }

    fn mem(&mut self) -> (&mut [u8], &mut [u8]) {
        (
            self.pool.fast_buf(self.slot),
            self.pool.large_buf(self.slot),
        )
    }
}

impl HsmIoController for StdHsmPal {
    type Io = StdHsmIo;

    /// Wait for the next IO request and allocate a buffer slot.
    ///
    /// Delegates to [`StdIic::recv`](crate::drivers::iic::StdIic::recv)
    /// which receives from the submit channel and allocates a pool slot.
    /// Suspends if no requests are available or if the buffer pool is
    /// exhausted.
    async fn poll_io(&self) -> HsmResult<StdHsmIo> {
        let (req, slot) = self.iic.recv().await?;
        Ok(StdHsmIo::new(req, slot, self.iic.pool()))
    }

    /// Complete an IO: send response via OIC driver, then free the buffer.
    ///
    /// 1. Delegates to [`StdOic::send`](crate::drivers::oic::StdOic::send)
    ///    which simulates the OIC delay and sends the response.
    /// 2. Frees the buffer slot back to the pool via
    ///    [`StdIic::free`](crate::drivers::iic::StdIic::free).
    async fn complete_io(&self, io: Self::Io) -> HsmResult<()> {
        let slot = io.slot;
        self.oic.send(io).await;
        self.iic.free(slot);
        Ok(())
    }
}
