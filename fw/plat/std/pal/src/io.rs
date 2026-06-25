// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IO work item and [`HsmIoController`] implementation for the std PAL.
//!
//! Defines the request/response types and the IO work item that flows
//! through the core. The [`HsmIoController`] implementation delegates
//! to [`StdIic`](crate::drivers::iic::StdIic) for receiving and
//! [`StdOic`](crate::drivers::oic::StdOic) for completing IOs.

use azihsm_fw_hsm_pal_traits::*;
use tokio::sync::oneshot::Sender as ReplySender;

use crate::StdHsmPal;

/// An IO submit request sent from the user thread to the Embassy thread.
///
/// Contains the SQE, metadata, and a oneshot reply channel. Host
/// source data for inbound DMA is referenced by the PRP address in
/// the SQE — the caller must keep the source buffer alive until the
/// response is received.
pub struct HsmIoRequest {
    /// Source partition identifier.
    pub pid: HsmPartId,

    /// Source queue identifier.
    pub qid: u16,

    /// Index within the source queue.
    pub qidx: u16,

    /// The 64-byte submission queue entry.
    pub sqe: HsmSqe,

    /// Oneshot channel for sending the CQE back to the submitter.
    pub tx: ReplySender<HsmCqe>,
}

/// An IO work item backed by a pool-allocated buffer slot.
///
/// Created by [`poll_io`](HsmIoController::poll_io) and consumed by
/// [`complete_io`](HsmIoController::complete_io). Flows through the
/// core's `recv_task` → `send_task` pipeline unchanged.
///
/// # Buffers
///
/// `StdHsmIo` holds the index of its slot in the
/// [`BufferPool`](crate::buf_pool::BufferPool); the
/// [`HsmAlloc`](azihsm_fw_hsm_pal_traits::HsmAlloc) implementation on
/// [`StdHsmPal`] uses [`HsmIo::index`] to address per-slot bump
/// allocators backed by the pool's pre-allocated NonDma + Dma buffers.
pub struct StdHsmIo {
    /// Source partition identifier.
    pub(crate) pid: HsmPartId,

    /// Source queue identifier.
    pub(crate) qid: u16,

    /// Index within the source queue.
    pub(crate) qidx: u16,

    /// Index into the buffer pool (also the [`HsmIo::index`] value
    /// used by [`HsmAlloc`](azihsm_fw_hsm_pal_traits::HsmAlloc) to
    /// address per-IO bump heaps).
    pub(crate) slot: u16,

    /// Oneshot channel for the CQE reply.
    pub(crate) tx: ReplySender<HsmCqe>,

    /// The 64-byte submission queue entry.
    pub(crate) sqe: HsmSqe,

    /// The 16-byte completion queue entry to be populated by the core.
    pub(crate) cqe: HsmCqe,
}

// SAFETY: StdHsmIo is only used on the single-threaded Embassy executor.
unsafe impl Send for StdHsmIo {}

impl StdHsmIo {
    /// Construct a new IO work item from a request and an allocated slot.
    fn new(req: HsmIoRequest, slot: u16) -> Self {
        Self {
            pid: req.pid,
            qid: req.qid,
            qidx: req.qidx,
            sqe: req.sqe,
            slot,
            tx: req.tx,
            cqe: [0; CQE_DWORDS],
        }
    }

    /// Construct a transient admin IO for internal provisioning crypto
    /// (e.g. masking `BK_BOOT` at partition allocation), backed by a
    /// caller-borrowed buffer-pool `slot`.  `tx` is a throwaway reply
    /// channel — no host awaits the completion.
    pub(crate) fn admin(pid: HsmPartId, slot: u16, tx: ReplySender<HsmCqe>) -> Self {
        Self {
            pid,
            qid: 0,
            qidx: 0,
            sqe: [0; SQE_DWORDS],
            slot,
            tx,
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
    fn index(&self) -> u16 {
        self.slot
    }

    fn pid(&self) -> HsmPartId {
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
}

impl HsmIoController for StdHsmPal {
    type Io = StdHsmIo;

    /// Wait for the next IO request and allocate a buffer slot.
    ///
    /// Delegates to [`StdIic::recv`](crate::drivers::iic::StdIic::recv)
    /// which receives from the submit channel and allocates a pool slot.
    /// The pool resets the slot's bump-allocator watermarks before
    /// returning, so the new IO starts with empty NonDma/Dma heaps.
    ///
    /// Suspends if no requests are available or if the buffer pool is
    /// exhausted.
    async fn poll_io(&self) -> HsmResult<StdHsmIo> {
        let (req, slot) = self.iic.recv().await?;
        Ok(StdHsmIo::new(req, slot))
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

    /// Drop an IO without sending a CQE — frees the buffer slot only.
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()> {
        let slot = io.slot;
        drop(io);
        self.iic.free(slot);
        Ok(())
    }
}
