// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std PAL — struct definition and [`HsmPal`] trait implementation.

use async_channel::Receiver;
use async_channel::Sender;
use azihsm_fw_hsm_core_tracing::*;
use azihsm_fw_hsm_pal_traits::*;
use tokio::runtime::Handle;
use tokio::runtime::Runtime;

use crate::drivers::gdma::StdGdma;
use crate::drivers::iic::StdIic;
use crate::drivers::oic::StdOic;
use crate::io::HsmIoRequest;
use crate::worker::WorkerPool;

/// Response data returned after an IO is processed by the core.
#[derive(Debug)]
pub struct HsmIoResponse {
    /// The completion queue entry written by the core.
    pub cqe: HsmCqe,

    /// Source controller identifier.
    pub pid: u8,

    /// Source queue identifier.
    pub qid: u16,

    /// Index within the source queue.
    pub qidx: u16,
}

/// Host-native HSM platform abstraction layer.
///
/// Owns an [`StdIic`] (inbound IO), [`StdOic`] (outbound completion),
/// and [`StdGdma`] (memory copy) driver.
/// architecture.
pub struct StdHsmPal {
    /// Inbound IO controller — receives requests and manages buffer pool.
    pub(crate) iic: StdIic,

    /// Outbound IO controller — sends completions.
    pub(crate) oic: StdOic,

    /// GDMA controller — memory copy.
    pub(crate) gdma: StdGdma,

    /// Tokio-backed worker pool for offloading async work.
    #[allow(dead_code)]
    pub(crate) pool: WorkerPool,

    /// Tokio runtime owned by this instance when constructed via [`Default`].
    ///
    /// `None` when constructed via [`new`](Self::new) — the caller owns the
    /// runtime. `Some` when constructed via `Default` so the runtime is kept
    /// alive as long as the `StdHsmPal` is alive.
    #[allow(dead_code)]
    _rt: Option<Runtime>,
}

impl core::fmt::Debug for StdHsmPal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StdHsmPal").finish()
    }
}

impl StdHsmPal {
    /// Create a new std PAL.
    pub fn new(
        submit_rx: Receiver<HsmIoRequest>,
        complete_tx: Sender<HsmIoResponse>,
        tokio_handle: Handle,
    ) -> Self {
        Self {
            iic: StdIic::new(submit_rx),
            oic: StdOic::new(complete_tx),
            gdma: StdGdma::new(),
            pool: WorkerPool::new(tokio_handle),
            _rt: None,
        }
    }
}

impl Default for StdHsmPal {
    fn default() -> Self {
        let (_tx, rx) = async_channel::bounded(1);
        let (tx2, _rx2) = async_channel::bounded(1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let handle = rt.handle().clone();
        Self {
            iic: StdIic::new(rx),
            oic: StdOic::new(tx2),
            gdma: StdGdma::new(),
            pool: WorkerPool::new(handle),
            // Keep the runtime alive so `handle` remains valid.
            _rt: Some(rt),
        }
    }
}

impl HsmPal for StdHsmPal {
    fn init(&self) {
        info!("pal", "initialized (std)");
    }

    async fn run(&self) {
        core::future::pending::<()>().await;
    }

    fn deinit(&self) {}
}
