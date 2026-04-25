// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! StdHsm — host-native HSM instance.
//!
//! Runs the HSM core logic natively on the host using channels for IO
//! transport and heap-allocated buffers.
//!
//! IO submission uses `async-channel` (bounded to [`MAX_CONCURRENT_IOS`] - 1)
//! for backpressure. Each IO carries a `tokio::sync::oneshot` reply channel
//! so completions are routed directly to the submitter — no ordering issues
//! with concurrent IOs.
//!
//! # Example
//!
//! ```ignore
//! // Default:
//! let hsm = StdHsm::new();
//! let c = hsm.submit([0u32; 16], 0, 0, 0).await;
//! assert_eq!(c.cqe[3], expected_cmd_id);
//!
//! // With caller's tokio runtime:
//! let hsm = StdHsm::with_tokio(tokio::runtime::Handle::current());
//! ```

use std::thread::JoinHandle;

use azihsm_fw_hsm_pal_std::HsmIoRequest;
pub use azihsm_fw_hsm_pal_std::HsmIoResponse;
use azihsm_fw_hsm_pal_std::StdHsmPal;
use azihsm_fw_hsm_pal_traits::HsmSqe;

#[embassy_executor::task]
async fn run_core(spawner: embassy_executor::Spawner) {
    azihsm_fw_hsm_core::HSM
        .get_or_init(Default::default)
        .run(spawner)
        .await;
}

/// Maximum concurrent IOs — matches core's `send_task` pool size.
/// The submit channel is bounded to this minus one (one slot reserved
/// for the IO being processed by `recv_task`).
const MAX_CONCURRENT_IOS: usize = 32;

/// Builder for configuring and creating a [`StdHsm`].
///
/// # Example
///
/// ```ignore
/// let hsm = StdHsm::builder()
///     .tokio_handle(handle)
///     .build();
/// ```
pub struct StdHsmBuilder {
    /// External tokio runtime handle (None = create owned runtime).
    tokio_handle: Option<tokio::runtime::Handle>,
}

impl StdHsmBuilder {
    /// Use an existing tokio runtime handle for async worker tasks.
    ///
    /// When set, `StdHsm` does not create or own a tokio runtime.
    /// The caller must keep their runtime alive for the lifetime of
    /// the `StdHsm`.
    pub fn tokio_handle(mut self, handle: tokio::runtime::Handle) -> Self {
        self.tokio_handle = Some(handle);
        self
    }

    /// Build and start the HSM instance.
    ///
    /// Spawns an Embassy executor on a background thread and optionally
    /// creates a tokio runtime (if [`tokio_handle`](Self::tokio_handle)
    /// was not called).
    ///
    /// # Panics
    ///
    /// Panics if the Embassy thread or tokio runtime fails to start.
    pub fn build(self) -> StdHsm {
        let (owned_rt, handle) = if let Some(h) = self.tokio_handle {
            (None, h)
        } else {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .expect("failed to create tokio runtime");
            let h = rt.handle().clone();
            (Some(rt), h)
        };

        let (submit_tx, submit_rx) = async_channel::bounded(MAX_CONCURRENT_IOS - 1);
        let (complete_tx, complete_rx) = async_channel::bounded(MAX_CONCURRENT_IOS);

        let pool_handle = handle.clone();

        let embassy_thread = std::thread::Builder::new()
            .name("hsm-embassy".into())
            .spawn(move || {
                use embassy_executor::Executor;
                use static_cell::StaticCell;

                static EXECUTOR: StaticCell<Executor> = StaticCell::new();
                let executor = EXECUTOR.init(Executor::new());

                executor.run(|spawner| {
                    let pal = StdHsmPal::new(submit_rx, complete_tx, pool_handle);

                    let _ = azihsm_fw_hsm_core::HSM.init(azihsm_fw_hsm_core::Hsm::new(pal));

                    let token = run_core(spawner).expect("run_core spawn failed");
                    spawner.spawn(token);
                });
            })
            .expect("failed to spawn Embassy thread");

        StdHsm {
            submit_tx,
            complete_rx,
            embassy_thread: Some(embassy_thread),
            tokio_rt: owned_rt,
            tokio_handle: handle,
        }
    }
}

/// A host-native HSM instance.
///
/// Wraps an Embassy executor thread and an optional tokio runtime.
/// Submit IOs via [`submit`](Self::submit) and receive completions
/// asynchronously. Supports up to [`MAX_CONCURRENT_IOS`] in-flight
/// IOs with automatic backpressure.
///
/// # Thread safety
///
/// `StdHsm` is `Send + Sync` — [`submit`](Self::submit) can be called
/// from multiple tokio tasks concurrently. Each IO gets its own oneshot
/// reply channel, so completions never get mixed up.
///
/// # Shutdown
///
/// Call [`shutdown`](Self::shutdown) to cleanly stop the Embassy thread
/// and (if owned) the tokio runtime. Dropping without shutdown will
/// also clean up, but the Embassy thread may not exit gracefully.
pub struct StdHsm {
    submit_tx: async_channel::Sender<HsmIoRequest>,
    #[allow(dead_code)]
    complete_rx: async_channel::Receiver<HsmIoResponse>,
    embassy_thread: Option<JoinHandle<()>>,
    /// Owned tokio runtime (None if caller provided a handle).
    /// Kept alive for the lifetime of StdHsm; dropped on shutdown.
    #[allow(dead_code)]
    tokio_rt: Option<tokio::runtime::Runtime>,
    #[allow(dead_code)]
    tokio_handle: tokio::runtime::Handle,
}

/// Result returned by [`StdHsm::shutdown`].
#[derive(Debug)]
pub struct RunResult {
    /// Number of IOs submitted.
    pub total_ios: u64,
}

impl StdHsm {
    /// Create a [`StdHsmBuilder`] for configuring the HSM.
    ///
    /// Use this to set delays or provide an external tokio handle.
    pub fn builder() -> StdHsmBuilder {
        StdHsmBuilder { tokio_handle: None }
    }

    /// Create and start with default settings (no delays, owned tokio).
    ///
    /// Equivalent to `StdHsm::builder().build()`.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Create and start using an existing tokio runtime handle.
    ///
    /// The caller must keep their tokio runtime alive. No delays are
    /// configured — use [`builder`](Self::builder) for that.
    pub fn with_tokio(handle: tokio::runtime::Handle) -> Self {
        Self::builder().tokio_handle(handle).build()
    }

    /// Submit an IO and wait for the completion.
    ///
    /// Constructs a [`StdHsmIo`] from the given SQE and metadata, sends
    /// it to the core via the submit channel, and awaits the per-IO
    /// oneshot reply.
    ///
    /// If the core's task pool is full ([`MAX_CONCURRENT_IOS`] in flight),
    /// this method blocks asynchronously until a slot opens up — natural
    /// backpressure, no errors.
    ///
    /// # Panics
    ///
    /// Panics if the Embassy thread has stopped (submit channel closed)
    /// or if the IO's completion is dropped without sending a reply.
    pub async fn submit(&self, sqe: HsmSqe, pid: u8, qid: u16, qidx: u16) -> HsmIoResponse {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = HsmIoRequest {
            pid,
            qid,
            qidx,
            sqe,
            tx: reply_tx,
        };
        self.submit_tx
            .send(req)
            .await
            .expect("Embassy thread stopped");
        reply_rx.await.expect("IO completion dropped")
    }

    /// Shutdown the HSM and return results.
    ///
    /// Closes the submit channel (causing `recv_task` to exit), then
    /// joins the Embassy background thread. If `StdHsm` owns the tokio
    /// runtime, it is shut down on drop.
    pub fn shutdown(mut self) -> RunResult {
        self.submit_tx.close();
        if let Some(thread) = self.embassy_thread.take() {
            let _ = thread.join();
        }
        RunResult { total_ios: 0 }
    }
}

impl Default for StdHsm {
    fn default() -> Self {
        Self::new()
    }
}
