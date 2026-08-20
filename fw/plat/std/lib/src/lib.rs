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

use azihsm_fw_hsm_core::Hsm;
use azihsm_fw_hsm_pal_std::*;
use azihsm_fw_hsm_pal_traits::*;
use embassy_sync::once_lock::OnceLock;

/// Global HSM singleton — concrete type with StdHsmPal.
static HSM: OnceLock<Hsm<StdHsmPal>> = OnceLock::new();

/// Embassy task that runs the HSM core lifecycle.
///
/// Initialises the PAL, spawns the IO recv/send task pool, enters the
/// PAL's main event loop, then deinitialises. This task never returns
/// under normal operation.
#[embassy_executor::task]
async fn run_core(spawner: embassy_executor::Spawner) {
    let hsm = HSM.get().await;
    hsm.pal().init();
    if hsm.pal().init_cert_store().await.is_err() {
        return;
    }

    if let Ok(token) = poll_io(spawner) {
        spawner.spawn(token);
    } else {
        return;
    }

    hsm.pal().run().await;
    hsm.pal().deinit();
}

/// IO receive loop — runs forever as a single Embassy task.
///
/// Awaits the next IO from the PAL submission queue, then spawns a
/// `handle_io` task from the 32-slot pool. If no pool slots are
/// available, the IO is silently skipped and the loop continues.
#[embassy_executor::task]
async fn poll_io(spawner: embassy_executor::Spawner) -> ! {
    loop {
        let Ok(io) = HSM.get().await.pal().poll_io().await else {
            continue;
        };

        let Ok(token) = handle_io(io) else {
            continue;
        };
        spawner.spawn(token);
    }
}

/// Processes a single IO to completion.
///
/// Delegates all parsing, validation, and CQE population to
/// [`Hsm::handle_io`]. Runs in a 32-task Embassy pool, allowing
/// up to 32 IOs to be processed concurrently.
#[embassy_executor::task(pool_size = 32)]
async fn handle_io(io: StdHsmIo) {
    HSM.get().await.handle_io(io).await;
}

/// Embassy task that processes sideband partition commands.
///
/// Receives [`PartCommand`]s from the user-facing [`StdHsm`] and
/// dispatches them to [`StdHsmPal`]'s internal alloc/free methods.
/// Replies via the per-command oneshot channel.
#[embassy_executor::task]
async fn ipc_task(rx: async_channel::Receiver<PartCommand>) {
    loop {
        let Ok(cmd) = rx.recv().await else {
            break;
        };
        let pal = HSM.get().await.pal();
        match cmd {
            PartCommand::Alloc {
                pid,
                res_mask,
                reply,
            } => {
                let _ = reply.send(pal.part_alloc_internal(pid, res_mask).await);
            }
            PartCommand::Free { pid, reply } => {
                let _ = reply.send(pal.part_free_internal(pid));
            }
            PartCommand::Enable { pid, reply } => {
                let _ = reply.send(pal.part_enable_internal(pid).await);
            }
            PartCommand::Disable { pid, reply } => {
                let _ = reply.send(pal.part_disable_internal(pid));
            }
        }
    }
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

        let (io_tx, io_rx) = async_channel::bounded(MAX_CONCURRENT_IOS - 1);
        let (ipc_tx, ipc_rx) = async_channel::bounded(4);

        let pool_handle = handle.clone();

        // Embassy + Hsm task frames in debug builds are large enough
        // to overflow Linux's default 2 MiB thread stack — every
        // emu-backed integration test SIGABRTs with "thread
        // 'hsm-embassy' has overflowed its stack" when each test
        // runs in its own process (e.g. under `cargo nextest run`).
        // Reserve 8 MiB explicitly so debug and release behave
        // identically; on Linux this is virtual-only and costs no
        // RSS until pages are touched.
        const EMBASSY_STACK_SIZE: usize = 8 * 1024 * 1024;

        let embassy_thread = std::thread::Builder::new()
            .name("hsm-embassy".into())
            .stack_size(EMBASSY_STACK_SIZE)
            .spawn(move || {
                use embassy_executor::Executor;
                use static_cell::StaticCell;

                static EXECUTOR: StaticCell<Executor> = StaticCell::new();
                let executor = EXECUTOR.init(Executor::new());

                executor.run(|spawner| {
                    let pal = StdHsmPal::new(io_rx, pool_handle);

                    let _ = HSM.init(Hsm::new(pal));

                    let token = run_core(spawner).expect("run_core spawn failed");
                    spawner.spawn(token);

                    let token = ipc_task(ipc_rx).expect("part_cmd_task spawn failed");
                    spawner.spawn(token);
                });
            })
            .expect("failed to spawn Embassy thread");

        StdHsm {
            io_tx,
            ipc_tx,
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
/// Dropping `StdHsm` cleanly shuts down the Embassy thread and
/// (if owned) the tokio runtime.
#[derive(Debug)]
pub struct StdHsm {
    io_tx: async_channel::Sender<HsmIoRequest>,
    ipc_tx: async_channel::Sender<PartCommand>,
    embassy_thread: Option<JoinHandle<()>>,
    /// Owned tokio runtime (None if caller provided a handle).
    /// Kept alive for the lifetime of StdHsm; dropped on shutdown.
    #[allow(dead_code)]
    tokio_rt: Option<tokio::runtime::Runtime>,
    #[allow(dead_code)]
    tokio_handle: tokio::runtime::Handle,
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
    /// # Errors
    ///
    /// Returns [`HsmError::InternalError`] if the core discards the IO (e.g. the
    /// partition is not enabled). Returns [`HsmError::InternalError`] if the
    /// Embassy thread has stopped.
    pub async fn io(&self, sqe: HsmSqe, pid: u8, qid: u16, qidx: u16) -> HsmResult<HsmCqe> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let req = HsmIoRequest {
            pid: HsmPartId::from(pid),
            qid,
            qidx,
            sqe,
            tx: reply_tx,
        };
        self.io_tx
            .send(req)
            .await
            .map_err(|_| HsmError::InternalError)?;
        reply_rx.await.map_err(|_| HsmError::InternalError)
    }

    /// Allocate a partition on the HSM.
    ///
    /// Sends a sideband command to the Embassy thread to allocate
    /// partition `pid` with the given `res_mask` (each set bit = one
    /// vault table).  On success the partition transitions from
    /// `Disabled` → `Uninitialized`, a 16-byte random ID is generated,
    /// and an ECC-384 key pair is created.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `pid >= 65` or invalid mask bits
    /// - [`HsmError::InvalidArg`] — partition is not `Disabled`
    /// - [`HsmError::NotEnoughSpace`] — `res_mask` overlaps already-allocated resources
    /// - [`HsmError::InternalError`] — ECC key or RNG failure
    pub async fn part_alloc(&self, pid: u8, res_mask: u128) -> HsmResult<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = PartCommand::Alloc {
            pid,
            res_mask,
            reply: reply_tx,
        };
        self.ipc_tx.send(cmd).await.expect("Embassy thread stopped");
        reply_rx.await.expect("partition command reply dropped")
    }

    /// Free a partition on the HSM.
    ///
    /// Sends a sideband command to the Embassy thread to free partition
    /// `pid`. Clears the partition's ID, key pair, and resource count,
    /// then transitions the state to `Disabled`. The freed resources
    /// become available for other partitions.
    ///
    /// # Errors
    ///
    /// - `PART_INVALID_PID` — `pid >= 65`
    /// - `PART_NOT_ALLOCATED` — partition is already `Disabled`
    pub async fn part_free(&self, pid: u8) -> HsmResult<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = PartCommand::Free {
            pid,
            reply: reply_tx,
        };
        self.ipc_tx.send(cmd).await.expect("Embassy thread stopped");
        reply_rx.await.expect("partition command reply dropped")
    }

    /// Enable a partition: create internal ECC-384 key pairs and nonce.
    ///
    /// Transitions `Allocated | Disabled → Enabled`.  IO operations
    /// require the partition to be in `Enabled` state.
    pub async fn part_enable(&self, pid: u8) -> HsmResult<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = PartCommand::Enable {
            pid,
            reply: reply_tx,
        };
        self.ipc_tx.send(cmd).await.expect("Embassy thread stopped");
        reply_rx.await.expect("partition command reply dropped")
    }

    /// Disable a partition: clear internal keys, nonce, vault, sessions.
    ///
    /// Transitions `Enabled → Disabled`.
    pub async fn part_disable(&self, pid: u8) -> HsmResult<()> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = PartCommand::Disable {
            pid,
            reply: reply_tx,
        };
        self.ipc_tx.send(cmd).await.expect("Embassy thread stopped");
        reply_rx.await.expect("partition command reply dropped")
    }
}

/// Cleanly shuts down the HSM.
///
/// Closes both the IO submission and partition command channels, which
/// causes the corresponding Embassy tasks (`run_core` / `part_cmd_task`)
/// to exit. Then joins the Embassy background thread to ensure all
/// in-flight work is completed before the `StdHsm` is dropped.
///
/// If a tokio runtime is owned (`tokio_rt` is `Some`), it is dropped
/// after the Embassy thread exits, shutting down the worker pool.
impl Drop for StdHsm {
    fn drop(&mut self) {
        self.io_tx.close();
        self.ipc_tx.close();
        if let Some(thread) = self.embassy_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Default for StdHsm {
    fn default() -> Self {
        Self::new()
    }
}
