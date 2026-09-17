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
//! let runtime = tokio::runtime::Builder::new_multi_thread().build()?;
//! let hsm = StdHsm::with_tokio(runtime.handle().clone());
//! ```

use core::future::poll_fn;
use core::task::Poll;
use core::task::Waker;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle;

use azihsm_fw_hsm_core::Hsm;
use azihsm_fw_hsm_pal_std::*;
use azihsm_fw_hsm_pal_traits::*;
use embassy_sync::once_lock::OnceLock;

/// Global HSM singleton — concrete type with StdHsmPal.
static HSM: OnceLock<Hsm<StdHsmPal>> = OnceLock::new();

/// Tracks the one-instance-ever [`StdHsm`] lifecycle restriction.
static STD_HSM_BUILT: AtomicBool = AtomicBool::new(false);

/// Coordinates a drain-then-stop shutdown of the Embassy executor.
///
/// `active_tasks` starts at 2, accounting for the long-running
/// [`poll_io`] and [`ipc_task`] loops. Each in-flight [`handle_io`]
/// spawn adds one more. Every task decrements the count exactly once
/// when it permanently exits — `poll_io`/`ipc_task` only exit once
/// their channel is closed and drained, and `handle_io` always exits
/// after finishing its single IO. Once the task count reaches zero,
/// [`run_core`] is woken to deinitialize the PAL; only then may
/// `run_until` stop the executor.
struct ShutdownTracker {
    active_tasks: AtomicUsize,
    drained: AtomicBool,
    deinitialized: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ShutdownTracker {
    fn new(active_tasks: usize) -> Self {
        Self {
            active_tasks: AtomicUsize::new(active_tasks),
            drained: AtomicBool::new(false),
            deinitialized: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    /// Marks one tracked task as permanently finished.
    fn task_done(&self) {
        if self.active_tasks.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drained.store(true, Ordering::Release);
            let mut waker = self
                .waker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(waker) = waker.take() {
                waker.wake();
            }
        }
    }

    async fn wait_drained(&self) {
        poll_fn(|cx| {
            if self.drained.load(Ordering::Acquire) {
                return Poll::Ready(());
            }

            *self
                .waker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cx.waker().clone());

            if self.drained.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    fn mark_deinitialized(&self) {
        self.deinitialized.store(true, Ordering::Release);
    }
}

/// Embassy task that runs the HSM core lifecycle.
///
/// Initialises the PAL, spawns the IO recv/send task pool, waits for
/// shutdown drain, then deinitialises before allowing the executor to stop.
#[embassy_executor::task]
async fn run_core(spawner: embassy_executor::Spawner, tracker: Arc<ShutdownTracker>) {
    let hsm = HSM.get().await;
    hsm.pal().init();
    if hsm.pal().init_cert_store().await.is_err() {
        // poll_io never starts — account for its reserved slot.
        tracker.task_done();
        tracker.wait_drained().await;
        hsm.pal().deinit();
        tracker.mark_deinitialized();
        return;
    }

    if let Ok(token) = poll_io(spawner, tracker.clone()) {
        spawner.spawn(token);
    } else {
        // poll_io never starts — account for its reserved slot.
        tracker.task_done();
        tracker.wait_drained().await;
        hsm.pal().deinit();
        tracker.mark_deinitialized();
        return;
    }

    tracker.wait_drained().await;
    hsm.pal().deinit();
    tracker.mark_deinitialized();
}

/// IO receive loop — runs until the submission channel is closed.
///
/// Awaits the next IO from the PAL submission queue, then spawns a
/// `handle_io` task from the 32-slot pool. If no pool slots are
/// available, the IO is silently skipped and the loop continues. Only
/// exits once the submission channel is closed and drained, and only
/// then marks itself done in `tracker` — the executor won't stop
/// until this loop (and every `handle_io` it spawned) has finished.
#[embassy_executor::task]
async fn poll_io(spawner: embassy_executor::Spawner, tracker: Arc<ShutdownTracker>) {
    loop {
        let Ok(io) = HSM.get().await.pal().poll_io().await else {
            break;
        };

        tracker.active_tasks.fetch_add(1, Ordering::AcqRel);
        let Ok(token) = handle_io(io, tracker.clone()) else {
            tracker.task_done();
            continue;
        };
        spawner.spawn(token);
    }
    tracker.task_done();
}

/// Processes a single IO to completion.
///
/// Delegates all parsing, validation, and CQE population to
/// [`Hsm::handle_io`]. Runs in a 32-task Embassy pool, allowing
/// up to 32 IOs to be processed concurrently.
#[embassy_executor::task(pool_size = 32)]
async fn handle_io(io: StdHsmIo, tracker: Arc<ShutdownTracker>) {
    HSM.get().await.handle_io(io).await;
    tracker.task_done();
}

/// Embassy task that processes sideband partition commands.
///
/// Receives [`PartCommand`]s from the user-facing [`StdHsm`] and
/// dispatches them to [`StdHsmPal`]'s internal alloc/free methods.
/// Replies via the per-command oneshot channel. Only exits once the
/// command channel is closed and drained, then marks itself done in
/// `tracker`.
#[embassy_executor::task]
async fn ipc_task(rx: async_channel::Receiver<PartCommand>, tracker: Arc<ShutdownTracker>) {
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
    tracker.task_done();
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
    /// the `StdHsm`. The runtime must use Tokio's multi-thread scheduler.
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
    /// Panics if a [`StdHsm`] has already been built in this process, or if the
    /// Embassy thread or tokio runtime fails to start. Also panics if the
    /// supplied Tokio handle belongs to a current-thread runtime.
    pub fn build(self) -> StdHsm {
        if let Some(handle) = &self.tokio_handle {
            assert!(
                matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ),
                "StdHsm requires a multi-thread Tokio runtime"
            );
        }
        assert!(
            !STD_HSM_BUILT.swap(true, Ordering::AcqRel),
            "StdHsm can only be built once per process"
        );

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
        // Reserves one slot each for `poll_io` and `ipc_task`; decremented
        // as those loops (and any in-flight `handle_io`) permanently exit.
        let shutdown_tracker = Arc::new(ShutdownTracker::new(2));
        let executor_shutdown = shutdown_tracker.clone();

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

                executor.run_until(
                    |spawner| {
                        let pal = StdHsmPal::new(io_rx, pool_handle);

                        let _ = HSM.init(Hsm::new(pal));

                        let token = run_core(spawner, shutdown_tracker.clone())
                            .expect("run_core spawn failed");
                        spawner.spawn(token);

                        let token = ipc_task(ipc_rx, shutdown_tracker.clone())
                            .expect("part_cmd_task spawn failed");
                        spawner.spawn(token);
                    },
                    || executor_shutdown.deinitialized.load(Ordering::Acquire),
                );
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
/// Prefer the explicit [`shutdown`](Self::shutdown) /
/// [`shutdown_async`](Self::shutdown_async) methods: both close the submission
/// channels and return only once the Embassy executor has drained every
/// in-flight IO and IPC command and stopped. This is required when the caller
/// owns the tokio runtime, since that runtime must outlive the drain.
///
/// Dropping `StdHsm` without calling them also closes the submission channels,
/// but the drain is joined on a background thread, so `Drop` returns before the
/// Embassy thread has finished. An owned tokio runtime is dropped by that
/// thread after the drain completes; a caller-owned runtime is not coordinated.
///
/// `StdHsm` owns process-global HSM and executor singletons, so only one
/// instance can ever be built per process, even after that instance is dropped.
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
    /// configured — use [`builder`](Self::builder) for that. The runtime
    /// must use Tokio's multi-thread scheduler.
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

    /// Shut down the HSM, blocking until all in-flight work has drained.
    ///
    /// Callers that supplied their own tokio runtime
    /// ([`with_tokio`](Self::with_tokio) /
    /// [`tokio_handle`](StdHsmBuilder::tokio_handle)) must use this method (or
    /// [`shutdown_async`](Self::shutdown_async)) instead of relying on `Drop`:
    /// `Drop` joins the Embassy thread in the background and returns
    /// immediately, so the caller-owned runtime could be dropped while
    /// in-flight work still needs it, aborting that work and stalling the
    /// drain. This method returns only once the Embassy executor has stopped,
    /// after which the runtime can safely be dropped.
    ///
    /// Must not be called from a thread of the tokio runtime backing this HSM —
    /// blocking a worker that in-flight work needs would deadlock the drain.
    /// Use [`shutdown_async`](Self::shutdown_async) from async contexts.
    pub fn shutdown(mut self) {
        if let Some(thread) = self.begin_shutdown() {
            let _ = thread.join();
        }
        drop(self.tokio_rt.take());
    }

    /// Shut down the HSM, awaiting until all in-flight work has drained.
    ///
    /// Async counterpart of [`shutdown`](Self::shutdown): the Embassy thread is
    /// joined on a dedicated thread, so no tokio worker is blocked while
    /// in-flight work drains. Awaiting this future to completion guarantees the
    /// executor has stopped, so a caller-owned runtime can then be dropped
    /// safely.
    pub async fn shutdown_async(mut self) {
        if let Some(thread) = self.begin_shutdown() {
            let (tx, rx) = tokio::sync::oneshot::channel();
            std::thread::spawn(move || {
                let _ = thread.join();
                let _ = tx.send(());
            });
            let _ = rx.await;
        }
        drop(self.tokio_rt.take());
    }

    /// Stops accepting new work and takes ownership of the Embassy thread.
    ///
    /// Closing both channels lets `poll_io`/`ipc_task` exit once drained,
    /// which in turn wakes `run_core` to deinitialize the PAL. Returns `None`
    /// if shutdown was already started.
    fn begin_shutdown(&mut self) -> Option<JoinHandle<()>> {
        self.io_tx.close();
        self.ipc_tx.close();
        self.embassy_thread.take()
    }
}

/// Cleanly shuts down the HSM.
///
/// Closes both the IO submission and partition command channels, which
/// causes the corresponding Embassy tasks (`run_core` / `part_cmd_task`)
/// to exit. A shutdown thread then joins the Embassy background thread
/// after all in-flight work is complete, without blocking a Tokio worker
/// that may be needed by the work being drained.
///
/// Because that join is detached, `Drop` returns before the drain finishes.
/// Callers owning the tokio runtime must instead use
/// [`StdHsm::shutdown`]/[`StdHsm::shutdown_async`], which return only after the
/// Embassy executor has stopped, so their runtime outlives the drain.
///
/// If a tokio runtime is owned (`tokio_rt` is `Some`), it is dropped
/// after the Embassy thread exits, shutting down the worker pool.
impl Drop for StdHsm {
    fn drop(&mut self) {
        // Stop accepting new work; `poll_io`/`ipc_task` exit their loops
        // once these channels are closed and drained. `ShutdownTracker`
        // then wakes `run_core` to deinitialize the PAL before the
        // `run_until` predicate lets the Embassy thread stop.
        if let Some(thread) = self.begin_shutdown() {
            join_shutdown(thread, self.tokio_rt.take());
        }
    }
}

fn join_shutdown(thread: JoinHandle<()>, tokio_rt: Option<tokio::runtime::Runtime>) {
    std::thread::spawn(move || {
        let _ = thread.join();
        drop(tokio_rt);
    });
}

impl Default for StdHsm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Regression test for the shutdown drain protocol: shutdown must not
    /// drain while `handle_io` work is still in flight, and draining must
    /// not by itself satisfy the `run_until` predicate before `run_core`
    /// has deinitialized the PAL.
    #[test]
    fn shutdown_tracker_waits_for_all_tasks() {
        let tracker = ShutdownTracker::new(2);

        // Simulate an IO accepted by `poll_io` and still being processed
        // by `handle_io` when shutdown begins.
        tracker.active_tasks.fetch_add(1, Ordering::AcqRel);

        // `poll_io`'s loop exits (its channel closed and drained).
        tracker.task_done();
        assert!(
            !tracker.drained.load(Ordering::Acquire),
            "must not stop while handle_io is still in flight"
        );

        // `ipc_task`'s loop exits (its channel closed and drained).
        tracker.task_done();
        assert!(
            !tracker.drained.load(Ordering::Acquire),
            "must not stop while handle_io is still in flight"
        );

        // The in-flight `handle_io` finally finishes.
        tracker.task_done();
        assert!(
            tracker.drained.load(Ordering::Acquire),
            "must drain only once every accepted task has finished"
        );
        assert!(
            !tracker.deinitialized.load(Ordering::Acquire),
            "must not stop before run_core deinitializes the PAL"
        );

        tracker.mark_deinitialized();
        assert!(
            tracker.deinitialized.load(Ordering::Acquire),
            "must stop after run_core deinitializes the PAL"
        );
    }

    #[test]
    #[should_panic(expected = "StdHsm requires a multi-thread Tokio runtime")]
    fn current_thread_tokio_runtime_is_rejected() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to create tokio runtime");
        let _hsm = StdHsm::with_tokio(runtime.handle().clone());
    }

    #[test]
    fn shutdown_join_does_not_block_caller() {
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            release_rx.recv().expect("release sender dropped");
            done_tx.send(()).expect("completion receiver dropped");
        });

        join_shutdown(thread, None);

        assert!(
            done_rx.recv_timeout(Duration::from_millis(10)).is_err(),
            "shutdown must not join on the calling thread"
        );
        release_tx.send(()).expect("shutdown thread dropped");
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown thread did not complete");
    }
}
