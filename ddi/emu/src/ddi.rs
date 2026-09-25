// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - AZIHSM Emulator - DDI Module.

use std::sync::Arc;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use azihsm_fw_hsm_std::StdHsm;
use parking_lot::Condvar;
use parking_lot::Mutex;
use tokio::runtime::Runtime;

use crate::dev::DdiEmuDev;
use crate::dev::EMU_DEVICE_PATH;

/// Process-global emulator context.
///
/// Owns the tokio runtime that backs the firmware platform tasks, and the
/// single [`StdHsm`] instance that runs the firmware. The `StdHsm` core
/// (`Hsm<StdHsmPal>`) lives in a global `OnceLock` inside
/// `azihsm_fw_hsm_std`, so only one instance can ever exist per process —
/// we lazily create at most one and never let it be re-created after
/// [`DdiEmu::shutdown`] releases it (see [`CTX`]).
struct EmuCtx {
    /// Multi-thread tokio runtime shared with [`StdHsm`].
    ///
    /// The runtime is built explicitly so that synchronous trait methods
    /// (`exec_op`) can use `Handle::block_on` to drive `StdHsm::io`. The
    /// runtime is also passed to [`StdHsm::with_tokio`] so the firmware's
    /// internal worker pool runs on the same threads.
    rt: Runtime,

    /// The single in-process firmware instance.
    hsm: Arc<StdHsm>,
}

impl EmuCtx {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .thread_name("azihsm-emu")
            .build()
            .expect("azihsm_ddi_emu: failed to build tokio runtime");

        let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));

        Self { rt, hsm }
    }
}

/// Lifecycle state of the process-global emulator context.
///
/// Kept as an explicit state machine (rather than folding all "no live
/// `EmuCtx`" cases into a single `None`) so [`with_ctx`] and
/// [`DdiEmu::shutdown`] can each tell apart "never initialised" (safe to
/// lazily create), "a shutdown join is in progress on another thread"
/// (must wait, not race ahead), and "fully released" (must reject, since
/// the underlying `StdHsm` core cannot be re-initialised) — see [`CTX`].
enum CtxState {
    /// No device has ever been opened.
    Uninitialized,
    /// A live `EmuCtx` exists and may be used.
    Running(EmuCtx),
    /// A [`DdiEmu::shutdown`] call has taken the `EmuCtx` out to run its
    /// (potentially slow) blocking join outside the lock; the slot is
    /// temporarily empty until that call either restores `Running` (live
    /// handles remained) or transitions to `ShutDown` (join completed).
    ShuttingDown,
    /// [`DdiEmu::shutdown`] has fully released the context. Permanent:
    /// the underlying `StdHsm` core is a process-global singleton that
    /// cannot be re-initialised.
    ShutDown,
}

/// Global emulator context, lazily initialised on first access and
/// released by [`DdiEmu::shutdown`].
///
/// Held behind a mutex+condvar (rather than a [`std::sync::LazyLock`])
/// so that [`DdiEmu::shutdown`] can take ownership of the `EmuCtx` out of
/// the slot: without an explicit release, the last `Arc<StdHsm>`
/// reference would never drop for the life of the process, so
/// `StdHsm`'s Embassy and Tokio background threads would never stop —
/// reproducing the hypervisor shutdown hang this crate exists to avoid.
/// If live `DdiEmuDev` handles remain when `shutdown` is called, the
/// context is put back rather than released, so a later retry can still
/// complete it — see [`shutdown`](DdiEmu::shutdown). Once a call *does*
/// release it, [`CtxState::ShutDown`] is permanent: the underlying
/// `StdHsm` core is a process-global singleton (see above) that cannot
/// be re-initialised, so [`open_dev`](Ddi::open_dev) must not be called
/// again afterwards.
static CTX: Mutex<CtxState> = Mutex::new(CtxState::Uninitialized);

/// Signalled whenever [`CTX`]'s state changes, so callers blocked behind
/// an in-progress [`CtxState::ShuttingDown`] wake up and re-check it
/// instead of racing ahead on a stale, temporarily-empty slot.
static CTX_CHANGED: Condvar = Condvar::new();

/// Test-only rendezvous point, fired immediately before a caller blocks
/// on [`CTX_CHANGED`] while still holding the [`CTX`] lock. Lets tests
/// deterministically wait for a concurrent caller to actually reach the
/// wait point (and thus be registered to receive the next notification)
/// instead of racing it with a sleep — since [`CTX`] is still locked at
/// that point, a test that subsequently takes the lock itself is
/// guaranteed to only succeed once the waiter has called
/// [`Condvar::wait`], never before. A no-op outside tests.
#[cfg(test)]
static WAIT_HOOK: Mutex<Option<Arc<std::sync::Barrier>>> = Mutex::new(None);

#[cfg(test)]
fn on_about_to_wait_for_ctx_change() {
    if let Some(barrier) = WAIT_HOOK.lock().clone() {
        barrier.wait();
    }
}

#[cfg(not(test))]
fn on_about_to_wait_for_ctx_change() {}

/// Blocks on [`CTX_CHANGED`] while holding `guard`, firing the
/// test-only [`on_about_to_wait_for_ctx_change`] hook immediately
/// beforehand.
fn wait_for_ctx_change(guard: &mut parking_lot::MutexGuard<'_, CtxState>) {
    on_about_to_wait_for_ctx_change();
    CTX_CHANGED.wait(guard);
}

/// Runs `f` with a reference to the global emulator context, creating it
/// on first use.
///
/// If a concurrent [`DdiEmu::shutdown`] join is in progress, waits for it
/// to settle (either restoring the context or fully releasing it) rather
/// than racing ahead on a temporarily-empty slot.
///
/// Returns [`DdiError::DeviceNotReady`] if called after a
/// [`DdiEmu::shutdown`] call has fully released the context; see
/// [`CTX`]. This is a normal, expected outcome of the `open_dev`/
/// `shutdown` teardown race (a concurrent `open_dev` can lose the race
/// and observe `ShutDown` right after it settles), so it must be
/// reported through [`DdiResult`] rather than panicking.
fn with_ctx<T>(f: impl FnOnce(&EmuCtx) -> T) -> DdiResult<T> {
    let mut guard = CTX.lock();
    loop {
        match &*guard {
            CtxState::Running(_) => break,
            CtxState::Uninitialized => {
                *guard = CtxState::Running(EmuCtx::new());
                break;
            }
            CtxState::ShuttingDown => wait_for_ctx_change(&mut guard),
            CtxState::ShutDown => return Err(DdiError::DeviceNotReady),
        }
    }
    let CtxState::Running(ctx) = &*guard else {
        unreachable!("loop above only exits with CtxState::Running")
    };
    Ok(f(ctx))
}

/// DDI Implementation - AZIHSM Emulator interface.
///
/// Implements [`Ddi`] for the in-process firmware emulator. Constructing
/// a `DdiEmu` is a no-op; the underlying [`StdHsm`] is initialised on
/// the first call to [`open_dev`](Ddi::open_dev).
#[derive(Default, Debug)]
pub struct DdiEmu {}

impl DdiEmu {
    /// Releases the process-global emulator context, allowing its
    /// `StdHsm`'s Embassy and Tokio background threads to stop.
    ///
    /// Must be called by the embedding host (e.g. a hypervisor) during
    /// its own shutdown, once every [`DdiEmuDev`] obtained via
    /// [`open_dev`](Ddi::open_dev) has already been dropped — closing
    /// the last outstanding device handle drops the last other
    /// reference to the shared `Arc<StdHsm>`, letting this call take
    /// sole ownership and actually join the background threads via
    /// [`StdHsm::shutdown`].
    ///
    /// If device handles are still alive, this call is a no-op that
    /// leaves the context in place (rather than releasing it
    /// irreversibly): callers should drop all `DdiEmuDev`s and call
    /// [`shutdown`](Self::shutdown) again, which then completes
    /// normally. Retrying is important — there is no other way to stop
    /// the background threads once this call has released the context,
    /// so silently discarding it here would leak them permanently and
    /// reintroduce the hang this crate exists to avoid.
    ///
    /// A no-op if the context was never initialised (no device was ever
    /// opened) or has already been fully released by a prior call. If
    /// another call's join is already in progress on another thread,
    /// this call waits for it to settle before deciding whether to join
    /// itself, retry, or return, instead of racing ahead on a
    /// temporarily-empty slot and returning early as if it had completed
    /// a shutdown it never actually performed.
    ///
    /// After a call that *does* release the context, no `DdiEmu` in
    /// this process may open a new device: the underlying firmware core
    /// is a process-global singleton that cannot be re-initialised (see
    /// [`CTX`]).
    ///
    /// Must not be called from a worker thread of the emulator's own
    /// tokio runtime — see [`StdHsm::shutdown`].
    pub fn shutdown() {
        let mut guard = CTX.lock();
        let (rt, hsm) = loop {
            match &mut *guard {
                CtxState::Uninitialized | CtxState::ShutDown => return,
                CtxState::ShuttingDown => wait_for_ctx_change(&mut guard),
                CtxState::Running(_) => {
                    let CtxState::Running(EmuCtx { rt, hsm }) =
                        std::mem::replace(&mut *guard, CtxState::ShuttingDown)
                    else {
                        unreachable!("just matched CtxState::Running");
                    };
                    break (rt, hsm);
                }
            }
        };

        match Arc::try_unwrap(hsm) {
            Ok(hsm) => {
                // Release the lock before the blocking join below: nothing
                // else needs `CTX` while `shutdown` drains, and holding a
                // mutex across it would needlessly block any concurrent
                // `open_dev`/`shutdown` caller. They instead see (and wait
                // on) the explicit `ShuttingDown` state set above, rather
                // than a plain empty slot that would make `open_dev` try
                // to reinitialise `EmuCtx` (which panics — `StdHsm` can
                // only ever be built once) or make a concurrent `shutdown`
                // return early as if it had completed this join itself.
                drop(guard);
                hsm.shutdown();
                let mut guard = CTX.lock();
                *guard = CtxState::ShutDown;
                CTX_CHANGED.notify_all();
            }
            Err(hsm) => {
                tracing::warn!(
                    refs = Arc::strong_count(&hsm),
                    "azihsm_ddi_emu: shutdown called with live DdiEmuDev handles \
                     outstanding; leaving the context in place so a later \
                     shutdown() call (after they are all dropped) can complete"
                );
                // Put the context back rather than releasing `rt`/`hsm`:
                // dropping `rt` here would be unsound (other `Arc<StdHsm>`
                // clones still need it), but discarding it without dropping
                // it (e.g. via `mem::forget`) would leak it irrecoverably —
                // no future call could ever join it, permanently
                // reintroducing the hang this crate exists to avoid.
                *guard = CtxState::Running(EmuCtx { rt, hsm });
                CTX_CHANGED.notify_all();
            }
        }
    }
}

impl Ddi for DdiEmu {
    type Dev = DdiEmuDev;

    /// Returns a single virtual device entry for the emulator.
    ///
    /// The returned [`DevInfo`] always uses [`EMU_DEVICE_PATH`].
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let devs = vec![DevInfo {
            path: EMU_DEVICE_PATH.to_owned(),
            driver_ver: env!("CARGO_PKG_VERSION").to_owned(),
            firmware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            pci_info: String::from("0.0.0"),
            entropy_data: vec![0u8; 32],
        }];

        tracing::debug!(size = devs.len(), "Got DdiEmu device info list");
        devs
    }

    /// Open the emulator device.
    ///
    /// `path` must equal [`EMU_DEVICE_PATH`]; any other value yields
    /// [`DdiError::DeviceNotFound`](azihsm_ddi_interface::DdiError::DeviceNotFound).
    /// Returns [`DdiError::DeviceNotReady`] if [`DdiEmu::shutdown`] has
    /// already fully released the process-global context (the
    /// underlying `StdHsm` core is a singleton that cannot be
    /// re-initialised).
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let (hsm, handle) = with_ctx(|ctx| (ctx.hsm.clone(), ctx.rt.handle().clone()))?;
        DdiEmuDev::open(hsm, handle, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_info_list_returns_emu_device() {
        let ddi = DdiEmu::default();
        let devs = ddi.dev_info_list();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].path, EMU_DEVICE_PATH);
    }

    #[test]
    fn open_unknown_path_fails() {
        let ddi = DdiEmu::default();
        let res = ddi.open_dev("/dev/nonexistent");
        assert!(res.is_err(), "opening unknown path must fail");
    }

    #[test]
    fn shutdown_without_open_dev_is_a_no_op() {
        // Must not panic even though the context was never initialised.
        DdiEmu::shutdown();
    }

    #[test]
    fn shutdown_releases_context_once_handles_are_dropped() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open_dev");
        drop(dev);

        // Sole reference: this joins the Embassy/Tokio background
        // threads instead of leaking the runtime.
        DdiEmu::shutdown();

        // Idempotent: calling again after release is still a no-op.
        DdiEmu::shutdown();
    }

    #[test]
    fn open_dev_after_shutdown_returns_device_not_ready_instead_of_panicking() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open_dev");
        drop(dev);
        DdiEmu::shutdown();

        // Once `CtxState::ShutDown` is permanent, `open_dev` must report
        // it through `DdiResult` instead of panicking/aborting — a
        // concurrent `open_dev` that loses the race with a real
        // `shutdown()` can observe exactly this state.
        let res = ddi.open_dev(EMU_DEVICE_PATH);
        assert!(
            matches!(res, Err(azihsm_ddi_interface::DdiError::DeviceNotReady)),
            "expected DeviceNotReady, got {res:?}"
        );
    }

    #[test]
    fn shutdown_with_live_handle_is_retryable() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open_dev");

        // A live handle still holds an `Arc<StdHsm>` clone, so this is a
        // no-op that leaves the context in place rather than releasing
        // or leaking it.
        DdiEmu::shutdown();

        // Dropping the last handle and retrying now succeeds: the
        // context was preserved, not lost.
        drop(dev);
        DdiEmu::shutdown();

        // Idempotent: calling again after release is still a no-op.
        DdiEmu::shutdown();
    }

    #[test]
    fn shutdown_call_waits_for_an_in_progress_shutdown_to_settle() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open_dev");
        drop(dev);

        // Starting two real `shutdown()` calls back-to-back doesn't
        // reliably exercise the `ShuttingDown`/condvar-wait branch: the
        // real join is fast enough that the first call can settle to
        // `ShutDown` before the second thread even runs, so it would
        // just see `ShutDown` directly instead of waiting. Instead,
        // deterministically simulate a join already being in progress by
        // taking the `EmuCtx` out and setting `ShuttingDown` directly —
        // exactly the state `shutdown()` leaves `CTX` in right before its
        // own unlocked, potentially slow `hsm.shutdown()` join.
        let (rt, hsm) = {
            let mut guard = CTX.lock();
            match std::mem::replace(&mut *guard, CtxState::ShuttingDown) {
                CtxState::Running(EmuCtx { rt, hsm }) => (rt, hsm),
                _ => panic!("expected CtxState::Running after open_dev"),
            }
        };

        // Deterministically wait for the waiter thread below to reach
        // its `wait_for_ctx_change` call (i.e. to be registered on
        // `CTX_CHANGED` and waiting) before settling the state: a fixed
        // sleep here would be racy (if the waiter isn't scheduled in
        // time, this thread could set `ShutDown` and notify before the
        // waiter ever calls `Condvar::wait`, so it would just observe
        // `ShutDown` directly and return without exercising the wait
        // path at all — the test would still pass without covering it).
        // `barrier.wait()` below only unblocks once the waiter's hook
        // fires *while it still holds the `CTX` lock*, so this thread's
        // subsequent `CTX.lock()` is guaranteed to block until the
        // waiter actually calls `Condvar::wait` (which atomically
        // releases the lock as it registers to be woken) — no lost
        // wakeup is possible.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *WAIT_HOOK.lock() = Some(barrier.clone());

        // A concurrent `shutdown()` call must wait on the condvar
        // instead of seeing the (currently `ShuttingDown`, not
        // empty/`Uninitialized`) slot and returning early as if it had
        // completed a shutdown it never performed.
        let waiter = std::thread::spawn(DdiEmu::shutdown);

        barrier.wait();
        *WAIT_HOOK.lock() = None;

        // Settle the state exactly as the real success path would, then
        // wake the waiter.
        *CTX.lock() = CtxState::ShutDown;
        CTX_CHANGED.notify_all();

        waiter.join().expect("waiting shutdown() call panicked");

        // Actually release the resources this test borrowed from `CTX`,
        // as the real success path would have.
        let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));
        hsm.shutdown();
        drop(rt);
    }
}
