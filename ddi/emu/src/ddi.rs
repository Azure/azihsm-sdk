// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - AZIHSM Emulator - DDI Module.

use std::sync::Arc;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use azihsm_fw_hsm_std::StdHsm;
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

/// Global emulator context, lazily initialised on first access and
/// released by [`DdiEmu::shutdown`].
///
/// Held behind a mutex (rather than a [`std::sync::LazyLock`]) so that
/// [`DdiEmu::shutdown`] can take ownership of the `EmuCtx` out of the
/// slot: without an explicit release, the last `Arc<StdHsm>` reference
/// would never drop for the life of the process, so `StdHsm`'s Embassy
/// and Tokio background threads would never stop — reproducing the
/// hypervisor shutdown hang this crate exists to avoid. If live
/// `DdiEmuDev` handles remain when `shutdown` is called, the context is
/// put back rather than released, so a later retry can still complete
/// it — see [`shutdown`](DdiEmu::shutdown). Once a call *does* release
/// it, this slot is left `None` permanently: the underlying `StdHsm`
/// core is a process-global singleton (see above) that cannot be
/// re-initialised, so [`open_dev`](Ddi::open_dev) must not be called
/// again afterwards.
static CTX: Mutex<Option<EmuCtx>> = Mutex::new(None);

/// Runs `f` with a reference to the global emulator context, creating it
/// on first use.
///
/// Panics if called after a [`DdiEmu::shutdown`] call has fully released
/// the context; see [`CTX`].
fn with_ctx<T>(f: impl FnOnce(&EmuCtx) -> T) -> T {
    let mut guard = CTX.lock();
    let ctx = guard.get_or_insert_with(EmuCtx::new);
    f(ctx)
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
    /// opened) or has already been fully released by a prior call.
    /// After a call that *does* release the context, no `DdiEmu` in
    /// this process may open a new device: the underlying firmware core
    /// is a process-global singleton that cannot be re-initialised (see
    /// [`CTX`]).
    ///
    /// Must not be called from a worker thread of the emulator's own
    /// tokio runtime — see [`StdHsm::shutdown`].
    pub fn shutdown() {
        let mut guard = CTX.lock();
        let Some(EmuCtx { rt, hsm }) = guard.take() else {
            return;
        };

        match Arc::try_unwrap(hsm) {
            Ok(hsm) => {
                // Release the lock before the blocking join below: nothing
                // else needs `CTX` while `shutdown` drains, and holding a
                // mutex across it would needlessly block any concurrent
                // `open_dev`/`shutdown` caller (the latter would otherwise
                // see a spurious empty slot and reinitialise `EmuCtx`,
                // which panics — `StdHsm` can only ever be built once).
                drop(guard);
                hsm.shutdown();
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
                *guard = Some(EmuCtx { rt, hsm });
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
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        let (hsm, handle) = with_ctx(|ctx| (ctx.hsm.clone(), ctx.rt.handle().clone()));
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
}
