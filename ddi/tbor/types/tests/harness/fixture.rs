// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend setup + canonical fixture constants shared by every TBOR
//! integration test.
//!
//! The single entry point is [`open_dev_parts`], which:
//!
//! 1. Acquires the process-global [`TEST_LOCK`] (held for the
//!    returned guard's lifetime). The `StdHsm` is a single shared
//!    instance for the whole test binary, so any in-flight FW work
//!    from another test would be corrupted by this one's `erase`.
//! 2. Opens the device advertised by the configured backend
//!    (`emu` / `mock` / `sock` / native OS).
//! 3. Factory-resets the device on every backend that owns partition
//!    state (all but `mock`) so every test starts from byte-identical
//!    state — no inherited session slots, no inherited PSK rotations,
//!    no implicit ordering dependency on other tests' cleanup
//!    discipline.
//!
//! Tests never call this directly — they construct a
//! [`TestCtx`](crate::harness::ctx::TestCtx), which owns the returned
//! `Dev`, caches the `path`, and holds the lock guard for its
//! lifetime.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
#[cfg(not(feature = "mock"))]
use azihsm_ddi_interface::DdiDev;
pub use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
pub use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
pub use azihsm_ddi_tbor_types::PSK_LEN;
pub use azihsm_ddi_tbor_types::SESSION_SEED_LEN;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

/// Process-global serialisation lock — see module docs.
///
/// Uses `parking_lot::Mutex` (workspace convention; std's variant is
/// disallowed by `clippy.toml`). parking_lot's `Mutex` does not
/// poison, so a panicking test cannot cause subsequent tests to fail
/// at the lock acquisition step — the next test acquires the lock
/// cleanly and [`open_dev_parts`]'s `erase` puts the FW back to a
/// known state.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the test lock, open the configured backend device, factory-
/// reset it (on every backend that owns partition state — all but
/// `mock`), and return the raw `Dev`, the lock guard, and the
/// [`DevInfo`](azihsm_ddi_interface::DevInfo) `path` the device was
/// opened on.
///
/// The three parts are returned separately (rather than bundled in a
/// wrapper type) so [`TestCtx`](crate::harness::ctx::TestCtx) can
/// store the `Dev` alongside the cached `path` and the lock guard as
/// individual fields. The `path` is threaded into [`open_extra_dev`]
/// so every extra fd binds to the **same** underlying device as the
/// primary.
///
/// Panics if the backend lists no devices or if `erase` fails — both
/// are backend bugs, not test bugs, and surfacing them immediately
/// is preferable to running a test against a dirty device.
pub fn open_dev_parts() -> (<AzihsmDdi as Ddi>::Dev, MutexGuard<'static, ()>, String) {
    let guard = TEST_LOCK.lock();
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("backend should advertise a device");
    let path = info.path.clone();
    let dev = ddi.open_dev(&path).expect("open test backend device");
    // Factory-reset every backend that owns partition state so each
    // test starts from byte-identical defaults. `emu` resets the
    // in-process HSM, `sock` propagates a reset through the socket
    // server, and on the native OS backend the trait method resolves
    // to NSSR. `mock` has no state to reset and no `erase` handler,
    // so it is skipped.
    #[cfg(not(feature = "mock"))]
    dev.erase()
        .expect("open_dev_parts: factory-reset backend before test");
    (dev, guard, path)
}

/// Open an *additional* backend Dev on the **same underlying device**
/// as the primary, without re-acquiring [`TEST_LOCK`].
///
/// The caller passes the primary's cached `path` (captured at
/// [`open_dev_parts`] time) so we skip re-enumeration — the backend's
/// `dev_info_list()` ordering is not contractually stable across
/// calls, so a naive `list.first()` here could silently open a
/// different device on a multi-device rig.
///
/// Used when a single `#[test]` needs multiple concurrent sessions:
/// on the native OS backend the kernel driver enforces
/// `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so every concurrent session past
/// the first sits on its own fd against the same device. On
/// `emu` / `mock` / `sock` the extra handle is just another view onto
/// the process-global instance — harmless.
///
/// The caller must already hold the process-global lock via the
/// primary `Dev` (i.e. the `Dev` returned by [`open_dev_parts`]
/// and stored inside [`TestCtx`](crate::harness::ctx::TestCtx));
/// that is what makes it safe for this function to bypass
/// [`TEST_LOCK`]. Never call this without a live primary in scope.
pub fn open_extra_dev(path: &str) -> <AzihsmDdi as Ddi>::Dev {
    let ddi = AzihsmDdi::default();
    ddi.open_dev(path).expect("open extra test backend device")
}
