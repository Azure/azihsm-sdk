// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend setup + canonical fixture constants shared by every TBOR
//! integration test.
//!
//! Calling [`open_dev`] does three things, in order:
//!
//! 1. Acquires the process-global `TEST_LOCK` (held for the
//!    returned handle's lifetime). The `StdHsm` is a single shared
//!    instance for the whole test binary, so any in-flight FW work
//!    from another test would be corrupted by this one's `erase`.
//! 2. Opens the device advertised by the configured backend
//!    (`emu` or `mock`).
//! 3. Factory-resets the device on every backend that owns partition
//!    state (all but `mock`) so every test starts from byte-identical
//!    state — no inherited session slots, no inherited PSK rotations,
//!    no implicit ordering dependency on other tests' cleanup
//!    discipline.
//!
//! Tests therefore become self-contained by construction. The
//! returned [`TestDev`] wraps the backend handle in a type that
//! `Deref`s to the underlying `<AzihsmDdi as Ddi>::Dev`, so existing
//! call sites (`let dev = open_dev(); helper(&dev, ...)`) keep
//! compiling without modification — deref coercion supplies the
//! `&<Dev>` automatically.

use std::ops::Deref;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
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
/// cleanly and `open_dev`'s `erase` puts the FW back to a known state.
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Owned wrapper around an opened backend device that holds the
/// process-global test lock for its lifetime.
///
/// Derefs to `<AzihsmDdi as Ddi>::Dev` so call sites that previously
/// took `&<AzihsmDdi as Ddi>::Dev` keep compiling unchanged.
pub struct TestDev {
    dev: <AzihsmDdi as Ddi>::Dev,
    // Lifetime parameter is `'static` because `TEST_LOCK` is
    // `static`. Underscore-prefixed to mark it as "held purely for
    // the side-effect of locking". `None` on secondary handles opened
    // on the same path as a primary that already holds the lock —
    // taking it a second time would deadlock the test.
    _guard: Option<MutexGuard<'static, ()>>,
    /// Backend `DevInfo::path` this handle was opened on. Cached so
    /// multi-fd tests can bind extra `TestDev`s to the *same*
    /// underlying device via [`TestCtx::new_with_path`](crate::harness::TestCtx::new_with_path).
    path: String,
}

impl TestDev {
    /// The backend path this device was opened on.
    pub fn path(&self) -> &str {
        &self.path
    }
}

// SAFETY: The only `!Send` field on `TestDev` is
// `_guard: Option<MutexGuard<'static, ()>>`. The lock protects a
// unit `()` and is never dereferenced — the guard exists purely to
// serialise tests. Secondary `TestDev` handles (returned by
// `open_dev_secondary`) always have `_guard: None`. Sending the
// primary is safe as long as `TestDev` is not moved off the thread
// that acquired the lock until the guard drops; in practice only
// secondaries (with `_guard: None`) are sent into `thread::scope`
// worker threads, and rustc cannot prove that at compile time
// because both variants share the same type.
#[allow(unsafe_code)]
unsafe impl Send for TestDev {}

impl Deref for TestDev {
    type Target = <AzihsmDdi as Ddi>::Dev;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}

/// Acquire the test lock, open the configured backend device, and
/// factory-reset it before use. Only reachable under `--features emu`
/// or the no-feature (hw) build — mock/sock builds gate the whole
/// harness out at the crate root.
///
/// Panics if the backend lists no devices or if `erase` fails — both
/// are backend bugs, not test bugs, and surfacing them immediately
/// is preferable to running a test against a dirty device.
pub fn open_dev() -> TestDev {
    let guard = TEST_LOCK.lock();
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("backend should advertise a device");
    let path = info.path.clone();
    let dev = ddi.open_dev(&path).expect("open test backend device");
    dev.erase()
        .expect("open_dev: factory-reset backend before test");
    TestDev {
        dev,
        _guard: Some(guard),
        path,
    }
}

/// Open a secondary [`TestDev`] on the same backend path as the
/// primary [`TestDev`] already alive in this test.
///
/// Does not acquire `TEST_LOCK` — the primary already holds it, and
/// `parking_lot::Mutex` is not reentrant, so a second acquisition on
/// this thread would deadlock. Also skips `erase`: the primary owns
/// the device state, and wiping it mid-test would break both handles.
///
/// Used by multi-fd tests whose semantics require overlapping
/// sessions on distinct fds — on hw the driver enforces
/// `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so the second concurrent session
/// must live on its own handle.
///
/// Caller must ensure the primary [`TestDev`] outlives every
/// secondary, otherwise the lock guard drops mid-test.
pub(crate) fn open_dev_secondary(path: &str) -> TestDev {
    let dev = AzihsmDdi::default()
        .open_dev(path)
        .expect("open secondary backend device on the same path as the primary TestDev");
    TestDev {
        dev,
        _guard: None,
        path: path.to_string(),
    }
}
