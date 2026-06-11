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
//! 3. Factory-resets the device under `feature = "emu"` so every
//!    test starts from byte-identical state — no inherited session
//!    slots, no inherited PSK rotations, no implicit ordering
//!    dependency on other tests' cleanup discipline.
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
#[cfg(feature = "emu")]
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
    // the side-effect of locking".
    _guard: MutexGuard<'static, ()>,
}

impl Deref for TestDev {
    type Target = <AzihsmDdi as Ddi>::Dev;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}

/// Acquire the test lock, open the configured backend device, and
/// (under `feature = "emu"`) factory-reset it. See module docs.
///
/// Panics if the backend lists no devices or if `erase` fails — both
/// are backend bugs, not test bugs, and surfacing them immediately
/// is preferable to running a test against a dirty device.
pub fn open_dev() -> TestDev {
    let guard = TEST_LOCK.lock();
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("backend should advertise a device");
    let dev = ddi.open_dev(&info.path).expect("open test backend device");
    #[cfg(feature = "emu")]
    dev.erase()
        .expect("open_dev: factory-reset emu backend before test");
    TestDev { dev, _guard: guard }
}
