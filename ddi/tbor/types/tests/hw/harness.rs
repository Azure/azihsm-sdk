// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Setup / execute / cleanup harness for hardware tests.
//!
//! Modelled on the mbor integration-test `ddi_dev_test` helper
//! (`ddi/mbor/types/tests/integration/common.rs`) but panic-safe:
//! cleanup runs even if `execute` panics, and any panic is
//! re-raised after cleanup so the failure is still reported.
//!
//! The default cleanup is [`cleanup_nssr`], which issues NSSR /
//! factory-reset via [`DdiDev::erase`]. Combined with
//! [`setup_nssr`] on entry, each test starts and ends with the
//! partition at pristine defaults (PSKs at `DEFAULT_PSK_*`,
//! partition `Enabled`, session table empty) so tests are
//! idempotent and order-independent.

use std::panic::AssertUnwindSafe;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;

use crate::hw::open_hw_dev;

/// Backend device type shared across all hw tests.
pub type HwDevInner = <AzihsmDdi as Ddi>::Dev;

/// Run `setup` -> `execute` -> `cleanup` against a locked hw device.
///
/// The value returned by `setup` is passed by reference to `execute`
/// and moved into `cleanup`, mirroring the mbor pattern of
/// `setup -> u16 -> test -> cleanup(Some(u16))`.
///
/// `cleanup` runs even if `execute` panics; the panic is re-raised
/// after cleanup so the test still fails.
pub fn hw_test<S, T, C, U>(setup: S, execute: T, cleanup: C)
where
    S: FnOnce(&HwDevInner) -> U,
    T: FnOnce(&HwDevInner, &U),
    C: FnOnce(&HwDevInner, U),
{
    let dev = open_hw_dev();
    let state = setup(&dev);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| execute(&dev, &state)));
    cleanup(&dev, state);
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

/// Default setup: NSSR / factory-reset before the test runs so the
/// partition is guaranteed at pristine defaults regardless of any
/// prior test's state.
pub fn setup_nssr(dev: &HwDevInner) {
    dev.erase().expect("NSSR setup: dev.erase() must succeed");
}

/// Default cleanup: NSSR / factory-reset after the test. Best-effort
/// (ignores errors) so a panic in `execute` still propagates cleanly
/// even if the device is in a state that rejects `erase`.
pub fn cleanup_nssr<U>(dev: &HwDevInner, _state: U) {
    let _ = dev.erase();
}

/// Convenience wrapper: NSSR on entry, run `execute`, NSSR on exit.
/// Use for tests that don't need to thread state from setup to
/// cleanup (i.e. sessions are opened and closed inside `execute`).
pub fn hw_test_reset<T: FnOnce(&HwDevInner)>(execute: T) {
    hw_test(setup_nssr, |dev, _| execute(dev), cleanup_nssr);
}
