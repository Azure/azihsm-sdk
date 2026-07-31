// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware-only TBOR smoke tests.
//!
//! Runs against the native OS backend (`azihsm_ddi_nix::DdiNix` on
//! Linux, `azihsm_ddi_win::DdiWin` on Windows) selected by
//! [`azihsm_ddi::AzihsmDdi`]. Gated behind the `hw-tests` cargo
//! feature so a plain `cargo test` on machines without a physical
//! device does not attempt to open the backend. Invoke with:
//!
//! ```text
//! cargo test --no-default-features --features hw-tests \
//!     -p azihsm_ddi_tbor_types \
//!     --test azihsm_ddi_tbor_tests hw::
//! ```
//!
//! # Why a separate module (vs. the `commands/` harness)
//!
//! * The `commands/*` tests are file-gated on
//!   `any(feature = "emu", feature = "mock", feature = "sock")` and
//!   drive the [`TestCtx`](crate::harness::TestCtx) which itself is
//!   only compiled under those features. `TestCtx::new` also relies
//!   on `dev.erase()` (an emu-only factory-reset) for cross-test
//!   isolation — real silicon cannot be reset from a test binary.
//! * Hardware tests therefore need their own thin fixture: a
//!   process-global serialisation lock so parallel `cargo test`
//!   workers don't stomp on the single physical device, plus an
//!   open-and-return helper that does **no** state-mutating setup.
//! * Keeping these under `hw::` also documents which tests are
//!   safe to run against a live board (sessionless / read-only, or
//!   with explicit end-of-test cleanup) — everything else stays
//!   confined to the emu-backed harness.
//!
//! # What belongs here
//!
//! Sessionless / read-only TBOR commands, e.g. `ApiRev`, `PartInfo`
//! before any `PartInit`. Anything that opens a session slot,
//! rotates a PSK, or mutates persistent state should either land in
//! the emu harness (with factory reset) or ship with its own
//! explicit cleanup path.

use std::ops::Deref;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

pub mod api_rev;
pub mod assertions;
pub mod default_psk_gate;
pub mod harness;
pub mod open_session;
pub mod part_info;
pub mod psk_change;
pub mod session_helper;

/// Process-global serialisation lock for hardware tests.
///
/// The single physical HSM is shared across the whole test binary, so
/// concurrent `cargo test` workers must not issue overlapping TBOR
/// commands. `parking_lot::Mutex` matches the workspace convention
/// (std's variant is disallowed by `clippy.toml`) and does not
/// poison, so a panicking test cannot wedge subsequent runs.
static HW_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Owned wrapper around an opened native-backend device that holds
/// [`HW_TEST_LOCK`] for its lifetime.
///
/// `Deref`s to `<AzihsmDdi as Ddi>::Dev` so test bodies can call
/// [`DdiDev`](azihsm_ddi_interface::DdiDev) methods
/// (`exec_op_tbor`, ...) directly on the guard.
pub(crate) struct HwDev {
    dev: <AzihsmDdi as Ddi>::Dev,
    _guard: MutexGuard<'static, ()>,
}

impl Deref for HwDev {
    type Target = <AzihsmDdi as Ddi>::Dev;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}

/// Acquire [`HW_TEST_LOCK`] and open the first device advertised by
/// the native backend.
///
/// Panics if the backend lists no devices or if `open_dev` fails —
/// both are environmental (driver not loaded, board not present),
/// not test bugs, and surfacing them immediately gives a clearer
/// signal than downstream `exec_op_tbor` failures.
pub(crate) fn open_hw_dev() -> HwDev {
    let guard = HW_TEST_LOCK.lock();
    let dev = open_backend_dev();
    HwDev { dev, _guard: guard }
}

/// Open an *additional* fd on the same physical device without
/// re-acquiring [`HW_TEST_LOCK`]. Intended for tests that need two
/// concurrent file descriptors on the same board (the Linux kernel
/// driver enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so multi-session
/// tests must span multiple fds).
///
/// The caller must already hold the lock via a live [`HwDev`], which
/// is why this helper takes `&HwDev` — it borrows the guard's
/// lifetime to statically prevent lock-free use.
pub(crate) fn open_additional_hw_dev_fd(_lock_holder: &HwDev) -> <AzihsmDdi as Ddi>::Dev {
    open_backend_dev()
}

fn open_backend_dev() -> <AzihsmDdi as Ddi>::Dev {
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos
        .first()
        .expect("hw test: backend advertised no device (driver loaded? board present?)");
    ddi.open_dev(&info.path)
        .expect("hw test: failed to open backend device")
}
