// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HwCtx`] — hardware-backend twin of [`crate::harness::ctx::TestCtx`].
//!
//! Same method surface as `TestCtx` so every `commands/*` test can be
//! written once and pick a backend via the `Ctx` type alias exported
//! from [`crate::harness`]. The differences are all in the lifecycle:
//!
//! * **Setup:** acquires the process-global test lock, opens the
//!   native OS backend (`DdiNix` / `DdiWin`) selected at compile time
//!   by [`AzihsmDdi::default()`], and issues NSSR / factory-reset via
//!   [`DdiDev::erase`] so the partition starts at pristine defaults.
//! * **Teardown:** [`Drop`] issues a best-effort NSSR so a panicking
//!   test still leaves the device clean for the next one. Errors are
//!   swallowed — a wedged device that rejects `erase` during unwind
//!   must not double-panic.
//!
//! Gated behind `feature = "hw-tests"`. Only compiled when the test
//! binary is built against a real silicon backend.

use std::ops::Deref;

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborApiRevResp;
use azihsm_ddi_tbor_types::TborOpReq;
use azihsm_ddi_tbor_types::TborPartFinalResp;
use azihsm_ddi_tbor_types::TborPartInitResp;
use azihsm_ddi_tbor_types::TborStatus;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

use crate::harness::api_rev::helper_api_rev_tbor;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::assertions::assert_tbor_decode_error;
use crate::harness::session::part_final as part_final_helper;
use crate::harness::session::part_init as part_init_helper;
use crate::harness::session::psk_change as psk_change_helper;
use crate::harness::session::session_close as session_close_helper;
use crate::harness::session::session_open_finish as session_open_finish_helper;
use crate::harness::session::session_open_finish_with_mac as session_open_finish_with_mac_helper;
use crate::harness::session::session_open_init as session_open_init_helper;
use crate::harness::session::session_open_init_with_options as session_open_init_with_options_helper;
use crate::harness::session::PendingHandshake;
use crate::harness::session::SessionHandshake;
use crate::harness::session::SessionOpenInitOptions;

/// Fixed default 48-byte SATA thumbprint used by the convenience
/// [`HwCtx::part_init`] wrapper.
const DEFAULT_SATA_THUMBPRINT: [u8; 48] = [0x5A; 48];

/// Process-global serialisation lock. A single physical device is
/// shared by every `#[test]` in the binary; the lock keeps parallel
/// nextest workers from stomping on each other. `parking_lot` per the
/// workspace convention (std lock is banned in clippy.toml).
static HW_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Native OS backend device handle, compile-time-selected by
/// [`AzihsmDdi::default()`] to [`azihsm_ddi_nix::DdiNix`] on Linux and
/// [`azihsm_ddi_win::DdiWin`] on Windows.
type HwDev = <AzihsmDdi as Ddi>::Dev;

/// Owned wrapper around an opened hw device that holds the
/// process-global test lock for its lifetime.
struct HwTestDev {
    dev: HwDev,
    _guard: MutexGuard<'static, ()>,
}

impl Deref for HwTestDev {
    type Target = HwDev;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}

/// Acquire the hw test lock, open the native backend device, and
/// NSSR-reset it so the test starts at pristine defaults.
///
/// Panics if the backend advertises no devices or if NSSR-on-entry
/// fails — both are environment bugs (no device plugged in, or a
/// wedged partition) and running a test against a dirty device would
/// produce a misleading failure downstream.
fn open_hw_dev() -> HwTestDev {
    let guard = HW_TEST_LOCK.lock();
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("hw backend advertises no device");
    let dev = ddi.open_dev(&info.path).expect("open hw backend device");
    dev.erase().expect("open_hw_dev: NSSR must succeed before test");
    HwTestDev { dev, _guard: guard }
}

/// One-test fixture for the hw backend. Mirrors [`TestCtx`] method-for-method.
///
/// [`TestCtx`]: crate::harness::ctx::TestCtx
pub struct HwCtx {
    dev: HwTestDev,
}

impl HwCtx {
    /// Open the hw device via [`open_hw_dev`].
    pub fn new() -> Self {
        Self { dev: open_hw_dev() }
    }

    /// NSSR / factory-reset the partition. Same call `TestCtx::erase`
    /// makes on emu; the trait method [`DdiDev::erase`] resolves to
    /// NSSR on the native backend.
    pub fn erase(&self) -> DdiResult<()> {
        self.dev.erase()
    }

    pub fn tbor<R: TborOpReq>(&self, req: &R) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.dev.exec_op_tbor(req, None, &mut cookie)
    }

    pub fn tbor_oob<R: TborOpReq>(&self, req: &R, oob_items: &[&[u8]]) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.dev.exec_op_tbor(req, Some(oob_items), &mut cookie)
    }

    #[track_caller]
    pub fn expect_fw_reject<R: TborOpReq>(&self, req: &R, expected: TborStatus) -> DdiError
    where
        R::OpResp: core::fmt::Debug,
    {
        match self.tbor(req) {
            Ok(resp) => panic!(
                "expected FW reject {expected:?} (0x{:08X}), got Ok({resp:?})",
                expected.0,
            ),
            Err(err) => {
                assert_fw_rejects(&err, expected);
                err
            }
        }
    }

    #[track_caller]
    pub fn expect_fw_reject_oob<R: TborOpReq>(
        &self,
        req: &R,
        oob_items: &[&[u8]],
        expected: TborStatus,
    ) -> DdiError
    where
        R::OpResp: core::fmt::Debug,
    {
        match self.tbor_oob(req, oob_items) {
            Ok(_resp) => panic!(
                "expected FW reject {expected:?} (0x{:08X}), got unexpected success",
                expected.0,
            ),
            Err(err) => {
                assert_fw_rejects(&err, expected);
                err
            }
        }
    }

    #[track_caller]
    pub fn expect_decode_error<R: TborOpReq>(&self, req: &R) -> DdiError
    where
        R::OpResp: core::fmt::Debug,
    {
        match self.tbor(req) {
            Ok(resp) => panic!("expected DdiError::TborDecodeError, got Ok({resp:?})"),
            Err(err) => {
                assert_tbor_decode_error(&err);
                err
            }
        }
    }

    pub fn session_open_init(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<PendingHandshake> {
        session_open_init_helper(&self.dev, psk_id, session_type)
    }

    pub fn session_open_init_with_options(
        &self,
        opts: SessionOpenInitOptions<'_>,
    ) -> DdiResult<PendingHandshake> {
        session_open_init_with_options_helper(&self.dev, opts)
    }

    pub fn session_open_finish(&self, pending: PendingHandshake) -> DdiResult<SessionHandshake> {
        session_open_finish_helper(&self.dev, pending)
    }

    pub fn session_open_finish_with_mac(
        &self,
        pending: PendingHandshake,
        mac_fin: [u8; 48],
    ) -> DdiResult<SessionHandshake> {
        session_open_finish_with_mac_helper(&self.dev, pending, mac_fin)
    }

    pub fn open_session_raw(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<SessionHandshake> {
        let pending = self.session_open_init(psk_id, session_type)?;
        self.session_open_finish(pending)
    }

    pub fn session_close(&self, session_id: u16) -> DdiResult<()> {
        session_close_helper(&self.dev, session_id)
    }

    pub fn psk_change(&self, session: &SessionHandshake, new_psk: &[u8]) -> DdiResult<()> {
        psk_change_helper(&self.dev, session, new_psk)
    }

    pub fn part_init(
        &self,
        session: &SessionHandshake,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
    ) -> DdiResult<TborPartInitResp> {
        part_init_helper(
            &self.dev,
            session,
            mach_seed,
            part_policy,
            pota_thumbprint,
            &DEFAULT_SATA_THUMBPRINT,
            None,
        )
    }

    pub fn part_init_sd(
        &self,
        session: &SessionHandshake,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
        sata_thumbprint: &[u8],
        sapota_thumbprint: Option<&[u8]>,
    ) -> DdiResult<TborPartInitResp> {
        part_init_helper(
            &self.dev,
            session,
            mach_seed,
            part_policy,
            pota_thumbprint,
            sata_thumbprint,
            sapota_thumbprint,
        )
    }

    pub fn part_final(
        &self,
        session: &SessionHandshake,
        part_policy: &[u8],
        prev_local_mk_backup: &[u8],
        certs: &[&[u8]],
    ) -> DdiResult<TborPartFinalResp> {
        part_final_helper(&self.dev, session, part_policy, prev_local_mk_backup, certs)
    }

    pub fn api_rev(&self) -> DdiResult<TborApiRevResp> {
        helper_api_rev_tbor(&self.dev)
    }
}

/// Best-effort NSSR so a panicking test still hands the next test a
/// clean device. Errors are intentionally swallowed — a wedged
/// device that rejects `erase` during unwind must not double-panic.
impl Drop for HwCtx {
    fn drop(&mut self) {
        let _ = self.dev.erase();
    }
}
