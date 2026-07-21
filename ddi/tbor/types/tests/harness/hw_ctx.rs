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

use std::collections::HashMap;
use std::sync::Arc;

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

/// Acquire the hw test lock, open the native backend device, and
/// NSSR-reset it so the test starts at pristine defaults. Returns
/// the lock guard alongside the primary fd (both must live for the
/// full `HwCtx` lifetime).
///
/// Panics if the backend advertises no devices or if NSSR-on-entry
/// fails — both are environment bugs (no device plugged in, or a
/// wedged partition) and running a test against a dirty device would
/// produce a misleading failure downstream.
fn open_hw_dev() -> (HwDev, MutexGuard<'static, ()>) {
    let guard = HW_TEST_LOCK.lock();
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("hw backend advertises no device");
    let dev = ddi.open_dev(&info.path).expect("open hw backend device");
    dev.erase()
        .expect("open_hw_dev: NSSR must succeed before test");
    (dev, guard)
}

/// Open an *additional* fd on the same physical device, without
/// re-acquiring [`HW_TEST_LOCK`] and without issuing NSSR. Used when
/// a test needs a second (third, …) concurrent session — the Linux
/// kernel driver enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so every
/// concurrent session past the first sits on its own fd.
///
/// Takes `&HwDev` purely to borrow the primary fd's lifetime — the
/// caller must already hold the process-global lock via that fd for
/// the returned fd to be safe to use.
fn open_extra_hw_dev(_lock_holder: &HwDev) -> HwDev {
    let ddi = AzihsmDdi::default();
    let infos = ddi.dev_info_list();
    let info = infos.first().expect("hw backend advertises no device");
    ddi.open_dev(&info.path).expect("open extra hw fd")
}

/// One-test fixture for the hw backend. Mirrors [`TestCtx`] method-for-method.
///
/// Every session opened on this ctx lands in [`Self::sessions`] keyed
/// by its FW-assigned id, and every session-scoped op looks up the
/// owning fd via the map — so callers can treat `HwCtx` exactly like
/// `TestCtx`.
///
/// Fd placement policy: the first live session lives on the primary
/// fd (`primary`, the same fd that acquired [`HW_TEST_LOCK`] and did
/// NSSR at construction). This matches the pattern the hw test suite
/// relied on before the merge — driver behaviour with sessions on
/// only-extra fds (leaving primary idle) has proven fragile. When
/// primary already carries a live session, additional concurrent
/// sessions get their own fresh fds via [`open_extra_hw_dev`].
/// Routing is always via [`Self::sessions`] — nothing session-scoped
/// ever bypasses it and targets `primary` directly.
///
/// [`TestCtx`]: crate::harness::ctx::TestCtx
pub struct HwCtx {
    primary: Arc<HwDev>,
    _guard: MutexGuard<'static, ()>,
    /// `true` while `primary` currently owns a live session. Cleared
    /// when that session's entry is removed from `sessions`.
    primary_busy: Mutex<bool>,
    /// Fds waiting for a matching finish to promote them into
    /// [`Self::sessions`], keyed by the FW-assigned session id that
    /// [`Self::session_open_init`] returned. Keying by id (rather
    /// than a single slot) lets concurrent handshakes coexist. Each
    /// value is the same `Arc` as either `primary` (when we grabbed
    /// primary) or a fresh fd (when primary was busy).
    pending_fds: Mutex<HashMap<u16, Arc<HwDev>>>,
    /// Every live session, keyed by FW-assigned session id. Value is
    /// the `Arc` for the fd that owns that session — same `Arc` as
    /// `primary` or a fresh fd.
    sessions: Mutex<HashMap<u16, Arc<HwDev>>>,
}

impl HwCtx {
    /// Acquire the hw test lock, open the primary fd, NSSR, and set
    /// up empty session tracking.
    pub fn new() -> Self {
        let (dev, guard) = open_hw_dev();
        Self {
            primary: Arc::new(dev),
            _guard: guard,
            primary_busy: Mutex::new(false),
            pending_fds: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// NSSR / factory-reset the partition. Same call `TestCtx::erase`
    /// makes on emu; the trait method [`DdiDev::erase`] resolves to
    /// NSSR on the native backend.
    pub fn erase(&self) -> DdiResult<()> {
        self.primary.erase()
    }

    /// Look up the fd that owns `session_id`, or return `None` for
    /// unknown ids (negative-path tests exercising invalid ids, or
    /// ids from a session that's already been closed).
    fn dev_for_session(&self, session_id: u16) -> Option<Arc<HwDev>> {
        self.sessions.lock().get(&session_id).cloned()
    }

    /// Pick the fd for a fresh handshake: primary if free, else a
    /// brand-new extra fd. Also flips `primary_busy` if we took
    /// primary — the caller must roll that back on error and
    /// [`Self::session_close`] must clear it on close.
    fn take_fd_for_new_session(&self) -> (Arc<HwDev>, bool) {
        let mut busy = self.primary_busy.lock();
        if !*busy {
            *busy = true;
            (Arc::clone(&self.primary), true)
        } else {
            (Arc::new(open_extra_hw_dev(&self.primary)), false)
        }
    }

    pub fn tbor<R: TborOpReq>(&self, req: &R) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.primary.exec_op_tbor(req, None, &mut cookie)
    }

    pub fn tbor_oob<R: TborOpReq>(&self, req: &R, oob_items: &[&[u8]]) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.primary.exec_op_tbor(req, Some(oob_items), &mut cookie)
    }

    /// Session-scoped raw tbor exec: routes the op via the fd that
    /// owns `session_id`, so requests referring to a specific session
    /// (`TborPskChangeReq`, `TborPartInitReq`, …) reach the kernel
    /// driver on the correct fd. Falls back to `primary` for unknown
    /// ids — lets negative-path tests exercise "bogus session id"
    /// paths without special-casing.
    pub fn tbor_on_session<R: TborOpReq>(&self, session_id: u16, req: &R) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        match self.dev_for_session(session_id) {
            Some(dev) => dev.exec_op_tbor(req, None, &mut cookie),
            None => self.primary.exec_op_tbor(req, None, &mut cookie),
        }
    }

    /// Session-scoped OOB variant of [`Self::tbor_on_session`].
    pub fn tbor_oob_on_session<R: TborOpReq>(
        &self,
        session_id: u16,
        req: &R,
        oob_items: &[&[u8]],
    ) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        match self.dev_for_session(session_id) {
            Some(dev) => dev.exec_op_tbor(req, Some(oob_items), &mut cookie),
            None => self.primary.exec_op_tbor(req, Some(oob_items), &mut cookie),
        }
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
    pub fn expect_fw_reject_on_session<R: TborOpReq>(
        &self,
        session_id: u16,
        req: &R,
        expected: TborStatus,
    ) -> DdiError
    where
        R::OpResp: core::fmt::Debug,
    {
        match self.tbor_on_session(session_id, req) {
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
        let (dev, took_primary) = self.take_fd_for_new_session();
        match session_open_init_helper(&dev, psk_id, session_type) {
            Ok(pending) => {
                self.pending_fds.lock().insert(pending.session_id, dev);
                Ok(pending)
            }
            Err(e) => {
                if took_primary {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
    }

    pub fn session_open_init_with_options(
        &self,
        opts: SessionOpenInitOptions<'_>,
    ) -> DdiResult<PendingHandshake> {
        let (dev, took_primary) = self.take_fd_for_new_session();
        match session_open_init_with_options_helper(&dev, opts) {
            Ok(pending) => {
                self.pending_fds.lock().insert(pending.session_id, dev);
                Ok(pending)
            }
            Err(e) => {
                if took_primary {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
    }

    pub fn session_open_finish(&self, pending: PendingHandshake) -> DdiResult<SessionHandshake> {
        let dev = self.pending_fds.lock().remove(&pending.session_id).expect(
            "session_open_finish: no pending fd for this session_id — call session_open_init first",
        );
        let is_primary = Arc::ptr_eq(&dev, &self.primary);
        match session_open_finish_helper(&dev, pending) {
            Ok(handshake) => {
                self.sessions.lock().insert(handshake.session_id, dev);
                Ok(handshake)
            }
            Err(e) => {
                if is_primary {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
    }

    pub fn session_open_finish_with_mac(
        &self,
        pending: PendingHandshake,
        mac_fin: [u8; 48],
    ) -> DdiResult<SessionHandshake> {
        let dev = self
            .pending_fds
            .lock()
            .remove(&pending.session_id)
            .expect("session_open_finish_with_mac: no pending fd for this session_id — call session_open_init first");
        let is_primary = Arc::ptr_eq(&dev, &self.primary);
        match session_open_finish_with_mac_helper(&dev, pending, mac_fin) {
            Ok(handshake) => {
                self.sessions.lock().insert(handshake.session_id, dev);
                Ok(handshake)
            }
            Err(e) => {
                if is_primary {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
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
        // Remove the entry so the owning fd drops (closing the kernel
        // handle) after the close call — unless the fd is `primary`,
        // in which case just clear the busy flag so the next session
        // can reuse it. Fall back to `primary` on unknown ids so the
        // FW/driver can surface its own error for negative-path tests.
        let entry = self.sessions.lock().remove(&session_id);
        match entry {
            Some(dev) => {
                let is_primary = Arc::ptr_eq(&dev, &self.primary);
                let res = session_close_helper(&dev, session_id);
                if is_primary {
                    *self.primary_busy.lock() = false;
                }
                drop(dev);
                res
            }
            None => session_close_helper(&self.primary, session_id),
        }
    }

    pub fn psk_change(&self, session: &SessionHandshake, new_psk: &[u8]) -> DdiResult<()> {
        match self.dev_for_session(session.session_id) {
            Some(dev) => psk_change_helper(&dev, session, new_psk),
            None => psk_change_helper(&self.primary, session, new_psk),
        }
    }

    pub fn part_init(
        &self,
        session: &SessionHandshake,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
    ) -> DdiResult<TborPartInitResp> {
        let dev = self.dev_for_session(session.session_id);
        let dev_ref: &HwDev = dev.as_deref().unwrap_or(&self.primary);
        part_init_helper(
            dev_ref,
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
        let dev = self.dev_for_session(session.session_id);
        let dev_ref: &HwDev = dev.as_deref().unwrap_or(&self.primary);
        part_init_helper(
            dev_ref,
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
        let dev = self.dev_for_session(session.session_id);
        let dev_ref: &HwDev = dev.as_deref().unwrap_or(&self.primary);
        part_final_helper(dev_ref, session, part_policy, prev_local_mk_backup, certs)
    }

    pub fn api_rev(&self) -> DdiResult<TborApiRevResp> {
        helper_api_rev_tbor(&self.primary)
    }
}

/// Panic-safe cleanup: close every session the ctx is still tracking,
/// then best-effort NSSR. Sessions **must** be closed one-by-one —
/// NSSR alone does not clear the FW session table, so relying on it
/// would leak slots into the next test.
///
/// Errors are intentionally swallowed. Drop never panics — a wedged
/// device that rejects `session_close` during unwind must not
/// double-panic, and a leaked slot surfaces loudly on the next test's
/// `session_open` anyway.
impl Drop for HwCtx {
    fn drop(&mut self) {
        // Drain the map so each fd Arc's refcount hits 0 as we finish
        // closing its session, releasing the extra kernel fds.
        let live: Vec<(u16, Arc<HwDev>)> = self.sessions.lock().drain().collect();
        for (id, dev) in live {
            if let Err(e) = session_close_helper(&dev, id) {
                eprintln!(
                    "HwCtx::drop: session_close({id}) failed: {e:?} \
                     — session may leak on the device",
                );
            }
        }
        *self.primary_busy.lock() = false;
        let _ = self.primary.erase();
    }
}
