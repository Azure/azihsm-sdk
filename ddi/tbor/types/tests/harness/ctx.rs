// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`TestCtx`] — the single entry point per integration test.
//!
//! Wraps an opened backend device and offers three small primitives
//! that capture the only three outcomes a TBOR command test ever
//! cares about:
//!
//! * [`TestCtx::tbor`] — issue an `OP_TBOR` request and return the
//!   decoded response or a [`DdiError`] for the caller to inspect.
//! * [`TestCtx::expect_fw_reject`] — issue a request that *must* be
//!   rejected by the FW dispatcher with a specific [`TborStatus`],
//!   panicking with diagnostic context otherwise.
//! * [`TestCtx::expect_decode_error`] — issue a request whose response
//!   *must* fail host-side TBOR decoding, panicking otherwise.
//!
//! Test files therefore never reach for the bare `Dev` handle or the
//! `assert_*` helpers in [`crate::harness::assertions`] directly; the
//! ctx is the single funnel that future cross-cutting changes (tracing,
//! retry policy, fault injection) can hook into without touching every
//! test.
//!
//! Cross-test isolation (process-global lock + factory reset) lives
//! in [`crate::harness::fixture::open_dev`], which this type calls
//! through.
//!
//! # Multi-fd routing
//!
//! On the native OS backend the kernel driver enforces
//! `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so every concurrent session past
//! the first sits on its own fd. `TestCtx` tracks
//! `session_id → owning Dev` so session-scoped ops
//! (`session_open_finish`, `session_close`, `psk_change`, `part_init`,
//! …) reach the driver on the right fd. On emu / mock / sock the
//! extra "fds" are just extra handles onto the same in-process
//! backend — harmless, and lets the same test source run identically
//! on every backend.
//!
//! The raw device handle deliberately has **no public accessor** on
//! this type. All device interactions must flow through one of the
//! TBOR methods (`tbor`, `session_open_init`, `psk_change`, ...) or
//! the narrow non-TBOR pass-throughs (`erase`, `cert_chain_info`,
//! `get_certificate`). This forces every test path through the
//! shared assertion funnel.

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
use crate::harness::fixture::open_dev_parts;
use crate::harness::fixture::open_extra_dev;
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
/// [`TestCtx::part_init`] wrapper, whose callers don't exercise the
/// security-domain inputs.
const DEFAULT_SATA_THUMBPRINT: [u8; 48] = [0x5A; 48];

/// Backend device handle, compile-time-selected by
/// [`AzihsmDdi::default()`] — `DdiEmu` under `--features emu`,
/// `DdiSock` under `--features sock`, `DdiMock` under `--features
/// mock`, and the native `DdiNix` / `DdiWin` when no backend feature
/// is enabled.
type Dev = <AzihsmDdi as Ddi>::Dev;

/// One-test fixture: an opened backend device handle (with the
/// process-global test lock held for its lifetime) plus a thin layer
/// of error-shape assertions. Constructed once per `#[test]`.
///
/// Fd placement policy: the first live session lives on the primary
/// fd (the same fd that acquired the test lock via
/// [`open_dev_parts`]). When primary already carries a live session,
/// additional concurrent sessions get their own fresh fds via
/// [`open_extra_dev`]. Session-scoped ops always route via the
/// [`Self::sessions`] map — nothing session-scoped bypasses it and
/// targets the primary directly.
///
/// The primary fd sits behind `Arc<Dev>` (not `Arc<TestDev>`)
/// deliberately: `TestDev` bundles the `parking_lot::MutexGuard` and
/// is therefore `!Send`; wrapping it in `Arc` would make `TestCtx`
/// `!Sync`, which in turn breaks `std::thread::scope`-based tests
/// that share `&TestCtx` across threads. Keeping the guard as a
/// separate field of `TestCtx` leaves the ctx `!Send` (the guard
/// still can't cross a `Send` boundary) but `Sync`, which is what
/// `s.spawn(|| ctx.foo())` actually needs.
pub struct TestCtx {
    primary: Arc<Dev>,
    _guard: MutexGuard<'static, ()>,
    /// `true` while `primary` currently owns a live session. Cleared
    /// when that session's entry is removed from `sessions`.
    primary_busy: Mutex<bool>,
    /// Fds waiting for a matching finish to promote them into
    /// [`Self::sessions`], keyed by the FW-assigned session id that
    /// [`Self::session_open_init`] returned. Keying by id (rather
    /// than a single slot) lets concurrent handshakes coexist.
    pending_fds: Mutex<HashMap<u16, FdSlot>>,
    /// Every live session, keyed by FW-assigned session id.
    sessions: Mutex<HashMap<u16, FdSlot>>,
}

/// One entry in the session/pending map: either "the primary fd" (in
/// which case no owned handle is stored) or an extra fd opened via
/// [`open_extra_dev`]. Kept as an enum rather than a bare `Arc<Dev>`
/// so we don't have to wrap the primary [`TestDev`] in an `Arc` just
/// to satisfy the map's ownership.
enum FdSlot {
    Primary,
    Extra(Arc<Dev>),
}

impl FdSlot {
    fn is_primary(&self) -> bool {
        matches!(self, FdSlot::Primary)
    }
}

impl TestCtx {
    /// Open the backend device via [`open_dev_parts`] — see its docs
    /// for the locking + factory-reset semantics.
    pub fn new() -> Self {
        let (dev, guard) = open_dev_parts();
        Self {
            primary: Arc::new(dev),
            _guard: guard,
            primary_busy: Mutex::new(false),
            pending_fds: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Factory-reset the partition. On emu this issues the emulator's
    /// reset; on the native backend it issues NSSR. Under `--features
    /// mock` this call is unavailable (the mock backend has no state
    /// to reset).
    #[cfg(not(feature = "mock"))]
    pub fn erase(&self) -> DdiResult<()> {
        self.primary.erase()
    }

    /// Look up the fd that owns `session_id`, or return `None` for
    /// unknown ids (negative-path tests exercising invalid ids, or
    /// ids from a session that's already been closed).
    ///
    /// Callers that need a `&Dev` for a helper should use
    /// [`Self::with_session_dev`] instead so the primary borrow stays
    /// live across the call.
    fn with_session_dev<R>(&self, session_id: u16, f: impl FnOnce(&Dev) -> R) -> R {
        // Take a snapshot of the owning slot while holding the map
        // lock briefly, then release it before running `f` (which
        // may itself call back into `self` for the primary fd on
        // unknown-id fallback).
        let slot = self.sessions.lock().get(&session_id).map(|s| match s {
            FdSlot::Primary => FdSlot::Primary,
            FdSlot::Extra(arc) => FdSlot::Extra(Arc::clone(arc)),
        });
        match slot {
            Some(FdSlot::Extra(arc)) => f(&arc),
            Some(FdSlot::Primary) | None => f(&self.primary),
        }
    }

    /// Pick the fd for a fresh handshake: primary if free, else a
    /// brand-new extra fd. Also flips `primary_busy` if we took
    /// primary — the caller must roll that back on error and
    /// [`Self::session_close`] must clear it on close.
    fn take_fd_for_new_session(&self) -> FdSlot {
        let mut busy = self.primary_busy.lock();
        if !*busy {
            *busy = true;
            FdSlot::Primary
        } else {
            FdSlot::Extra(Arc::new(open_extra_dev()))
        }
    }

    /// Resolve an [`FdSlot`] snapshot down to a `&Dev` borrow. The
    /// snapshot must outlive the returned reference (it holds the
    /// `Arc` alive for the extra-fd case).
    fn dev_of<'a>(&'a self, slot: &'a FdSlot) -> &'a Dev {
        match slot {
            FdSlot::Primary => &self.primary,
            FdSlot::Extra(arc) => arc,
        }
    }

    /// Issue an `OP_TBOR` request and return the raw `DdiResult`.
    ///
    /// Use this when the test needs to inspect both `Ok` and `Err`
    /// arms itself (e.g. asserting a specific response field on
    /// success, or matching on a structural decode error variant).
    /// For the common "must reject with status X" shape, prefer
    /// [`Self::expect_fw_reject`].
    pub fn tbor<R: TborOpReq>(&self, req: &R) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.primary.exec_op_tbor(req, None, &mut cookie)
    }

    /// Issue an `OP_TBOR` request carrying out-of-band SGL items.
    ///
    /// Each slice in `oob_items` becomes one NVMe SGL Data Block
    /// descriptor the emulator writes into a 4-KiB descriptor page; the
    /// firmware indexes them by position (see the OOB transport). Used by
    /// commands whose bulk evidence rides outside the 4-KiB request
    /// buffer (e.g. `SdCreateRemoteBackup`'s receiver `KeyReport`).
    pub fn tbor_oob<R: TborOpReq>(&self, req: &R, oob_items: &[&[u8]]) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.primary.exec_op_tbor(req, Some(oob_items), &mut cookie)
    }

    /// Session-scoped raw tbor exec: routes the op via the fd that
    /// owns `session_id`. Falls back to `primary` for unknown ids —
    /// lets negative-path tests exercise "bogus session id" paths
    /// without special-casing.
    pub fn tbor_on_session<R: TborOpReq>(&self, session_id: u16, req: &R) -> DdiResult<R::OpResp> {
        self.with_session_dev(session_id, |dev| {
            let mut cookie = None;
            dev.exec_op_tbor(req, None, &mut cookie)
        })
    }

    /// Session-scoped OOB variant of [`Self::tbor_on_session`].
    pub fn tbor_oob_on_session<R: TborOpReq>(
        &self,
        session_id: u16,
        req: &R,
        oob_items: &[&[u8]],
    ) -> DdiResult<R::OpResp> {
        self.with_session_dev(session_id, |dev| {
            let mut cookie = None;
            dev.exec_op_tbor(req, Some(oob_items), &mut cookie)
        })
    }

    /// Issue `req`, assert the FW dispatcher rejected it with exactly
    /// `expected`, and return the matched [`DdiError`] for any further
    /// caller-side inspection.
    ///
    /// Panics if the call succeeded (no rejection at all) or if the
    /// returned error was not a [`DdiError::DdiError`] with code
    /// `expected.0`. The diagnostic preserves the original error so
    /// failure messages still identify *how* the contract drifted.
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

    /// Session-scoped variant of [`Self::expect_fw_reject`] — routes
    /// via the fd owning `session_id`.
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

    /// [`Self::expect_fw_reject`] for a request carrying out-of-band SGL
    /// items (see [`Self::tbor_oob`]).
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

    /// Issue `req`, assert the response failed host-side TBOR decoding
    /// (i.e. surfaced as [`DdiError::TborDecodeError`]), and return
    /// the matched error.
    ///
    /// This is distinct from [`Self::expect_fw_reject`]: a decode
    /// error means the response was structurally invalid relative to
    /// the schema, not that the FW logically rejected the request.
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

    // -------------------------------------------------------------------
    // TBOR command pass-throughs
    //
    // Thin wrappers around the free helpers in `harness::session` so
    // tests can write `ctx.psk_change(&session, &psk)` instead of
    // reaching through a raw device handle. Every session-scoped
    // wrapper routes via the multi-fd map so hw callers hit the
    // driver on the correct fd.
    // -------------------------------------------------------------------

    /// Run Phase 1 of the TBOR session handshake with happy-path
    /// defaults. Returns a [`PendingHandshake`] consumable by
    /// [`Self::session_open_finish`].
    pub fn session_open_init(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<PendingHandshake> {
        let slot = self.take_fd_for_new_session();
        let res = {
            let dev = self.dev_of(&slot);
            session_open_init_helper(dev, psk_id, session_type)
        };
        match res {
            Ok(pending) => {
                self.pending_fds.lock().insert(pending.session_id, slot);
                Ok(pending)
            }
            Err(e) => {
                if slot.is_primary() {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
    }

    /// Full-control Phase 1 entry point: honours every override in
    /// `opts` (PSK, ephemeral, suite id).
    pub fn session_open_init_with_options(
        &self,
        opts: SessionOpenInitOptions<'_>,
    ) -> DdiResult<PendingHandshake> {
        let slot = self.take_fd_for_new_session();
        let res = {
            let dev = self.dev_of(&slot);
            session_open_init_with_options_helper(dev, opts)
        };
        match res {
            Ok(pending) => {
                self.pending_fds.lock().insert(pending.session_id, slot);
                Ok(pending)
            }
            Err(e) => {
                if slot.is_primary() {
                    *self.primary_busy.lock() = false;
                }
                Err(e)
            }
        }
    }

    /// Run Phase 2 of the TBOR session handshake with the canonical
    /// confirm MAC. Consumes `pending` so callers cannot reuse stale
    /// state.
    pub fn session_open_finish(&self, pending: PendingHandshake) -> DdiResult<SessionHandshake> {
        let slot = self.pending_fds.lock().remove(&pending.session_id).expect(
            "session_open_finish: no pending fd for this session_id — call session_open_init first",
        );
        let is_primary = slot.is_primary();
        let res = {
            let dev = self.dev_of(&slot);
            session_open_finish_helper(dev, pending)
        };
        match res {
            Ok(handshake) => {
                self.sessions.lock().insert(handshake.session_id, slot);
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

    /// Phase 2 entry point that ships a caller-supplied `mac_fin`,
    /// e.g. for the MAC-tamper negative-path tests.
    pub fn session_open_finish_with_mac(
        &self,
        pending: PendingHandshake,
        mac_fin: [u8; 48],
    ) -> DdiResult<SessionHandshake> {
        let slot = self.pending_fds.lock().remove(&pending.session_id).expect(
            "session_open_finish_with_mac: no pending fd for this session_id — call session_open_init first",
        );
        let is_primary = slot.is_primary();
        let res = {
            let dev = self.dev_of(&slot);
            session_open_finish_with_mac_helper(dev, pending, mac_fin)
        };
        match res {
            Ok(handshake) => {
                self.sessions.lock().insert(handshake.session_id, slot);
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

    /// One-shot happy-path handshake that returns the raw
    /// [`SessionHandshake`] *without* a `SessionGuard`. Callers are
    /// responsible for the matching [`Self::session_close`]. Used
    /// when the test needs to compare two open sessions opened under
    /// a non-default PSK, or to inspect the handshake before closing
    /// it explicitly.
    pub fn open_session_raw(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<SessionHandshake> {
        let pending = self.session_open_init(psk_id, session_type)?;
        self.session_open_finish(pending)
    }

    /// Issue `SessionClose(session_id)`. Removes the fd binding so
    /// extra fds drop (closing the kernel handle) after the close
    /// call; primary is retained but marked free for the next
    /// handshake. Falls back to `primary` for unknown ids so the
    /// FW/driver can surface its own error for negative-path tests.
    pub fn session_close(&self, session_id: u16) -> DdiResult<()> {
        let entry = self.sessions.lock().remove(&session_id);
        match entry {
            Some(slot) => {
                let is_primary = slot.is_primary();
                let res = {
                    let dev = self.dev_of(&slot);
                    session_close_helper(dev, session_id)
                };
                if is_primary {
                    *self.primary_busy.lock() = false;
                }
                drop(slot);
                res
            }
            None => session_close_helper(&self.primary, session_id),
        }
    }

    /// Issue `PskChange` on `session` with `new_psk` as the
    /// plaintext. The 32-byte length check is performed by the free
    /// helper before any wire bytes are emitted.
    pub fn psk_change(&self, session: &SessionHandshake, new_psk: &[u8]) -> DdiResult<()> {
        self.with_session_dev(session.session_id, |dev| {
            psk_change_helper(dev, session, new_psk)
        })
    }

    /// Issue `PartInit` on the CO `session` with the canonical
    /// envelope construction and a fixed default SATA thumbprint (no
    /// SAPOTA). Returns the decoded [`TborPartInitResp`].
    pub fn part_init(
        &self,
        session: &SessionHandshake,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
    ) -> DdiResult<TborPartInitResp> {
        self.with_session_dev(session.session_id, |dev| {
            part_init_helper(
                dev,
                session,
                mach_seed,
                part_policy,
                pota_thumbprint,
                &DEFAULT_SATA_THUMBPRINT,
                None,
            )
        })
    }

    /// Issue `PartInit` with explicit security-domain thumbprint inputs
    /// (SATA + optional SAPOTA).
    pub fn part_init_sd(
        &self,
        session: &SessionHandshake,
        mach_seed: &[u8],
        part_policy: &[u8],
        pota_thumbprint: &[u8],
        sata_thumbprint: &[u8],
        sapota_thumbprint: Option<&[u8]>,
    ) -> DdiResult<TborPartInitResp> {
        self.with_session_dev(session.session_id, |dev| {
            part_init_helper(
                dev,
                session,
                mach_seed,
                part_policy,
                pota_thumbprint,
                sata_thumbprint,
                sapota_thumbprint,
            )
        })
    }

    /// Issue `PartFinal` re-supplying `part_policy` (must match the one
    /// bound at `PartInit`), the out-of-band PTA cert chain (`certs`,
    /// root → PTA), and an optional prior `local_mk` backup.
    pub fn part_final(
        &self,
        session: &SessionHandshake,
        part_policy: &[u8],
        prev_local_mk_backup: &[u8],
        certs: &[&[u8]],
    ) -> DdiResult<TborPartFinalResp> {
        self.with_session_dev(session.session_id, |dev| {
            part_final_helper(dev, session, part_policy, prev_local_mk_backup, certs)
        })
    }

    /// Issue `ApiRev` and return the decoded response. Thin
    /// pass-through over the free helper.
    pub fn api_rev(&self) -> DdiResult<TborApiRevResp> {
        helper_api_rev_tbor(&self.primary)
    }

    // -------------------------------------------------------------------
    // Non-TBOR pass-throughs (MBOR cert-chain probes)
    //
    // These exist so `commands::part_init::verify_pta_report` can
    // recover the partition's PID-leaf public key without holding a
    // raw `&Dev`. Keeping the entire MBOR surface off of `TestCtx`
    // is intentional — only the two helpers the PTAReport verifier
    // needs are wrapped.
    // -------------------------------------------------------------------

    /// MBOR `GetCertChainInfo(slot_id=0)`.
    #[cfg(feature = "emu")]
    pub fn cert_chain_info(&self) -> DdiResult<azihsm_ddi_mbor_types::DdiGetCertChainInfoCmdResp> {
        azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info(&self.primary)
    }

    /// MBOR `GetCertificate(slot_id=0, cert_id)`.
    #[cfg(feature = "emu")]
    pub fn get_certificate(
        &self,
        cert_id: u8,
    ) -> DdiResult<azihsm_ddi_mbor_types::DdiGetCertificateCmdResp> {
        azihsm_ddi_mbor_test_helpers::helper_get_certificate(&self.primary, cert_id)
    }
}

/// Panic-safe cleanup: close every session the ctx is still tracking,
/// including handshakes that finished phase 1 but never reached phase
/// 2 (a test that panics between `session_open_init` and
/// `session_open_finish` leaves its slot in `pending_fds`). Sessions
/// **must** be closed one-by-one so their kernel-side tracking (and,
/// on hw, the extra fds) is torn down cleanly. Errors are swallowed —
/// drop never panics; a wedged device that rejects `session_close`
/// during unwind must not double-panic.
impl Drop for TestCtx {
    fn drop(&mut self) {
        let pending: Vec<(u16, FdSlot)> = self.pending_fds.lock().drain().collect();
        let live: Vec<(u16, FdSlot)> = self.sessions.lock().drain().collect();
        for (id, slot) in pending.into_iter().chain(live) {
            let dev: &Dev = match &slot {
                FdSlot::Primary => &self.primary,
                FdSlot::Extra(arc) => arc,
            };
            if let Err(e) = session_close_helper(dev, id) {
                eprintln!(
                    "TestCtx::drop: session_close failed: {e:?} \
                     — session may leak on the device",
                );
            }
        }
        *self.primary_busy.lock() = false;
    }
}
