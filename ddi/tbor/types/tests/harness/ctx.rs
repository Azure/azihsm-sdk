// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`TestCtx`] — the single entry point per integration test.
//!
//! Wraps **one** opened backend device (`Dev`) and offers thin
//! primitives for issuing TBOR ops on it. Tests that need concurrent
//! or overlapping sessions across multiple fds open additional
//! [`Dev`]s **outside** of `TestCtx` via
//! [`crate::harness::fixture::open_extra_dev`], passing
//! [`TestCtx::path`] to bind to the same underlying device. `TestCtx`
//! itself does not track those extra fds.
//!
//! Cross-test isolation (process-global lock + factory reset) lives
//! in [`crate::harness::fixture::open_dev_parts`], which this type
//! calls through.
//!
//! `TestCtx` owns exactly one `Dev`. Tests that need overlapping
//! sessions across multiple fds open extra `Dev`s themselves at the
//! call site so this type stays free of fd-routing state.

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
use parking_lot::MutexGuard;

use crate::harness::api_rev::helper_api_rev_tbor;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::assertions::assert_tbor_decode_error;
use crate::harness::fixture::open_dev_parts;
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
/// Tests that need extra concurrent fds open them themselves via
/// [`crate::harness::fixture::open_extra_dev`] using
/// [`Self::path`] — those extra `Dev`s are not tracked by `TestCtx`.
pub struct TestCtx {
    dev: Dev,
    /// Path the primary `Dev` was opened on — captured at open time.
    /// Tests that need additional fds pass this to
    /// [`crate::harness::fixture::open_extra_dev`] so every extra fd
    /// binds to the **same** underlying device as the primary.
    /// Reusing the path (instead of re-enumerating via
    /// `dev_info_list().first()`) avoids relying on backend-order
    /// stability on a multi-device rig.
    path: String,
    _guard: MutexGuard<'static, ()>,
}

impl TestCtx {
    /// Open the backend device via [`open_dev_parts`] — see its docs
    /// for the locking + factory-reset semantics.
    pub fn new() -> Self {
        let (dev, guard, path) = open_dev_parts();
        Self {
            dev,
            path,
            _guard: guard,
        }
    }

    /// Path (backend-specific string, e.g. `/dev/azihsm0` on nix,
    /// `\\.\AZIHSM0` on win, an emu handle on emu) the primary
    /// `Dev` was opened on. Tests that need an additional fd on the
    /// same underlying device pass this to
    /// [`crate::harness::fixture::open_extra_dev`].
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Factory-reset the partition. On emu this issues the emulator's
    /// reset; on the native backend it issues NSSR. Under `--features
    /// mock` this call is unavailable (the mock backend has no state
    /// to reset).
    #[cfg(not(feature = "mock"))]
    pub fn erase(&self) -> DdiResult<()> {
        self.dev.erase()
    }

    /// Issue an `OP_TBOR` request and return the raw `DdiResult`.
    ///
    /// Use this when the test needs to inspect both `Ok` and `Err`
    /// arms itself. For the common "must reject with status X" shape,
    /// prefer [`Self::expect_fw_reject`].
    pub fn tbor<R: TborOpReq>(&self, req: &R) -> DdiResult<R::OpResp> {
        let mut cookie = None;
        self.dev.exec_op_tbor(req, None, &mut cookie)
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
        self.dev.exec_op_tbor(req, Some(oob_items), &mut cookie)
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
    // reaching through a raw device handle. All operate on the single
    // primary `Dev`.
    // -------------------------------------------------------------------

    /// Run Phase 1 of the TBOR session handshake with happy-path
    /// defaults. Returns a [`PendingHandshake`] consumable by
    /// [`Self::session_open_finish`].
    pub fn session_open_init(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<PendingHandshake> {
        session_open_init_helper(&self.dev, psk_id, session_type)
    }

    /// Full-control Phase 1 entry point: honours every override in
    /// `opts` (PSK, ephemeral, suite id).
    pub fn session_open_init_with_options(
        &self,
        opts: SessionOpenInitOptions<'_>,
    ) -> DdiResult<PendingHandshake> {
        session_open_init_with_options_helper(&self.dev, opts)
    }

    /// Run Phase 2 of the TBOR session handshake with the canonical
    /// confirm MAC. Consumes `pending` so callers cannot reuse stale
    /// state.
    pub fn session_open_finish(&self, pending: PendingHandshake) -> DdiResult<SessionHandshake> {
        session_open_finish_helper(&self.dev, pending)
    }

    /// Phase 2 entry point that ships a caller-supplied `mac_fin`,
    /// e.g. for the MAC-tamper negative-path tests.
    pub fn session_open_finish_with_mac(
        &self,
        pending: PendingHandshake,
        mac_fin: [u8; 48],
    ) -> DdiResult<SessionHandshake> {
        session_open_finish_with_mac_helper(&self.dev, pending, mac_fin)
    }

    /// One-shot happy-path handshake that returns the raw
    /// [`SessionHandshake`] *without* a `SessionGuard`. Callers are
    /// responsible for the matching [`Self::session_close`].
    pub fn open_session_raw(
        &self,
        psk_id: u8,
        session_type: SessionType,
    ) -> DdiResult<SessionHandshake> {
        let pending = self.session_open_init(psk_id, session_type)?;
        self.session_open_finish(pending)
    }

    /// Issue `SessionClose(session_id)` on the primary `Dev`.
    pub fn session_close(&self, session_id: u16) -> DdiResult<()> {
        session_close_helper(&self.dev, session_id)
    }

    /// Issue `PskChange` on `session` with `new_psk` as the
    /// plaintext. The 32-byte length check is performed by the free
    /// helper before any wire bytes are emitted.
    pub fn psk_change(&self, session: &SessionHandshake, new_psk: &[u8]) -> DdiResult<()> {
        psk_change_helper(&self.dev, session, new_psk)
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
        part_final_helper(&self.dev, session, part_policy, prev_local_mk_backup, certs)
    }

    /// Issue `ApiRev` and return the decoded response.
    pub fn api_rev(&self) -> DdiResult<TborApiRevResp> {
        helper_api_rev_tbor(&self.dev)
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
        azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info(&self.dev)
    }

    /// MBOR `GetCertificate(slot_id=0, cert_id)`.
    #[cfg(feature = "emu")]
    pub fn get_certificate(
        &self,
        cert_id: u8,
    ) -> DdiResult<azihsm_ddi_mbor_types::DdiGetCertificateCmdResp> {
        azihsm_ddi_mbor_test_helpers::helper_get_certificate(&self.dev, cert_id)
    }
}
