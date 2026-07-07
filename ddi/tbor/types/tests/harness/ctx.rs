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
//! through. Tests that mix-and-match raw [`open_dev`] calls and
//! [`TestCtx`] both get the same guarantee.
//!
//! The raw device handle deliberately has **no public accessor** on
//! this type. All device interactions must flow through one of the
//! TBOR methods (`tbor`, `session_open_init`, `psk_change`, ...) or
//! the narrow non-TBOR pass-throughs (`erase`, `cert_chain_info`,
//! `get_certificate`). This forces every test path through the
//! shared assertion funnel.

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborApiRevResp;
use azihsm_ddi_tbor_types::TborOpReq;
use azihsm_ddi_tbor_types::TborPartInitResp;
use azihsm_ddi_tbor_types::TborStatus;

use crate::harness::api_rev::helper_api_rev_tbor;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::assertions::assert_tbor_decode_error;
use crate::harness::fixture::open_dev;
use crate::harness::fixture::TestDev;
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

/// One-test fixture: an opened backend device handle (with the
/// process-global test lock held for its lifetime) plus a thin layer
/// of error-shape assertions. Constructed once per `#[test]`.
pub struct TestCtx {
    dev: TestDev,
}

impl TestCtx {
    /// Open the backend device via [`open_dev`] — see its docs for
    /// the locking + factory-reset semantics.
    pub fn new() -> Self {
        Self { dev: open_dev() }
    }

    /// Factory-reset the partition. Available only on `emu`; the
    /// determinism tests in `commands::part_init` call this between
    /// cold-restart iterations.
    #[cfg(feature = "emu")]
    pub fn erase(&self) -> DdiResult<()> {
        self.dev.erase()
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
        self.dev.exec_op_tbor(req, &mut cookie)
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
    // reaching through a raw device handle. The free helpers remain
    // in place for documentation purposes (their signatures describe
    // what bytes reach the wire); the methods are the ergonomic
    // test-facing API.
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

    /// Issue `SessionClose(session_id)`. Used by negative-path
    /// tests (double-close, unknown id) and by callers that hold a
    /// raw [`SessionHandshake`] outside of a [`SessionGuard`].
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

    /// Issue `ApiRev` and return the decoded response. Thin
    /// pass-through over the free helper.
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
