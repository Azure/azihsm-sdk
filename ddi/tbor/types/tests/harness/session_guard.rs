// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII guard for a live TBOR session.
//!
//! A [`SessionGuard`] owns the handshake carrier produced by
//! [`TestCtx::open_session_raw`](crate::harness::TestCtx::open_session_raw)
//! and closes the session when dropped — including when the test is
//! unwinding from a failed assertion. The emulator's session table
//! is process-global and the per-test serialisation provided by
//! [`open_dev`](crate::harness::open_dev)'s `TEST_LOCK` only orders
//! execution; it does not clean up leaked slots. The guard
//! therefore makes panic-safe cleanup the default for every
//! happy-path session test.
//!
//! Negative-path tests that need to intercept the handshake mid-flight
//! (e.g. ship a tampered `mac_fin`, double-close the same id, exercise
//! a pending-only slot) keep using
//! [`TestCtx::session_open_init`](crate::harness::TestCtx::session_open_init) /
//! [`TestCtx::session_open_finish`](crate::harness::TestCtx::session_open_finish) /
//! [`TestCtx::session_close`](crate::harness::TestCtx::session_close)
//! directly. The guard exists for the well-behaved 90% case, not for
//! those intentional misuses.

use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_tbor_types::SessionType;

use crate::harness::session::SessionHandshake;
use crate::harness::TestCtx;

/// RAII handle to a live session. Closes on `Drop` unless explicitly
/// consumed via [`Self::close`]. Borrows the [`TestCtx`] for the
/// guard's lifetime — multiple guards from the same ctx are allowed
/// (the borrow is shared), which is how multi-session tests like
/// `open_session_multiple_concurrent_emu` will be expressed once
/// migrated.
pub struct SessionGuard<'ctx> {
    ctx: &'ctx TestCtx,
    handshake: SessionHandshake,
    closed: bool,
}

impl<'ctx> SessionGuard<'ctx> {
    /// Internal constructor — driven by [`TestCtx::open_session`].
    pub(crate) fn new(ctx: &'ctx TestCtx, handshake: SessionHandshake) -> Self {
        Self {
            ctx,
            handshake,
            closed: false,
        }
    }

    /// FW-assigned active session identifier.
    pub fn session_id(&self) -> u16 {
        self.handshake.session_id
    }

    /// Borrow the underlying handshake carrier for tests that need
    /// `param_key`, `bmk_session`, or any other field beyond the id.
    pub fn handshake(&self) -> &SessionHandshake {
        &self.handshake
    }

    /// Explicitly close the session and surface the `DdiResult`.
    ///
    /// Consuming `self` makes double-close a *compile* error rather
    /// than a runtime one — tests that *want* to assert the FW
    /// rejects a double-close must drive the second
    /// [`TestCtx::session_close`] call themselves.
    pub fn close(mut self) -> DdiResult<()> {
        self.closed = true;
        self.ctx.session_close(self.handshake.session_id)
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Always attempt cleanup, even while panicking: leaking a
        // slot corrupts the next serial test's starting state.
        // Drop never panics — failure is logged so the original panic
        // (if any) keeps its place at the top of the stack trace.
        if let Err(e) = self.ctx.session_close(self.handshake.session_id) {
            eprintln!(
                "SessionGuard: session_close({}) failed during drop: {e:?}",
                self.handshake.session_id,
            );
        }
    }
}

impl TestCtx {
    /// Open a session via the happy-path two-phase handshake and
    /// return a [`SessionGuard`] that will close it on `Drop`.
    ///
    /// Panics on any FW or transport error; negative-path tests must
    /// call [`TestCtx::session_open_init`] (etc.) directly so they
    /// can inspect the failure mode.
    pub fn open_session(&self, psk_id: u8, session_type: SessionType) -> SessionGuard<'_> {
        let handshake = self
            .open_session_raw(psk_id, session_type)
            .expect("TestCtx::open_session: handshake must succeed on the happy path");
        SessionGuard::new(self, handshake)
    }
}
