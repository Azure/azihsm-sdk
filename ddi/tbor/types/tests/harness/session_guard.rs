// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RAII guard for a live TBOR session.
//!
//! A [`SessionGuard`] owns the handshake carrier produced by
//! [`TestCtx::open_session_raw`](crate::harness::ctx::TestCtx::open_session_raw)
//! and closes the session when dropped — including when the test is
//! unwinding from a failed assertion. Backend session tables are
//! shared state (the emulator's is process-global; a real device has
//! a single fixed session table); the per-test serialisation
//! provided by the test lock only orders execution, it does not
//! clean up leaked slots. The guard therefore makes panic-safe
//! cleanup the default for every happy-path session test.
//!
//! Negative-path tests that need to intercept the handshake mid-flight
//! (e.g. ship a tampered `mac_fin`, double-close the same id, exercise
//! a pending-only slot) keep using `session_open_init` /
//! `session_open_finish` / `session_close` on the ctx directly. The
//! guard exists for the well-behaved 90% case, not for those
//! intentional misuses.

use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_tbor_types::SessionType;

use crate::harness::ctx::TestCtx;
use crate::harness::session::SessionHandshake;

/// Backend-agnostic hook the guard needs at cleanup time. Implemented
/// by every ctx type whose `open_session` returns a [`SessionGuard`]
/// so the guard file itself stays free of backend `cfg` scaffolding.
pub trait SessionCloser {
    /// Close the session identified by `session_id`. Called from
    /// [`SessionGuard::close`] and (best-effort) from [`Drop`].
    fn close_session_by_id(&self, session_id: u16) -> DdiResult<()>;
}

/// RAII handle to a live session. Closes on `Drop` unless explicitly
/// consumed via [`Self::close`]. Borrows the ctx (as a
/// [`SessionCloser`] trait object) for the guard's lifetime — multiple
/// guards from the same ctx are allowed (the borrow is shared).
pub struct SessionGuard<'ctx> {
    ctx: &'ctx dyn SessionCloser,
    handshake: SessionHandshake,
    closed: bool,
}

impl<'ctx> SessionGuard<'ctx> {
    /// Internal constructor — driven by the ctx's inherent
    /// `open_session` method.
    pub(crate) fn new(ctx: &'ctx dyn SessionCloser, handshake: SessionHandshake) -> Self {
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
    /// rejects a double-close must drive the second `session_close`
    /// call themselves.
    pub fn close(mut self) -> DdiResult<()> {
        self.closed = true;
        self.ctx.close_session_by_id(self.handshake.session_id)
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
        if let Err(e) = self.ctx.close_session_by_id(self.handshake.session_id) {
            eprintln!(
                "SessionGuard: session_close({}) failed during drop: {e:?}",
                self.handshake.session_id,
            );
        }
    }
}

impl SessionCloser for TestCtx {
    fn close_session_by_id(&self, session_id: u16) -> DdiResult<()> {
        self.session_close(session_id)
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
