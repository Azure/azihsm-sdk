// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain (TBOR) HSM session management.
//!
//! [`HsmSessionEx`] is the upper-layer handle for a session established
//! over the two-phase TBOR HPKE handshake ([`ddi::open_session_ex`]).
//! It mirrors [`HsmSession`] but carries the TBOR per-session key
//! material instead of the MBOR seed/credential state.
//!
//! Resiliency (session reopen after a partition restore) is not yet
//! wired for the TBOR transport, so a restore event invalidates the
//! session. The FW-side session slot is torn down via
//! [`ddi::close_session_ex`] when the last clone of the handle drops.

// TBOR session wiring is landing incrementally; the per-session key
// material is held now and consumed by the channel-crypto layer in a
// follow-up. Remove once those readers land.
#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;

use azihsm_crypto::AesKey;
use azihsm_ddi_tbor_types::SessionType;
use parking_lot::RwLock;
use tracing::*;

use super::*;

/// HSM security-domain session handle (TBOR transport).
///
/// Represents an active session established over the two-phase TBOR
/// HPKE handshake. Cloning shares the underlying session; the FW-side
/// slot is closed when the last clone is dropped.
#[derive(Clone)]
pub struct HsmSessionEx {
    inner: Arc<RwLock<HsmSessionExInner>>,
}

/// Marker trait for HSM sessions.
impl Session for HsmSessionEx {}

impl HsmSessionEx {
    /// Wraps a successful [`ddi::open_session_ex`] result in a session
    /// handle.
    ///
    /// # Arguments
    ///
    /// * `rev` - The API revision negotiated for this session.
    /// * `partition` - The partition the session is bound to.
    /// * `result` - The handshake output from [`ddi::open_session_ex`].
    #[instrument(skip_all, fields(session_id = result.session_id))]
    pub(crate) fn new(
        rev: HsmApiRev,
        partition: HsmPartition,
        result: ddi::OpenSessionExResult,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionExInner::new(rev, partition, result))),
        }
    }

    /// Returns the session identifier.
    pub fn id(&self) -> u16 {
        self.inner.read().id
    }

    /// Returns the API revision negotiated for this session.
    pub fn api_rev(&self) -> HsmApiRev {
        self.inner.read().rev
    }

    /// Returns the PSK id selecting the role (0 = CO, 1 = CU).
    pub(crate) fn psk_id(&self) -> u8 {
        self.inner.read().psk_id
    }

    /// Returns the channel integrity profile pinned at handshake time.
    pub(crate) fn session_type(&self) -> SessionType {
        self.inner.read().session_type
    }
}

impl fmt::Debug for HsmSessionEx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.read().fmt(f)
    }
}

/// Inner state for an [`HsmSessionEx`], guarded by an `RwLock`.
struct HsmSessionExInner {
    /// Active session identifier.
    id: u16,
    /// API revision negotiated for this session.
    rev: HsmApiRev,
    /// Partition this session is bound to. Retained so the FW-side
    /// session slot can be torn down on drop.
    partition: HsmPartition,
    /// PSK id used for the handshake (0 = CO, 1 = CU).
    psk_id: u8,
    /// Channel integrity profile pinned at handshake time.
    session_type: SessionType,
    /// HPKE exported secret (`Nh = 48`). Sensitive — never logged.
    exported: Vec<u8>,
    /// Per-session AES-256 wrap key derived from the HPKE export.
    /// Sensitive — never logged.
    param_key: AesKey,
    /// FW-emitted wrapped masking-key blob — opaque to the host.
    bmk_session: Vec<u8>,
}

impl HsmSessionExInner {
    fn new(rev: HsmApiRev, partition: HsmPartition, result: ddi::OpenSessionExResult) -> Self {
        Self {
            id: result.session_id,
            rev,
            partition,
            psk_id: result.psk_id,
            session_type: result.session_type,
            exported: result.exported,
            param_key: result.param_key,
            bmk_session: result.bmk_session,
        }
    }
}

impl fmt::Debug for HsmSessionExInner {
    /// Redacts the handshake key material (`exported`, `param_key`,
    /// `bmk_session`) so secrets are never written to logs or traces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmSessionEx")
            .field("id", &self.id)
            .field("rev", &self.rev)
            .field("psk_id", &self.psk_id)
            .field("session_type", &self.session_type)
            .field("exported", &"[redacted]")
            .field("param_key", &"[redacted]")
            .field("bmk_session", &"[redacted]")
            .finish()
    }
}

impl Drop for HsmSessionExInner {
    /// Tears down the FW-side session slot when the handle is dropped.
    #[instrument(skip_all, fields(session_id = self.id))]
    fn drop(&mut self) {
        let _ = ddi::close_session_ex(&self.partition, self.id);
    }
}
