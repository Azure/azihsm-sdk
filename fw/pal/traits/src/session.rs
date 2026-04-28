// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management trait for the HSM PAL.
//!
//! Defines the [`HsmSessionManager`] trait that PAL implementations use
//! to manage authenticated user sessions within a partition.  Each
//! session is identified by a logical [`HsmSessId`] (slot index 0–7)
//! and is scoped to a partition ([`HsmPartId`]).
//!
//! ## Session storage
//!
//! Sessions are stored as vault keys (`HsmVaultKeyKind::Session`)
//! containing an 88-byte blob: `[api_revision(8) || masking_key(80)]`.
//! The session table maps logical session IDs to physical vault key
//! IDs ([`HsmKeyId`]).
//!
//! ## Session lifecycle
//!
//! ```text
//! session_create(pid, api_rev, masking_key, None) → logical HsmSessId
//!   ↓
//! session_state(pid, id)   — verify session is active
//!   ↓
//! session_create(pid, api_rev, masking_key, Some(id)) — re-key after migration
//!   ↓
//! session_delete(pid, id)  — close: delete scoped keys + session key + free slot
//! ```
//!
//! ## Session–key binding
//!
//! Session-scoped vault keys are bound to the session's **physical**
//! vault key ID (not the logical slot index).  When a session is
//! deleted, all keys matching that physical ID are removed first.

use super::*;

/// Lifecycle state of a session.
pub enum HsmSessionState {
    /// The session exists and is active.
    Active,

    /// The session exists but requires re-negotiation (e.g., after VM migration).
    NeedsRenegotiation,

    /// The session has been deleted or is otherwise invalid.
    Invalid,
}

/// RAII guard for a newly created session.
///
/// Returned by [`HsmSessionManager::session_create`].  If dropped without
/// calling [`dismiss`](Self::dismiss), the session is automatically deleted
/// (cascading: session-scoped vault keys, session vault key, logical slot).
///
/// # Usage
///
/// ```text
/// let guard = pal.session_create(pid, api_rev, masking_key, None)?;
/// // ... derive keys, validate credential ...
/// let sess_id = guard.dismiss();  // committed — session persists
/// ```
pub struct SessionGuard<'a, P: HsmSessionManager + ?Sized> {
    pal: &'a P,
    pid: HsmPartId,
    sess_id: Option<HsmSessId>,
}

impl<'a, P: HsmSessionManager + ?Sized> SessionGuard<'a, P> {
    /// Create a guard wrapping a newly created session.
    pub fn new(pal: &'a P, pid: HsmPartId, sess_id: HsmSessId) -> Self {
        Self {
            pal,
            pid,
            sess_id: Some(sess_id),
        }
    }

    /// Peek at the session ID before committing.
    pub fn sess_id(&self) -> HsmSessId {
        self.sess_id.unwrap()
    }

    /// Commit — session persists permanently.  Returns the session ID.
    pub fn dismiss(mut self) -> HsmSessId {
        self.sess_id.take().unwrap()
    }
}

impl<P: HsmSessionManager + ?Sized> Drop for SessionGuard<'_, P> {
    fn drop(&mut self) {
        if let Some(sid) = self.sess_id.take() {
            let _ = self.pal.session_delete(self.pid, sid);
        }
    }
}

/// Session management interface.
///
/// Sessions are stored as vault keys.  `session_create` builds the
/// session blob, stores it in the vault, and allocates a logical slot.
/// `session_delete` cascades: removes session-scoped keys, deletes the
/// session vault key, and frees the slot.
///
/// All methods are synchronous — session operations are fast table
/// lookups or vault operations, not hardware-offloaded crypto.
pub trait HsmSessionManager {
    /// Check whether the partition has at least one free session slot.
    fn session_limit_reached(&self, pid: HsmPartId) -> bool;

    /// Create (or re-key) a session.
    ///
    /// Builds an 88-byte session blob from `api_rev` (8 bytes) and
    /// `masking_key` (80 bytes), stores it in the vault as
    /// [`HsmVaultKeyKind::Session`], and allocates a logical session
    /// slot pointing to that vault key.
    ///
    /// Returns a [`SessionGuard`] that auto-deletes the session on drop
    /// unless [`dismiss`](SessionGuard::dismiss) is called to persist it.
    ///
    /// # Parameters
    /// - `pid` — Partition to create the session in.
    /// - `api_rev` — 8-byte API revision negotiated during OpenSession.
    /// - `masking_key` — 80-byte session masking key (AES-256 + HMAC-384).
    /// - `id` — If `Some`, re-keys an existing session (must be in
    ///   `NeedsRenegotiation` state). If `None`, creates a new session.
    ///
    /// # Returns
    /// A [`SessionGuard`] wrapping the logical [`HsmSessId`] (0–7).
    ///
    /// # Errors
    /// - [`HsmError::VaultSessionLimitReached`] — no free slots.
    /// - [`HsmError::NotEnoughSpace`] — vault cannot store session key.
    /// - [`HsmError::InvalidArg`] — re-key requested but session is not
    ///   in `NeedsRenegotiation` state.
    fn session_create(
        &self,
        pid: HsmPartId,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<SessionGuard<'_, Self>>;

    /// Delete (close) a session.
    ///
    /// 1. Deletes all session-scoped vault keys bound to this session's
    ///    physical key ID.
    /// 2. Deletes the session vault key itself.
    /// 3. Frees the logical session slot.
    ///
    /// # Errors
    /// - [`HsmError::SessionNotFound`] — session ID is invalid.
    fn session_delete(&self, pid: HsmPartId, id: HsmSessId) -> HsmResult<()>;

    /// Query the current state of a session.
    ///
    /// Returns one of the [`HsmSessionState`] variants indicating whether
    /// the session is active, requires re-negotiation, or has been
    /// deleted/invalidated.
    fn session_state(&self, pid: HsmPartId, id: HsmSessId) -> HsmSessionState;
}
