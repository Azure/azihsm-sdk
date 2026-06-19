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
//! session_create(io, api_rev, masking_key, None) → logical HsmSessId
//!   ↓
//! session_state(io, id)   — verify session is active
//!   ↓
//! session_create(io, api_rev, masking_key, Some(id)) — re-key after migration
//!   ↓
//! session_destroy(io, id) — close: delete scoped keys + session key + free slot
//! ```
//!
//! ## Session–key binding
//!
//! Session-scoped vault keys are bound to the session's **physical**
//! vault key ID (not the logical slot index).  When a session is
//! deleted, all keys matching that physical ID are removed first.

use super::*;

/// Lifecycle state of a session.
///
/// Returned by [`HsmSessionManager::session_state`].  The state is
/// derived from the underlying vault entry plus session-table
/// metadata; there is no separate persistent state field.
pub enum HsmSessionState {
    /// The session slot is allocated and the masking key is valid for
    /// the current API revision.  The session may be used.
    Active,

    /// The session slot is allocated, but the API revision recorded in
    /// the masking blob does not match the live one (e.g. after a VM
    /// migration).  The host must call
    /// [`HsmSessionManager::session_create`] with `id =
    /// Some(existing)` to re-key before any further operations.
    NeedsRenegotiation,

    /// The session slot is reserved by an in-flight session
    /// establishment handshake.  Allocated by
    /// [`HsmSessionManager::session_create_pending`] and promoted to
    /// [`Active`](Self::Active) via
    /// [`HsmSessionManager::session_promote`] when the client's
    /// `OpenSessionFinish` message verifies.  No session-encrypted
    /// traffic can flow until promotion succeeds.
    Pending,

    /// The slot is free, the partition does not own such a session, or
    /// the session was destroyed.  Any operation referencing this ID
    /// must fail.
    Invalid,
}

/// Caller role asserted by the session-establishment handshake.
///
/// Roles are determined by the PSK identifier presented in
/// `OpenSessionInit` (`psk_id = 0` → CO, `psk_id = 1` → CU) and pinned
/// for the session lifetime.  The role determines which logical slot
/// range the session occupies and which TBOR commands the session may
/// invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Crypto Officer — administrative role.  Sessions land in
    /// slot 0.  CO sessions are pinned to
    /// [`SessionType::Authenticated`] (request rejected otherwise).
    CryptoOfficer,

    /// Crypto User — regular role.  Sessions land in slots 1..=7.
    /// CU sessions are pinned to
    /// [`SessionType::PlainText`] (request rejected otherwise).
    CryptoUser,
}

/// Channel-level integrity profile asserted by the session-establishment
/// handshake.
///
/// Selected by the `session_type` field of `OpenSessionInit` and
/// pinned for the session lifetime.  The session type determines
/// which derived keys are produced and stored, and whether subsequent
/// command/response bodies carry an outer per-message HMAC envelope.
///
/// Role pairing is enforced at handshake time:
///
/// | Role | Allowed `SessionType` |
/// |---|---|
/// | [`SessionRole::CryptoOfficer`] | [`Authenticated`](Self::Authenticated) |
/// | [`SessionRole::CryptoUser`]    | [`PlainText`](Self::PlainText) |
///
/// Any other combination is rejected with
/// [`HsmError::InvalidSessionType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionType {
    /// Channel transports MBOR bodies without per-message MAC.
    /// `param_key` is still derived so callers can opt-in to encrypt
    /// individual sensitive parameters via the `aead_envelope` envelope.
    PlainText = 0,

    /// Channel transports MBOR bodies wrapped in an outer
    /// per-message HMAC envelope.  Two directional MAC keys
    /// (`mac_tx_key` for VM→HSM, `mac_rx_key` for HSM→VM) are
    /// derived in addition to `param_key`.
    Authenticated = 1,
}

impl SessionType {
    /// Wire-encode this `SessionType` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire `u8` into a `SessionType`.
    ///
    /// Returns [`HsmError::InvalidSessionType`] for any value other
    /// than `0` (PlainText) or `1` (Authenticated).
    #[inline]
    pub const fn from_u8(v: u8) -> HsmResult<Self> {
        match v {
            0 => Ok(Self::PlainText),
            1 => Ok(Self::Authenticated),
            _ => Err(HsmError::InvalidSessionType),
        }
    }

    /// Validate that this `SessionType` is the only one allowed for
    /// the given [`SessionRole`].  Returns
    /// [`HsmError::InvalidSessionType`] for any disallowed pairing.
    #[inline]
    pub const fn validate_for_role(self, role: SessionRole) -> HsmResult<()> {
        match (role, self) {
            (SessionRole::CryptoOfficer, Self::Authenticated)
            | (SessionRole::CryptoUser, Self::PlainText) => Ok(()),
            _ => Err(HsmError::InvalidSessionType),
        }
    }

    /// `true` for [`Authenticated`](Self::Authenticated).
    #[inline]
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

/// Cryptographic suite negotiated by the session-establishment
/// handshake.
///
/// The suite identifier is carried as a single byte in the
/// `OpenSessionInit` request, mixed into the HPKE `info` for
/// transcript binding, and persisted in the Pending blob so
/// [`open_session_finish`] can recover it without trusting any
/// client-side state.
///
/// # Wire registry
///
/// | `suite_id` | Variant | Algorithms |
/// |---|---|---|
/// | `0x01` | [`P384HkdfSha384AesGcm256`](Self::P384HkdfSha384AesGcm256) | HPKE DHKEM(P-384, HKDF-SHA-384) + HKDF-SHA-384 + AES-256-GCM |
///
/// `0x01` is the only currently registered suite.  Any other value
/// is rejected by `OpenSessionInit` with
/// [`HsmError::UnsupportedSessionSuite`]; the `suite_id` byte exists
/// so future suites can be added without a wire-format break.
///
/// [`open_session_finish`]: crate::open_session_finish
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionSuite {
    /// HPKE `DHKEM(P-384, HKDF-SHA-384) + HKDF-SHA-384 + AES-256-GCM`.
    ///
    /// Authenticated PSK mode bound to the partition identity key.
    /// All session-establishment messages and the seed/`bmk_session`
    /// AEAD envelopes use AES-256-GCM (32 B keys, 12 B IVs, 16 B tags).
    P384HkdfSha384AesGcm256 = 0x01,
}

impl SessionSuite {
    /// Wire-encode this `SessionSuite` to its `u8` discriminant.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire `u8` into a `SessionSuite`.
    ///
    /// Returns [`HsmError::UnsupportedSessionSuite`] for any value
    /// that this firmware build does not implement (including `0x00`
    /// and any reserved-but-not-yet-supported variant).
    #[inline]
    pub const fn from_u8(v: u8) -> HsmResult<Self> {
        match v {
            0x01 => Ok(Self::P384HkdfSha384AesGcm256),
            _ => Err(HsmError::UnsupportedSessionSuite),
        }
    }
}

/// RAII guard for a newly created session.
///
/// Returned by [`HsmSessionManager::session_create`].  The guard
/// implements an explicit commit/rollback discipline: the session is
/// *provisional* until [`dismiss`](Self::dismiss) is called.  If the
/// guard is dropped without dismissing — for example because a
/// downstream encode step or DDI handler returned an error — the
/// destructor tears the session down (frees the slot, deletes the
/// session vault key, removes any session-scoped keys), leaving no
/// half-created session behind.
///
/// Typical usage:
///
/// ```ignore
/// let guard = pal.session_create(io, api_rev, masking_key, None)?;
/// // ... fallible work that uses `guard.sess_id()` ...
/// let id = guard.dismiss(); // commit; session now permanent
/// ```
pub trait SessionGuard {
    /// Returns the session ID assigned to the provisional session.
    ///
    /// Safe to call multiple times; does **not** commit the session.
    ///
    /// # Returns
    ///
    /// The [`HsmSessId`] under which the session is currently
    /// registered in the partition's session table.
    fn sess_id(&self) -> HsmSessId;

    /// Commits the session.  The session table entry persists past
    /// the guard's lifetime and the destructor becomes a no-op.
    ///
    /// # Returns
    ///
    /// The committed [`HsmSessId`].
    fn dismiss(self) -> HsmSessId;
}

/// Session management interface.
///
/// All methods take an [`HsmIo`] handle, which scopes the operation to
/// the calling partition: a session created by partition A is
/// invisible to partition B.  The trait is `&self`; PAL
/// implementations are expected to use interior mutability for the
/// session table (the firmware is single-core, cooperatively
/// scheduled, so a plain `Cell`/`RefCell` suffices).
pub trait HsmSessionManager {
    /// RAII guard returned by
    /// [`session_create`](Self::session_create).
    ///
    /// The lifetime parameter ties the guard to the session manager
    /// so an uncommitted session cannot outlive the manager that
    /// owns it.
    type Guard<'a>: SessionGuard
    where
        Self: 'a;

    /// Returns `true` if the calling partition has no free session
    /// slots.
    ///
    /// Used by DDI handlers to short-circuit `OpenSession` requests
    /// with [`HsmError::VaultSessionLimitReached`] before allocating
    /// any crypto state.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    ///
    /// # Returns
    ///
    /// - `true` — every session slot for this partition is in use.
    /// - `false` — at least one slot is free; a subsequent
    ///   [`session_create`](Self::session_create) with `id == None`
    ///   may succeed.
    fn session_limit_reached(&self, io: &impl HsmIo) -> bool;

    /// Creates a new session, or re-keys an existing one in place.
    ///
    /// On success, returns a [`Self::Guard`] that holds the session
    /// in a *provisional* state.  The caller must invoke
    /// [`SessionGuard::dismiss`] to commit; dropping the guard
    /// otherwise rolls the session back.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `api_rev` — 8-byte API-revision tag stored alongside the
    ///   masking key; later compared by
    ///   [`session_state`](Self::session_state) to detect post-
    ///   migration drift.
    /// - `masking_key` — 80-byte masking-key blob to seal into the
    ///   session vault entry.
    /// - `id` — `None` to allocate a new slot; `Some(existing)` to
    ///   re-key an already-open session in place (post-migration
    ///   renegotiation).  The existing session must currently be in
    ///   either [`HsmSessionState::Active`] or
    ///   [`HsmSessionState::NeedsRenegotiation`].
    ///
    /// # Returns
    ///
    /// - `Ok(guard)` — provisional session; commit with
    ///   [`SessionGuard::dismiss`].
    /// - `Err(HsmError::VaultSessionLimitReached)` — `id == None` and
    ///   no slots are free (see
    ///   [`session_limit_reached`](Self::session_limit_reached)).
    /// - `Err(HsmError::InvalidArg)` — `id == Some(_)` and the slot
    ///   is free, or `api_rev`/`masking_key` is the wrong length.
    /// - `Err(HsmError::NotEnoughSpace)` — vault is full and cannot
    ///   store the masking blob.
    fn session_create(
        &self,
        io: &impl HsmIo,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<Self::Guard<'_>>;

    /// Closes a session.
    ///
    /// Tears down the session in this order:
    ///
    /// 1. Removes every vault key bound to the session's physical
    ///    vault key ID (see module-level docs for the
    ///    session→physical-ID binding).
    /// 2. Deletes the session vault entry itself.
    /// 3. Frees the session table slot.
    ///
    /// Idempotent only in the sense that a freed slot is safe to
    /// reuse; calling `session_destroy` on an already-free slot is
    /// reported as [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session to close.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` — `id` does not refer to a live
    ///   session in the caller's partition.
    fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()>;

    /// Queries the lifecycle state of a session slot.
    ///
    /// This is an infallible probe: an unknown or freed slot is
    /// reported as [`HsmSessionState::Invalid`] rather than an
    /// `HsmError`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — session slot to probe.
    ///
    /// # Returns
    ///
    /// One of [`HsmSessionState::Active`],
    /// [`HsmSessionState::NeedsRenegotiation`], or
    /// [`HsmSessionState::Invalid`].
    fn session_state(&self, io: &impl HsmIo, id: HsmSessId) -> HsmSessionState;

    /// Reserves a session slot in the [`Pending`](HsmSessionState::Pending)
    /// state for an in-flight session-establishment handshake.
    ///
    /// Phase 1 of the session protocol: the slot holds the HPKE-derived
    /// `exported` secret and bound public keys so that
    /// [`session_promote`](Self::session_promote) can verify the
    /// `OpenSessionFinish` MAC and derive the final session keys.
    ///
    /// The chosen slot is constrained by `role`:
    ///
    /// - [`SessionRole::CryptoOfficer`] → slot 0 only.
    /// - [`SessionRole::CryptoUser`] → slots 1..=7.
    ///
    /// Allocation policy within the eligible range:
    ///
    /// 1. If an `Empty` slot exists, allocate there.
    /// 2. Otherwise the oldest `Pending` slot in the range is destroyed
    ///    (via [`session_destroy`](Self::session_destroy)) and
    ///    re-allocated.  An evicted handshake's late `OpenSessionFinish`
    ///    fails MAC verification because the slot's `exported` is
    ///    different.
    /// 3. Otherwise (all eligible slots `Active` or
    ///    `NeedsRenegotiation`) returns
    ///    [`HsmError::VaultSessionLimitReached`].
    ///
    /// The `handshake_state` blob is stored opaquely on the slot until
    /// promotion or destruction; the PAL must size internal storage
    /// for blobs up to
    /// [`SESSION_PENDING_BLOB_MAX`](crate::SESSION_PENDING_BLOB_MAX)
    /// bytes.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `role` — role the handshake is claiming.
    /// - `handshake_state` — opaque handshake material (`exported`
    ///   plus bound public keys); retrieved verbatim by
    ///   [`session_pending_state`](Self::session_pending_state).
    ///
    /// # Returns
    ///
    /// - `Ok(id)` — allocated Pending slot.
    /// - `Err(HsmError::InvalidArg)` — `io.pid()` out of range, or
    ///   `handshake_state.len() > SESSION_PENDING_BLOB_MAX`.
    /// - `Err(HsmError::VaultSessionLimitReached)` — no eligible slot
    ///   available for `role`.
    fn session_create_pending(
        &self,
        io: &impl HsmIo,
        role: SessionRole,
        handshake_state: &[u8],
    ) -> HsmResult<HsmSessId>;

    /// Borrows the opaque handshake state of a
    /// [`Pending`](HsmSessionState::Pending) slot.
    ///
    /// Used by the `OpenSessionFinish` handler to recover the HPKE
    /// `exported` secret and bound public keys from the Pending slot
    /// before verifying the client's confirmation MAC.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Pending session slot.
    /// - `out` — `None` for size query, `Some(buf)` to copy.
    ///
    /// # Returns
    ///
    /// - `Ok(size)` — bytes written / would be written.
    /// - `Err(HsmError::InvalidArg)` — `id` does not refer to a live
    ///   session in the caller's partition, or `out.len() < size`.
    /// - `Err(HsmError::SessionNotPending)` — slot exists but is not
    ///   in [`Pending`](HsmSessionState::Pending) state.
    fn session_pending_state(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize>;

    /// Promotes a [`Pending`](HsmSessionState::Pending) slot to
    /// [`Active`](HsmSessionState::Active), committing the derived
    /// session keys to the vault.
    ///
    /// Phase 2 of the session protocol: called by the
    /// `OpenSessionFinish` handler after the client's confirmation MAC
    /// verifies.  The Pending handshake state is zeroized and replaced
    /// by the session-key vault blob:
    ///
    /// Length-discriminated by session type:
    /// * **PlainText (CU):** 120 B blob =
    ///   `[api_rev(8) ‖ param_key(32) ‖ masking_key(80)]`.
    ///   `mac_tx_key` and `mac_rx_key` MUST both be `None`.
    /// * **Authenticated (CO):** 216 B blob = the above ‖
    ///   `mac_tx(48) ‖ mac_rx(48)`.  Both `mac_tx_key` and
    ///   `mac_rx_key` MUST be `Some` (and 48 B each).
    ///
    /// Mixed presence (one MAC key supplied, the other not) is
    /// rejected with [`HsmError::InvalidArg`].
    ///
    /// On error the slot is left untouched; callers may either retry
    /// `session_promote` with corrected arguments or
    /// [`session_destroy`](Self::session_destroy) the slot.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Pending session slot to promote.
    /// - `api_rev` — 8-byte API revision tag (same convention as
    ///   [`session_create`](Self::session_create)).
    /// - `param_key` — 32-byte AES-256 key used by
    ///   [`azihsm_fw_core_crypto_aead_envelope`] for per-parameter
    ///   authenticated encryption (and to unseal the `seed_envelope`
    ///   in `OpenSessionFinish`).
    /// - `masking_key` — 80-byte AES-CBC-256 + HMAC-SHA-384 blob;
    ///   required for both CO and CU sessions.  Consumed by the
    ///   `key_masking::cbc` masked-key system, not by the per-session AEAD.
    /// - `mac_tx_key` — `Some(48 B)` for Authenticated sessions
    ///   (VM→HSM message-MAC key); `None` for PlainText.
    /// - `mac_rx_key` — `Some(48 B)` for Authenticated sessions
    ///   (HSM→VM message-MAC key); `None` for PlainText.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success; slot transitions Pending → Active.
    /// - `Err(HsmError::InvalidArg)` — bad arguments (wrong key
    ///   lengths, `api_rev` wrong length, `id` out of range, mixed
    ///   `mac_*_key` presence).
    /// - `Err(HsmError::SessionNotPending)` — slot exists but is not
    ///   in [`Pending`](HsmSessionState::Pending) state.
    #[allow(clippy::too_many_arguments)]
    fn session_promote(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        api_rev: &[u8],
        param_key: &[u8],
        masking_key: &[u8],
        mac_tx_key: Option<&[u8]>,
        mac_rx_key: Option<&[u8]>,
    ) -> HsmResult<()>;

    /// Returns a borrowed view of the active session's `param_key`
    /// (a 32-byte AES-256 key used by
    /// [`azihsm_fw_core_crypto_aead_envelope`]).
    ///
    /// Zero-copy: the returned `&DmaBuf` borrows directly from the
    /// PAL's session-schedule storage, so callers can hand it to
    /// PAL crypto primitives without an intermediate allocation.
    /// This hides the layout of the session schedule blob from
    /// in-session handlers — they no longer need to know that the
    /// schedule is stored as `api_rev ‖ param_key ‖ masking_key …`
    /// behind a vault key.  If the schedule format changes, only
    /// the PAL impl needs to update.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Active session slot.
    ///
    /// # Returns
    ///
    /// - `Ok(&DmaBuf)` — a sub-view of the schedule blob, exactly
    ///   [`SESSION_PARAM_KEY_LEN`] bytes long.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live Active session in the caller's partition (slot free,
    ///   destroyed, or still Pending).
    /// - `Err(HsmError::InternalError)` — schedule blob is shorter
    ///   than expected (corruption indicator).
    fn session_param_key(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<&DmaBuf>;

    /// Atomically reserves the session's one-shot "PSK change"
    /// budget.  Each session may successfully consume this budget at
    /// most once.
    ///
    /// The budget is bound to one logical session for the slot's
    /// lifetime and reset whenever the slot is re-allocated
    /// (`session_destroy`, `session_create`, `session_create_pending`
    /// reuse) or rebound to new key material via re-keying
    /// (`session_recreate`, `session_promote`).
    ///
    /// Used by the TBOR `ChangePsk` handler to bound intra-session
    /// rotation replay.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `id` — Active session slot.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — budget consumed; the call site may proceed.  No
    ///   second `Ok(())` will be returned for this session.
    /// - `Err(HsmError::InvalidPermissions)` — budget already
    ///   consumed by a prior successful call.
    /// - `Err(HsmError::SessionNotFound)` — `id` does not refer to a
    ///   live Active session in the caller's partition (slot free,
    ///   destroyed, or still Pending).
    fn session_try_consume_psk_change(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()>;
}
