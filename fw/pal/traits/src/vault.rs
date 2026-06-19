// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM Key Vault types and trait.
//!
//! Defines the key management interface for the HSM firmware. The vault
//! stores cryptographic keys in protected memory (SRAM on Cortex-M7,
//! heap on the standard PAL) and tracks their type, attributes, and
//! per-key metadata.
//!
//! ## Key lifecycle
//!
//! ```text
//! vault_key_create(key_bytes, kind, session, attrs, meta) → key_id
//!   ↓
//! vault_key(key_id)       → &[u8] key material
//! vault_key_kind(key_id)  → HsmVaultKeyKind
//! vault_key_attrs(key_id) → HsmVaultKeyAttrs
//! vault_key_meta(key_id)  → &[u8] metadata blob
//!   ↓
//! vault_key_delete(key_id)
//! vault_key_delete_by_session(session_id)
//! vault_clear()
//! ```
//!
//! ## Key identifiers
//!
//! Each key is assigned a [`HsmKeyId`] (`u16` newtype) on creation.
//! This ID is used in all subsequent DDI operations (sign, encrypt,
//! delete, etc.) to reference the key without exposing key material.
//!
//! ## Key attributes
//!
//! [`HsmVaultKeyAttrs`] is a 64-bit bitfield encoding PKCS#11-inspired
//! properties (encrypt, decrypt, sign, verify, wrap, unwrap, derive)
//! plus HSM-specific flags (internal, session-scoped, extractable).
//! These are set at creation time and govern which operations are
//! permitted on the key.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::*;

use super::*;

/// Types of keys that can be managed by the HSM key vault.
///
/// Each variant corresponds to a specific cryptographic algorithm and
/// key size.  The discriminant values (`0..34`) match the firmware's
/// `EntryKind` enum so that key type information is wire-compatible
/// across the DDI protocol.
///
/// ## Categories
///
/// | Range | Category | Examples |
/// |-------|----------|---------|
/// | 0 | Free (empty slot) | `Free` |
/// | 1–3 | RSA public keys | `Rsa2kPublic`, `Rsa3kPublic`, `Rsa4kPublic` |
/// | 4–6 | RSA private keys | `Rsa2kPrivate` .. `Rsa4kPrivate` |
/// | 7–9 | RSA private CRT keys | `Rsa2kPrivateCrt` .. `Rsa4kPrivateCrt` |
/// | 10–12 | ECC public keys | `Ecc256Public`, `Ecc384Public`, `Ecc521Public` |
/// | 13–15 | ECC private keys | `Ecc256Private` .. `Ecc521Private` |
/// | 16–18 | AES symmetric keys | `Aes128`, `Aes192`, `Aes256` |
/// | 19–21 | AES bulk keys | `AesXtsBulk256`, `AesGcmBulk256`, `AesGcmBulk256Unapproved` |
/// | 22–24 | ECDH shared secrets | `Secret256`, `Secret384`, `Secret521` |
/// | 25–27 | Internal session keys | `EstablishCred`, `SessionEncryption`, `Session` |
/// | 28–30 | HMAC fixed-length | `_HmacSha256`, `_HmacSha384`, `_HmacSha512` |
/// | 31 | Masking key | `MaskingKey` |
/// | 32–34 | HMAC variable-length | `VarLenHmacSha256` .. `VarLenHmacSha512` |
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug)]
pub enum HsmVaultKeyKind {
    // Available slot
    Free = 0,

    // RSA Public Keys
    Rsa2kPublic = 1,
    Rsa3kPublic = 2,
    Rsa4kPublic = 3,

    // RSA Private Keys
    Rsa2kPrivate = 4,
    Rsa3kPrivate = 5,
    Rsa4kPrivate = 6,

    // RSA Private CRT Keys
    Rsa2kPrivateCrt = 7,
    Rsa3kPrivateCrt = 8,
    Rsa4kPrivateCrt = 9,

    // ECC Public Keys
    Ecc256Public = 10,
    Ecc384Public = 11,
    Ecc521Public = 12,

    // ECC Private Keys
    Ecc256Private = 13,
    Ecc384Private = 14,
    Ecc521Private = 15,

    // AES Keys
    Aes128 = 16,
    Aes192 = 17,
    Aes256 = 18,

    // AES Bulk Keys
    AesXtsBulk256 = 19,
    AesGcmBulk256 = 20,
    AesGcmBulk256Unapproved = 21,

    // ECDH Shared Secrets
    Secret256 = 22,
    Secret384 = 23,
    Secret521 = 24,

    // Internal Keys
    EstablishCred = 25,
    SessionEncryption = 26,
    Session = 27,

    // HMAC Keys (fixed length)
    _HmacSha256 = 28,
    _HmacSha384 = 29,
    _HmacSha512 = 30,

    // Masking Key
    MaskingKey = 31,

    // HMAC Keys (variable length)
    VarLenHmacSha256 = 32,
    VarLenHmacSha384 = 33,
    VarLenHmacSha512 = 34,

    /// Session-establishment-protocol blob for TBOR sessions (both CO
    /// and CU).
    ///
    /// Length-discriminated by session type:
    /// * **PlainText (CU):** `[api_rev(8) ‖ param_key(80) ‖ masking_key(80)]`
    ///   = 168 B.
    /// * **Authenticated (CO):** the above ‖ `mac_tx(48) ‖ mac_rx(48)`
    ///   = 264 B.
    ///
    /// Written by
    /// [`HsmSessionManager::session_promote`](crate::HsmSessionManager::session_promote)
    /// when any TBOR session completes its handshake; never produced
    /// by the existing [`Session`](Self::Session) path.
    SessionCu = 35,

    /// Partition Trust Anchor (PTA) ECC-P384 private key.
    ///
    /// Written by the TBOR `PartInit` handler when binding the
    /// per-incarnation PTA identity.  One per partition incarnation;
    /// rebinding is rejected with [`HsmError::PtaKeyAlreadySet`].
    ///
    /// [`HsmError::PtaKeyAlreadySet`]: crate::HsmError::PtaKeyAlreadySet
    PartitionTrustAnchor = 36,

    /// Partition Unique Machine Secret (UMS) — 48 B HMAC-SHA-384-sized
    /// secret derived in `PartInit` from `UDS` plus the request-side
    /// (`MachineSeed`, `PartPolicy`, `POTAThumbprint`) inputs.
    ///
    /// Persisted in the partition key vault for the lifetime of the
    /// partition incarnation so that later phases (e.g. FinalizePart)
    /// can derive secondary partition secrets without re-supplying
    /// `MachineSeed`.  One per partition incarnation; rebinding is
    /// rejected with [`HsmError::UmsKeyAlreadySet`].
    ///
    /// [`HsmError::UmsKeyAlreadySet`]: crate::HsmError::UmsKeyAlreadySet
    PartitionUniqueMachineSecret = 37,
}

/// Key attribute bitfield for vault-stored keys.
///
/// A 64-bit bitfield encoding PKCS#11-inspired key properties plus
/// HSM-specific flags.  Set at key creation time and governs which
/// operations are permitted on the key.
///
/// The bit positions and overall width match the prior reference
/// firmware's `EntryAttributeFlags` so a little-endian serialization
/// of this value into the leading 8 bytes of a masked-key attribute
/// blob is byte-compatible with host tooling that parses either
/// firmware's output.
///
/// ## Bit layout
///
/// | Bit | Field | Description |
/// |-----|-------|-------------|
/// | 0 | `internal` | Device-internal, not user-destroyable |
/// | 1 | `session` | Session-scoped, auto-deleted on close |
/// | 2 | `private` | Requires authenticated session |
/// | 3 | `modifiable` | Attributes can change post-creation |
/// | 4 | `destroyable` | User can delete |
/// | 5 | `local` | Generated on-device (not imported) |
/// | 6 | `extractable` | Key material can be exported |
/// | 7 | `never_extractable` | Has never been extractable |
/// | 8 | `trusted` | Can wrap other keys |
/// | 9 | `wrap_with_trusted` | Only wrappable by trusted keys |
/// | 10 | `encrypt` | Allowed for encryption |
/// | 11 | `decrypt` | Allowed for decryption |
/// | 12 | `sign` | Allowed for signing |
/// | 13 | `verify` | Allowed for verification |
/// | 14 | `wrap` | Allowed for key wrapping |
/// | 15 | `unwrap` | Allowed for key unwrapping |
/// | 16 | `derive` | Allowed for key derivation |
/// | 17–63 | `rsvd` | Reserved (must be zero) |
#[bitfield(u64)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct HsmVaultKeyAttrs {
    /// Device-internal key, not user-destroyable.
    pub internal: bool,

    /// Session-scoped key, deleted when session closes.
    pub session: bool,

    /// Requires authenticated session to access.
    pub private: bool,

    /// Key properties can be changed after creation.
    pub modifiable: bool,

    /// Can be deleted by user.
    pub destroyable: bool,

    /// Generated locally (not imported). Set by device.
    pub local: bool,

    /// Key value can be exported from the device.
    pub extractable: bool,

    /// Has never been marked extractable.
    pub never_extractable: bool,

    /// Can wrap other keys. Public keys only.
    pub trusted: bool,

    /// Can only be wrapped by a trusted key. Private & shared keys.
    pub wrap_with_trusted: bool,

    /// Allowed for encrypt operations. Public & secret keys.
    pub encrypt: bool,

    /// Allowed for decrypt operations. Private & secret keys.
    pub decrypt: bool,

    /// Allowed for sign operations. Private & secret keys.
    pub sign: bool,

    /// Allowed for verify operations. Public & secret keys.
    pub verify: bool,

    /// Allowed for key wrap operations. Public & secret keys.
    pub wrap: bool,

    /// Allowed for key unwrap operations. Private & secret keys.
    pub unwrap: bool,

    /// Allowed for key derivation. Secret keys.
    pub derive: bool,

    /// Reserved.
    #[bits(47)]
    rsvd: u64,
}

/// RAII guard for a newly created vault key.
///
/// Returned by [`HsmVault::vault_key_create`]. The guard implements an
/// explicit commit/rollback discipline: the key is *provisional* until
/// [`dismiss`](Self::dismiss) is called.  If the guard is dropped
/// without dismissing — for example because a downstream encode step
/// or DDI handler returned an error — the destructor deletes the key
/// from the vault, leaving no half-created entry behind.
///
/// Typical usage:
///
/// ```ignore
/// let guard = pal.vault_key_create(io, &key, kind, sess, attrs, meta)?;
/// // ... fallible work that uses `guard.key_id()` ...
/// let id = guard.dismiss(); // commit; key now permanent
/// ```
pub trait VaultKeyGuard {
    /// Returns the key ID assigned to the provisional key.
    ///
    /// Safe to call multiple times; does **not** commit the key.
    ///
    /// # Returns
    ///
    /// The [`HsmKeyId`] under which the key is currently registered in
    /// the vault.
    fn key_id(&self) -> HsmKeyId;

    /// Commits the key. The vault entry persists past the guard's
    /// lifetime and the destructor becomes a no-op.
    ///
    /// # Returns
    ///
    /// The committed [`HsmKeyId`].
    fn dismiss(self) -> HsmKeyId;
}

/// HSM key vault interface.
///
/// All accessor methods take an [`HsmIo`] handle, used to scope the
/// query to the calling partition — a key created under one partition
/// is invisible to other partitions.  Methods returning `&[u8]`
/// borrow directly from vault storage; the borrow lives no longer
/// than the `&self` borrow on the vault.
pub trait HsmVault {
    /// RAII guard returned by [`vault_key_create`](Self::vault_key_create).
    ///
    /// The lifetime parameter ties the guard to the vault so an
    /// uncommitted key cannot outlive the vault that owns it.
    type KeyGuard<'a>: VaultKeyGuard
    where
        Self: 'a;

    /// Stores a new key in the vault under a freshly assigned
    /// [`HsmKeyId`].
    ///
    /// The returned [`Self::KeyGuard`] holds the key in a *provisional*
    /// state.  The caller must invoke [`VaultKeyGuard::dismiss`] to
    /// commit the entry; dropping the guard otherwise rolls the key
    /// back.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context, used to bind the key to the
    ///   active partition.
    /// - `key` — raw key material. Length must match `kind`'s expected
    ///   size (see [`vault_key_len`](Self::vault_key_len)).
    /// - `kind` — algorithm/size tag for the key (see
    ///   [`HsmVaultKeyKind`]).
    /// - `session_id` — `Some(id)` to scope the key to a session
    ///   (auto-deleted on session close), `None` for a partition-wide
    ///   key.
    /// - `attrs` — PKCS#11-style permission bitfield (see
    ///   [`HsmVaultKeyAttrs`]).
    /// - `meta` — opaque per-key metadata (e.g. label, ECC point
    ///   encoding); stored verbatim and returned by
    ///   [`vault_key_meta`](Self::vault_key_meta).
    ///
    /// # Returns
    ///
    /// - `Ok(guard)` — provisional vault entry; commit with
    ///   [`VaultKeyGuard::dismiss`].
    /// - `Err(HsmError::NotEnoughSpace)` — vault is full.
    /// - `Err(HsmError::InvalidArg)` — `key.len()` does not match
    ///   `kind`, or `attrs` are inconsistent.
    fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &[u8],
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
        meta: &[u8],
    ) -> HsmResult<Self::KeyGuard<'_>>;

    /// Deletes a single key by ID.
    ///
    /// Idempotent in the sense that a deleted slot becomes available
    /// for the next [`vault_key_create`](Self::vault_key_create), but
    /// the deletion of an already-deleted ID is reported as
    /// [`HsmError::InvalidArg`].
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key_id` — ID returned by a previous successful
    ///   [`vault_key_create`](Self::vault_key_create).
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError::InvalidArg)` if `key_id` does not refer to a
    ///   live key in the caller's partition.
    /// - `Err(HsmError::NotPermitted)` if the key's `destroyable` bit
    ///   is unset (e.g. internal device keys).
    fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()>;

    /// Deletes every key whose `session_id` matches `session_id`.
    ///
    /// Used during session teardown to reap session-scoped keys in
    /// bulk.  Keys with no associated session are unaffected.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `session_id` — session whose keys must be removed.
    ///
    /// # Returns
    ///
    /// - `Ok(())` always; deleting zero keys is not an error.
    fn vault_key_delete_by_session(&self, io: &impl HsmIo, session_id: HsmSessId) -> HsmResult<()>;

    /// Deletes every key owned by the caller's partition, regardless
    /// of session or attribute flags.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    ///
    /// # Returns
    ///
    /// - `Ok(())` always; an already-empty vault is not an error.
    fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()>;

    /// Borrows the raw key material for `key_id`.
    ///
    /// The returned slice points into vault storage and is valid for
    /// the duration of the `&self` borrow.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key_id` — key to look up.
    ///
    /// # Returns
    ///
    /// - `Ok(&[u8])` — raw key bytes; length matches
    ///   [`vault_key_len`](Self::vault_key_len) for the key's `kind`.
    /// - `Err(HsmError::InvalidArg)` — `key_id` does not refer to a
    ///   live key in the caller's partition.
    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf>;

    /// Returns the canonical byte length of a key of the given kind.
    ///
    /// For variable-length kinds (e.g. `VarLenHmacSha256`) this
    /// returns the maximum supported length.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (used only for partition policy
    ///   checks; no key lookup is performed).
    /// - `kind` — key kind tag.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — expected `key.len()` for
    ///   [`vault_key_create`](Self::vault_key_create) calls of this
    ///   `kind`.
    /// - `Err(HsmError::InvalidArg)` — `kind` is `Free` or otherwise
    ///   not a real key type.
    fn vault_key_len(&self, io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16>;

    /// Returns the [`HsmVaultKeyKind`] tag stored alongside the key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key_id` — key to look up.
    ///
    /// # Returns
    ///
    /// - `Ok(kind)` — algorithm/size tag.
    /// - `Err(HsmError::InvalidArg)` — `key_id` does not refer to a
    ///   live key in the caller's partition.
    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind>;

    /// Returns the attribute bitfield stored alongside the key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key_id` — key to look up.
    ///
    /// # Returns
    ///
    /// - `Ok(attrs)` — the [`HsmVaultKeyAttrs`] supplied at creation.
    /// - `Err(HsmError::InvalidArg)` — `key_id` does not refer to a
    ///   live key in the caller's partition.
    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs>;

    /// Borrows the per-key metadata blob.
    ///
    /// The returned slice points into vault storage and is valid for
    /// the duration of the `&self` borrow.  Content is whatever was
    /// passed to
    /// [`vault_key_create`](Self::vault_key_create)'s `meta`
    /// parameter.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (partition scope).
    /// - `key_id` — key to look up.
    ///
    /// # Returns
    ///
    /// - `Ok(&[u8])` — metadata bytes (may be empty).
    /// - `Err(HsmError::InvalidArg)` — `key_id` does not refer to a
    ///   live key in the caller's partition.
    fn vault_key_meta(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&[u8]>;
}
