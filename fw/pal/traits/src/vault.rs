// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM Key Vault types and trait.
//!
//! Defines the key management interface for the HSM firmware. The vault
//! stores cryptographic keys in protected memory (SRAM on Cortex-M7,
//! heap on the standard PAL) and tracks their type, attributes, and
//! per-key attributes.
//!
//! ## Key lifecycle
//!
//! ```text
//! vault_key_create(key_bytes, kind, session, attrs) → key_id
//!   ↓
//! vault_key(key_id)       → &[u8] key material
//! vault_key_kind(key_id)  → HsmVaultKeyKind
//! vault_key_attrs(key_id) → HsmVaultKeyAttrs
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

    /// In-flight TBOR session-handshake (Pending) state blob.
    ///
    /// Holds the opaque Pending blob (`exported ‖ pk_init ‖ pk_resp ‖
    /// session_type ‖ suite_id`, up to
    /// [`SESSION_PENDING_BLOB_MAX`](crate::SESSION_PENDING_BLOB_MAX) =
    /// 256 B) produced by the TBOR `OpenSessionInit` phase and consumed
    /// by `OpenSessionFinish`.
    ///
    /// Written by
    /// [`HsmSessionManager::session_create_pending`](crate::HsmSessionManager::session_create_pending)
    /// as a session-scoped key (auto-deleted on session close); replaced
    /// by a [`SessionEx`](Self::SessionEx) key on
    /// [`session_promote`](crate::HsmSessionManager::session_promote).
    /// Used only by PALs that back Pending state in the key vault (e.g.
    /// the Uno PAL); the std PAL keeps Pending state in RAM.
    SessionExPending = 35,

    /// Session-establishment-protocol blob for TBOR sessions (both CO
    /// and CU).
    ///
    /// Length-discriminated by session type:
    /// * **PlainText (CU):** `[api_rev(8) ‖ param_key(32) ‖ masking_key(80)]`
    ///   = 120 B.
    /// * **Authenticated (CO):** the above ‖ `mac_tx(48) ‖ mac_rx(48)`
    ///   = 216 B.
    ///
    /// Written by
    /// [`HsmSessionManager::session_promote`](crate::HsmSessionManager::session_promote)
    /// when any TBOR session completes its handshake; never produced
    /// by the existing [`Session`](Self::Session) path.
    SessionEx = 36,

    /// Partition Trust Anchor (PTA) ECC-P384 private key.
    ///
    /// Written by the TBOR `PartInit` handler when binding the
    /// per-incarnation PTA identity.  One per partition incarnation;
    /// rebinding is rejected with [`HsmError::PtaKeyAlreadySet`].
    ///
    /// [`HsmError::PtaKeyAlreadySet`]: crate::HsmError::PtaKeyAlreadySet
    PartitionTrustAnchor = 37,

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
    PartitionUniqueMachineSecret = 38,
}

/// Key scope: the lifecycle / visibility domain a vault key belongs
/// to.
///
/// Encoded as the 3-bit [`scope`](HsmVaultKeyAttrs::scope) field of
/// [`HsmVaultKeyAttrs`] (six values defined; two encodings remain for
/// future expansion).
///
/// The field lives in bits that were **reserved** in the prior
/// `HsmVaultKeyAttrs` layout, so the change is purely additive and
/// backward-compatible: every previously-created key (including all
/// MBOR-created keys, which never touch these bits) decodes as
/// [`Unspecified`](Self::Unspecified) — the all-zero default.  Scope is
/// only meaningful for keys created through the TBOR API, which set an
/// explicit non-`Unspecified` value; MBOR key creation leaves it
/// `Unspecified`.
///
/// | Bits | Variant | Meaning |
/// |------|---------|---------|
/// | `000` | `Unspecified` | No scope (default; all MBOR / legacy keys) |
/// | `001` | `Session` | Session-scoped; auto-deleted on session close |
/// | `010` | `Ephemeral` | Ephemeral key; not persisted |
/// | `011` | `Local` | Partition-local key |
/// | `100` | `SecurityDomain` | Security-domain–scoped key |
/// | `101` | `Internal` | Firmware-internal key |
///
/// [`open_enum`] keeps the type forward-compatible: an unrecognized
/// 3-bit encoding surfaces as `HsmKeyScope::Unknown(bits)` rather than
/// failing to decode.
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmKeyScope {
    /// No scope. The all-zero default carried by every MBOR-created and
    /// pre-scope (legacy) key; scope semantics do not apply.
    Unspecified = 0b000,

    /// Session-scoped key; deleted when its session closes.
    Session = 0b001,

    /// Ephemeral key; lives only for the duration of an operation and
    /// is never persisted.
    Ephemeral = 0b010,

    /// Partition-local key.
    Local = 0b011,

    /// Security-domain–scoped key.
    SecurityDomain = 0b100,

    /// Firmware-internal key.
    Internal = 0b101,
}

impl HsmKeyScope {
    /// Mask covering the 3-bit `scope` field.
    const BITS_MASK: u8 = 0b111;

    /// Pack into the 3-bit [`HsmVaultKeyAttrs::scope`] field. Masked to
    /// 3 bits so an out-of-range `Unknown` can never corrupt
    /// neighbouring attribute bits.
    const fn into_bits(self) -> u8 {
        self.0 & Self::BITS_MASK
    }

    /// Unpack from the 3-bit [`HsmVaultKeyAttrs::scope`] field.
    const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::BITS_MASK)
    }
}

/// Key attribute bitfield for vault-stored keys.
///
/// A 64-bit bitfield encoding PKCS#11-inspired key properties plus
/// HSM-specific flags.  Set at key creation time and governs which
/// operations are permitted on the key.
///
/// The PKCS#11 usage bits (`private` … `derive`) keep the bit positions
/// of the prior reference firmware's `EntryAttributeFlags` so a
/// little-endian serialization of those bits stays byte-compatible with
/// host tooling.  The [`scope`](Self::scope) field (bits 17–19) is an
/// **additive** [`HsmKeyScope`] that complements — and is independent of
/// — the legacy `internal` (bit 0) and `session` (bit 1) flags, which
/// remain in place for backward compatibility.
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
/// | 17–19 | `scope` | Key scope ([`HsmKeyScope`]) — additive; `0` on legacy / MBOR keys |
/// | 20–63 | `rsvd` | Reserved (must be zero) |
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

    /// Key scope: lifecycle / visibility domain. See [`HsmKeyScope`].
    /// Carved from previously-reserved bits, so the all-zero default
    /// [`HsmKeyScope::Unspecified`] is what every legacy / MBOR key
    /// decodes to.  Set to a specific scope only by the TBOR API.
    #[bits(3)]
    pub scope: HsmKeyScope,

    /// Reserved.
    #[bits(44)]
    rsvd: u64,
}

/// RAII guard for a newly created vault key.
///
/// HSM key vault interface.
///
/// All accessor methods take an [`HsmIo`] handle, used to scope the
/// query to the calling partition — a key created under one partition
/// is invisible to other partitions.  Methods returning `&[u8]`
/// borrow directly from vault storage; the borrow lives no longer
/// than the `&self` borrow on the vault.
pub trait HsmVault {
    /// Stores a new key in the vault under a freshly assigned
    /// [`HsmKeyId`].
    ///
    /// The key is committed immediately. (Rollback of a half-completed
    /// operation will be handled by a future undo log, not here.)
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
    ///
    /// # Returns
    ///
    /// - `Ok(key_id)` — the new key's [`HsmKeyId`].
    /// - `Err(HsmError::NotEnoughSpace)` — vault is full.
    /// - `Err(HsmError::InvalidArg)` — `key.len()` does not match
    ///   `kind`, or `attrs` are inconsistent.
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId>;

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
    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()>;

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
    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()>;

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
    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()>;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_defaults_to_unspecified() {
        // Fresh attrs (and every legacy / MBOR key, which leaves the
        // reserved bits zero) decode as Unspecified.
        assert_eq!(HsmVaultKeyAttrs::new().scope(), HsmKeyScope::Unspecified);
    }

    #[test]
    fn scope_round_trips() {
        for s in [
            HsmKeyScope::Unspecified,
            HsmKeyScope::Session,
            HsmKeyScope::Ephemeral,
            HsmKeyScope::Local,
            HsmKeyScope::SecurityDomain,
            HsmKeyScope::Internal,
        ] {
            assert_eq!(HsmVaultKeyAttrs::new().with_scope(s).scope(), s);
        }
    }

    #[test]
    fn scope_occupies_bits_17_to_19_only() {
        // SecurityDomain = 0b100 → bit 19 set, value 1 << 19.
        let bits = HsmVaultKeyAttrs::new()
            .with_scope(HsmKeyScope::SecurityDomain)
            .into_bits();
        assert_eq!(bits, 1u64 << 19);
    }

    #[test]
    fn scope_is_additive_and_orthogonal_to_legacy_flags() {
        // Setting scope must not disturb the pre-existing internal /
        // session / usage bits, and vice-versa — the change is purely
        // additive over the reserved region.
        let attrs = HsmVaultKeyAttrs::new()
            .with_internal(true)
            .with_session(true)
            .with_derive(true)
            .with_scope(HsmKeyScope::Local);
        assert!(attrs.internal());
        assert!(attrs.session());
        assert!(attrs.derive());
        assert_eq!(attrs.scope(), HsmKeyScope::Local);
        // internal(bit0) | session(bit1) | derive(bit16) | Local<<17.
        let expected = 1u64 | (1 << 1) | (1 << 16) | ((0b011) << 17);
        assert_eq!(attrs.into_bits(), expected);
    }
}
