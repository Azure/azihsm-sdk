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
//! Each key is assigned a [`HsmVaultKeyId`] (`u16`) on creation. This
//! ID is used in all subsequent DDI operations (sign, encrypt, delete,
//! etc.) to reference the key without exposing key material.
//!
//! ## Key attributes
//!
//! [`HsmVaultKeyAttrs`] is a 32-bit bitfield encoding PKCS#11-inspired
//! properties (encrypt, decrypt, sign, verify, wrap, unwrap, derive)
//! plus HSM-specific flags (internal, session-scoped, extractable).
//! These are set at creation time and govern which operations are
//! permitted on the key.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::*;

use super::*;

/// Types of keys that can be managed by the HSM key vault.
#[repr(u8)]
#[open_enum]
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
}

#[bitfield(u32)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct HsmVaultKeyAttrs {
    /// Device-internal key, not user-destroyable.
    pub(crate) internal: bool,

    /// Session-scoped key, deleted when session closes.
    pub(crate) session: bool,

    /// Requires authenticated session to access.
    pub(crate) private: bool,

    /// Key properties can be changed after creation.
    pub(crate) modifiable: bool,

    /// Can be deleted by user.
    pub(crate) destroyable: bool,

    /// Generated locally (not imported). Set by device.
    pub(crate) local: bool,

    /// Key value can be exported from the device.
    pub(crate) extractable: bool,

    /// Has never been marked extractable.
    pub(crate) never_extractable: bool,

    /// Can wrap other keys. Public keys only.
    pub(crate) trusted: bool,

    /// Can only be wrapped by a trusted key. Private & shared keys.
    pub(crate) wrap_with_trusted: bool,

    /// Allowed for encrypt operations. Public & secret keys.
    pub(crate) encrypt: bool,

    /// Allowed for decrypt operations. Private & secret keys.
    pub(crate) decrypt: bool,

    /// Allowed for sign operations. Private & secret keys.
    pub(crate) sign: bool,

    /// Allowed for verify operations. Public & secret keys.
    pub(crate) verify: bool,

    /// Allowed for key wrap operations. Public & secret keys.
    pub(crate) wrap: bool,

    /// Allowed for key unwrap operations. Private & secret keys.
    pub(crate) unwrap: bool,

    /// Allowed for key derivation. Secret keys.
    pub(crate) derive: bool,

    /// Reserved.
    #[bits(15)]
    rsvd: u32,
}

/// Trait defining the HSM key vault interface.
///
/// Provides creation, deletion, and querying of cryptographic keys stored
/// in protected memory. Implementations are platform-specific:
/// - **Cortex-M7**: keys stored in on-chip SRAM with hardware protection.
/// - **Standard PAL**: keys stored on the heap for simulation/testing.
///
/// All methods are synchronous — vault operations are fast table lookups
/// or memory copies, not hardware-offloaded crypto.
pub trait HsmVault {
    /// Store a new key in the vault.
    ///
    /// # Parameters
    /// - `key` — The key material to store.
    /// - `kind` — The type/algorithm of the key (e.g., `Aes256`, `Ecc384Private`).
    /// - `session_id` — If `Some(id)`, the key is session-scoped and will be
    ///   deleted when the session closes. `None` for application-scoped keys.
    /// - `attrs` — Key attribute bitfield (encrypt, sign, extractable, etc.).
    /// - `meta` — Arbitrary per-key metadata blob (e.g., key label, DDI
    ///   target key metadata).
    ///
    /// # Returns
    /// A [`HsmVaultKeyId`] that uniquely identifies the stored key.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the vault is full or the key kind is invalid.
    fn vault_key_create(
        &self,
        pid: HsmPartId,
        key: &[u8],
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
        meta: &[u8],
    ) -> HsmResult<HsmKeyId>;

    /// Delete a key from the vault by ID.
    ///
    /// Zeroizes the key material and frees the slot.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key ID is invalid or the key is
    /// non-destroyable (internal key).
    fn vault_key_delete(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<()>;

    /// Delete all keys associated with the given session.
    ///
    /// Called during session close to clean up session-scoped keys.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the session ID is invalid.
    fn vault_key_delete_by_session(&self, pid: HsmPartId, session_id: HsmSessId) -> HsmResult<()>;

    /// Delete all keys from the vault.
    ///
    /// Zeroizes all key material and resets the vault to its initial
    /// empty state. Used during partition deallocation.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the clear operation fails.
    fn vault_clear(&self, pid: HsmPartId) -> HsmResult<()>;

    /// Retrieve the key material for a given key ID.
    ///
    /// # Returns
    /// A borrowed reference to the key material. The lifetime is tied
    /// to the vault's internal storage.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key ID is invalid or the slot is free.
    fn vault_key(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]>;

    /// Return the key material length in bytes for a given key kind.
    ///
    /// This is a static property of the key type (e.g., 32 for AES-256,
    /// 48 for ECC-384 private key) and does not require a key ID.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key kind is unknown.
    fn vault_key_len(&self, pid: HsmPartId, kind: HsmVaultKeyKind) -> HsmResult<u16>;

    /// Query the key kind for a stored key.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key ID is invalid.
    fn vault_key_kind(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind>;

    /// Query the attribute bitfield for a stored key.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key ID is invalid.
    fn vault_key_attrs(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs>;

    /// Query the metadata blob for a stored key.
    ///
    /// # Returns
    /// A borrowed reference to the per-key metadata set at creation time.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the key ID is invalid.
    fn vault_key_meta(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]>;
}
