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
}

/// Key attribute bitfield for vault-stored keys.
///
/// A 32-bit bitfield encoding PKCS#11-inspired key properties plus
/// HSM-specific flags.  Set at key creation time and governs which
/// operations are permitted on the key.
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
/// | 17–31 | `rsvd` | Reserved (must be zero) |
#[bitfield(u32)]
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
    #[bits(15)]
    rsvd: u32,
}

/// RAII guard for a newly created vault key.
///
/// Returned by [`HsmVault::vault_key_create`].  If dropped without
/// calling [`dismiss`](Self::dismiss), the key is automatically deleted
/// from the vault — providing rollback safety for multi-step DDI
/// operations (e.g., GenerateKeyPair creates private + public keys;
/// if the second create fails, the first is automatically rolled back).
///
/// # Usage
///
/// ```text
/// let guard = pal.vault_key_create(pid, key, kind, ...)?;
/// // ... more fallible work ...
/// let key_id = guard.dismiss();  // committed — key persists
/// ```
pub struct VaultKeyGuard<'a, P: HsmVault + ?Sized> {
    pal: &'a P,
    pid: HsmPartId,
    key_id: Option<HsmKeyId>,
}

impl<'a, P: HsmVault + ?Sized> VaultKeyGuard<'a, P> {
    /// Create a guard wrapping a newly created key.
    pub fn new(pal: &'a P, pid: HsmPartId, key_id: HsmKeyId) -> Self {
        Self {
            pal,
            pid,
            key_id: Some(key_id),
        }
    }

    /// Peek at the key ID (e.g., to read key material before committing).
    pub fn key_id(&self) -> HsmKeyId {
        self.key_id.unwrap()
    }

    /// Commit — key persists permanently.  Returns the key ID.
    pub fn dismiss(mut self) -> HsmKeyId {
        self.key_id.take().unwrap()
    }
}

impl<P: HsmVault + ?Sized> Drop for VaultKeyGuard<'_, P> {
    fn drop(&mut self) {
        if let Some(kid) = self.key_id.take() {
            let _ = self.pal.vault_key_delete(self.pid, kid);
        }
    }
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
    /// Returns a [`VaultKeyGuard`] that auto-deletes the key on drop
    /// unless [`dismiss`](VaultKeyGuard::dismiss) is called to persist it.
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
    /// A [`VaultKeyGuard`] wrapping the new key ID.
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
    ) -> HsmResult<VaultKeyGuard<'_, Self>>;

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
