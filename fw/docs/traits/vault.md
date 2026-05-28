# HsmVault — Key Storage and Metadata

**Crate:** `azihsm_fw_hsm_pal_traits`
**File:** `fw/pal/traits/src/vault.rs`

## Overview

The vault trait defines the HSM key management interface. Keys are stored in protected memory (SRAM on hardware, heap on the standard PAL) and tracked by type, attributes, and per-key metadata.

## Key Lifecycle

```
vault_key_create(key_bytes, kind, session, attrs, meta) → VaultKeyGuard → dismiss() → key_id
  ↓
vault_key(key_id)       → &[u8] key material
vault_key_kind(key_id)  → HsmVaultKeyKind
vault_key_attrs(key_id) → HsmVaultKeyAttrs
vault_key_meta(key_id)  → &[u8] metadata blob
  ↓
vault_key_delete(key_id)
vault_key_delete_by_session(session_id)
vault_clear()
```

## Key Kinds

```rust
pub enum HsmVaultKeyKind {
    Free = 0,

    // RSA Public Keys
    Rsa2kPublic = 1, Rsa3kPublic = 2, Rsa4kPublic = 3,

    // RSA Private Keys
    Rsa2kPrivate = 4, Rsa3kPrivate = 5, Rsa4kPrivate = 6,

    // RSA Private CRT Keys
    Rsa2kPrivateCrt = 7, Rsa3kPrivateCrt = 8, Rsa4kPrivateCrt = 9,

    // ECC Public Keys
    Ecc256Public = 10, Ecc384Public = 11, Ecc521Public = 12,

    // ECC Private Keys
    Ecc256Private = 13, Ecc384Private = 14, Ecc521Private = 15,

    // AES Symmetric Keys
    Aes128 = 16, Aes192 = 17, Aes256 = 18,

    // AES Bulk Keys
    AesXtsBulk256 = 19, AesGcmBulk256 = 20, AesGcmBulk256Unapproved = 21,

    // ECDH Shared Secrets
    Secret256 = 22, Secret384 = 23, Secret521 = 24,

    // Internal Keys (partition lifecycle)
    EstablishCred = 25, SessionEncryption = 26, Session = 27,

    // HMAC Keys (fixed length)
    _HmacSha256 = 28, _HmacSha384 = 29, _HmacSha512 = 30,

    // Masking Key
    MaskingKey = 31,

    // HMAC Keys (variable length)
    VarLenHmacSha256 = 32, VarLenHmacSha384 = 33, VarLenHmacSha512 = 34,
}
```

## Key Attributes

A 32-bit bitfield encoding PKCS#11-inspired properties:

```rust
pub struct HsmVaultKeyAttrs {
    pub internal: bool,          // Bit 0: device-internal, not user-destroyable
    pub session: bool,           // Bit 1: session-scoped, auto-deleted on close
    pub private: bool,           // Bit 2: requires authenticated session
    pub modifiable: bool,        // Bit 3: attributes can change post-creation
    pub destroyable: bool,       // Bit 4: user can delete
    pub local: bool,             // Bit 5: generated on-device (not imported)
    pub extractable: bool,       // Bit 6: key material can be exported
    pub never_extractable: bool, // Bit 7: has never been extractable
    pub trusted: bool,           // Bit 8: can wrap other keys
    pub wrap_with_trusted: bool, // Bit 9: only wrappable by trusted keys
    pub encrypt: bool,           // Bit 10: allowed for encryption
    pub decrypt: bool,           // Bit 11: allowed for decryption
    pub sign: bool,              // Bit 12: allowed for signing
    pub verify: bool,            // Bit 13: allowed for verification
    pub wrap: bool,              // Bit 14: allowed for key wrapping
    pub unwrap: bool,            // Bit 15: allowed for key unwrapping
    pub derive: bool,            // Bit 16: allowed for key derivation
    // Bits 17–31: reserved
}
```

## VaultKeyGuard

RAII guard returned by `vault_key_create`. If dropped without `dismiss()`, the key is automatically deleted — providing rollback safety for multi-step operations.

```rust
pub struct VaultKeyGuard<'a, P: HsmVault + ?Sized> { ... }

impl VaultKeyGuard {
    pub fn key_id(&self) -> HsmKeyId;    // Peek at key ID before committing
    pub fn dismiss(self) -> HsmKeyId;    // Commit — key persists permanently
}
// Drop without dismiss → vault_key_delete(key_id)
```

## Trait Methods

```rust
pub trait HsmVault {
    fn vault_key_create(
        &self, pid: HsmPartId, key: &[u8], kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>, attrs: HsmVaultKeyAttrs, meta: &[u8],
    ) -> HsmResult<VaultKeyGuard<'_, Self>>;

    fn vault_key_delete(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<()>;
    fn vault_key_delete_by_session(&self, pid: HsmPartId, session_id: HsmSessId) -> HsmResult<()>;
    fn vault_clear(&self, pid: HsmPartId) -> HsmResult<()>;

    fn vault_key(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]>;
    fn vault_key_len(&self, pid: HsmPartId, kind: HsmVaultKeyKind) -> HsmResult<u16>;
    fn vault_key_kind(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind>;
    fn vault_key_attrs(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs>;
    fn vault_key_meta(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]>;
}
```

## Currently Implemented Internal Keys

| Key | Kind | Attributes | Created | Destroyed | Purpose |
|-----|------|-----------|---------|-----------|---------|
| Partition Identity | `Ecc384Private` | `internal`, `local`, `sign` | `part_alloc` | `part_free` | Signs encryption key responses |
| Establish-Cred Encryption | `EstablishCred` | `internal`, `local`, `derive` | `part_enable` | After credential establishment or `part_disable` | ECDH for credential encryption |
| Session Encryption | `SessionEncryption` | `internal`, `local`, `derive` | `part_enable` | `part_disable` | ECDH for session encryption |
