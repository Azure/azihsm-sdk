// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-partition key vault emulating the firmware's multi-table storage
//! model.
//!
//! Each partition is assigned a set of vault tables (one per resource
//! bit in the partition's `res_mask`).  Each table holds up to
//! [`MAX_ENTRIES_PER_TABLE`] key entries and tracks a byte budget of
//! [`BLOB_MEMORY_SIZE`] bytes — the same limits as the physical
//! hardware SRAM.
//!
//! ## Capacity emulation
//!
//! The std PAL stores keys on the heap as `Vec<u8>`, but tracks
//! firmware-equivalent storage cost per key using [`fw_storage_cost`].
//! This ensures the simulator never accepts more keys than real
//! hardware could hold, even though the actual byte representation
//! may differ (e.g., DER-encoded private keys are larger than raw).
//!
//! ## Key ID encoding
//!
//! Key IDs pack `(table_index << 8) | entry_index` into a `u16`,
//! matching the firmware's [`KeyNumber`] layout.  This means a single
//! partition can address up to `65 × 256 = 16,640` key slots.
//!
//! ## Session scoping
//!
//! Keys can optionally be bound to a session via `session_id`.
//! [`KeyVault::delete_by_session_key`] removes all keys matching a given
//! session key ID — called during session close.

use azihsm_fw_hsm_pal_traits::*;

// ---------------------------------------------------------------------------
// Firmware-matching constants
// ---------------------------------------------------------------------------

/// Maximum tables across all partitions (= maximum resources).
#[allow(dead_code)]
pub const MAX_TABLE_COUNT: usize = 65;

/// Maximum entries (key slots) per table.
const MAX_ENTRIES_PER_TABLE: usize = 256;

/// Blob memory available per table for key + attribute storage (bytes).
///
/// Derived from firmware: `TOTAL_TABLE_LEN(17408) - METADATA_LIST(2048)
/// - BLOCK_TRACKING(256) = 15104`.
const BLOB_MEMORY_SIZE: usize = 15104;

/// Size of the attributes blob prepended to each key in firmware storage.
const ATTRIBUTES_BLOB_SIZE: usize = 32;

/// Alignment of blob blocks in firmware storage (bytes).
const BLOB_BLOCK_ALIGNMENT: usize = 8;

// ---------------------------------------------------------------------------
// Key size lookup — firmware raw key sizes
// ---------------------------------------------------------------------------

/// Returns the raw key blob size on the physical device for a given key
/// kind.  Source: `EntryKind::raw_key_blob_size()`.
///
/// Returns `None` for `Free` or unknown kinds, and for variable-length
/// HMAC kinds (whose size depends on the actual key).
pub fn fw_key_size(kind: HsmVaultKeyKind) -> Option<usize> {
    Some(match kind {
        HsmVaultKeyKind::Rsa2kPublic => 260,
        HsmVaultKeyKind::Rsa3kPublic => 388,
        HsmVaultKeyKind::Rsa4kPublic => 516,
        HsmVaultKeyKind::Rsa2kPrivate => 516,
        HsmVaultKeyKind::Rsa3kPrivate => 772,
        HsmVaultKeyKind::Rsa4kPrivate => 1028,
        HsmVaultKeyKind::Rsa2kPrivateCrt => 1284,
        HsmVaultKeyKind::Rsa3kPrivateCrt => 1924,
        HsmVaultKeyKind::Rsa4kPrivateCrt => 2564,
        HsmVaultKeyKind::Ecc256Public => 64,
        HsmVaultKeyKind::Ecc384Public => 96,
        HsmVaultKeyKind::Ecc521Public => 136,
        HsmVaultKeyKind::Ecc256Private => 32,
        HsmVaultKeyKind::Ecc384Private => 48,
        HsmVaultKeyKind::Ecc521Private => 68,
        HsmVaultKeyKind::Aes128 => 16,
        HsmVaultKeyKind::Aes192 => 24,
        HsmVaultKeyKind::Aes256 => 32,
        HsmVaultKeyKind::AesXtsBulk256
        | HsmVaultKeyKind::AesGcmBulk256
        | HsmVaultKeyKind::AesGcmBulk256Unapproved => 2,
        HsmVaultKeyKind::Secret256 => 32,
        HsmVaultKeyKind::Secret384 => 48,
        HsmVaultKeyKind::Secret521 => 68,
        HsmVaultKeyKind::EstablishCred => 144,
        HsmVaultKeyKind::SessionEncryption => 144,
        HsmVaultKeyKind::Session => 88,
        HsmVaultKeyKind::_HmacSha256 => 32,
        HsmVaultKeyKind::_HmacSha384 => 48,
        HsmVaultKeyKind::_HmacSha512 => 64,
        HsmVaultKeyKind::MaskingKey => 80,
        HsmVaultKeyKind::PartitionTrustAnchor => 48,
        HsmVaultKeyKind::PartitionUniqueMachineSecret => 48,
        // SessionCu is length-discriminated by session type
        // (PlainText=168, Authenticated=264); reported as variable
        // length, same handling as VarLenHmac*.
        HsmVaultKeyKind::SessionCu => return None,
        // Variable-length HMAC — size depends on actual key.
        HsmVaultKeyKind::VarLenHmacSha256
        | HsmVaultKeyKind::VarLenHmacSha384
        | HsmVaultKeyKind::VarLenHmacSha512 => return None,
        HsmVaultKeyKind::Free => return None,
        _ => return None,
    })
}

/// Compute the firmware-equivalent storage cost for a key.
///
/// Each key occupies `ATTRIBUTES_BLOB_SIZE + align8(raw_key_size)` bytes
/// in a table's blob memory.  For variable-length HMAC keys, the actual
/// key length is used instead of a fixed size.
///
/// Returns `None` if the kind is unknown or `Free`.
fn fw_storage_cost(kind: HsmVaultKeyKind, actual_len: usize) -> Option<usize> {
    let raw = match fw_key_size(kind) {
        Some(n) => n,
        None if matches!(
            kind,
            HsmVaultKeyKind::VarLenHmacSha256
                | HsmVaultKeyKind::VarLenHmacSha384
                | HsmVaultKeyKind::VarLenHmacSha512
                | HsmVaultKeyKind::SessionCu
        ) =>
        {
            actual_len
        }
        None => return None,
    };
    let aligned = (raw + BLOB_BLOCK_ALIGNMENT - 1) & !(BLOB_BLOCK_ALIGNMENT - 1);
    Some(ATTRIBUTES_BLOB_SIZE + aligned)
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single stored key with its metadata.
struct VaultEntry {
    /// Raw key material (may differ in size from firmware representation).
    key: Vec<u8>,
    /// Algorithm/size discriminant.
    kind: HsmVaultKeyKind,
    /// PKCS#11-inspired attribute bitfield.
    attrs: HsmVaultKeyAttrs,
    /// Physical session key ID — `None` for app-scoped keys, `Some(phys)`
    /// for session-scoped keys where `phys` is the vault key ID of the
    /// session blob.
    session_key_id: Option<HsmKeyId>,
    /// Arbitrary per-key metadata blob.
    meta: Vec<u8>,
    /// Firmware-equivalent storage cost (for capacity tracking).
    cost: usize,
}

/// One vault sub-table emulating a single firmware table.
///
/// Tracks both entry slot occupancy and a firmware-equivalent byte
/// budget to accurately limit key capacity.
struct VaultSubTable {
    /// Fixed array of 256 key slots.
    entries: Box<[Option<VaultEntry>; MAX_ENTRIES_PER_TABLE]>,
    /// Firmware-equivalent bytes used (`ATTRIBUTES_BLOB_SIZE + align8(key)`
    /// per entry).  Must not exceed [`BLOB_MEMORY_SIZE`].
    used_bytes: usize,
}

impl VaultSubTable {
    fn new() -> Self {
        Self {
            entries: Box::new(core::array::from_fn(|_| None)),
            used_bytes: 0,
        }
    }
}

/// Per-partition key vault spanning multiple sub-tables.
///
/// The number of tables equals `res_mask.count_ones()` from the
/// partition's resource allocation.
pub struct KeyVault {
    tables: Vec<VaultSubTable>,
}

impl KeyVault {
    /// Create a vault with `table_count` empty sub-tables.
    pub fn new(table_count: usize) -> Self {
        Self {
            tables: (0..table_count).map(|_| VaultSubTable::new()).collect(),
        }
    }

    /// Store a new key in the vault.
    ///
    /// Scans tables in order for the first with a free entry slot and
    /// enough byte budget.  Returns the packed key ID
    /// `(table_idx << 8 | entry_idx)`.
    pub fn create(
        &mut self,
        key: &[u8],
        kind: HsmVaultKeyKind,
        session_key_id: Option<HsmKeyId>,
        attrs: HsmVaultKeyAttrs,
        meta: &[u8],
    ) -> HsmResult<HsmKeyId> {
        let cost = fw_storage_cost(kind, key.len()).ok_or(HsmError::InvalidKeyType)?;

        for (table_idx, table) in self.tables.iter_mut().enumerate() {
            if table.used_bytes + cost > BLOB_MEMORY_SIZE {
                continue;
            }
            let Some(entry_idx) = table.entries.iter().position(|e| e.is_none()) else {
                continue;
            };

            table.entries[entry_idx] = Some(VaultEntry {
                key: key.to_vec(),
                kind,
                attrs,
                session_key_id,
                meta: meta.to_vec(),
                cost,
            });
            table.used_bytes += cost;

            let key_id = ((table_idx as u16) << 8) | entry_idx as u16;
            return Ok(HsmKeyId::from(key_id));
        }

        Err(HsmError::NotEnoughSpace)
    }

    /// Delete a key by ID, zeroizing its material.
    pub fn delete(&mut self, key_id: HsmKeyId) -> HsmResult<()> {
        let (table_idx, entry_idx) = split_key_id(key_id);
        let table = self
            .tables
            .get_mut(table_idx)
            .ok_or(HsmError::KeyNotFound)?;
        let slot = table
            .entries
            .get_mut(entry_idx)
            .ok_or(HsmError::KeyNotFound)?;
        let entry = slot.take().ok_or(HsmError::KeyNotFound)?;
        table.used_bytes -= entry.cost;
        // Key material in entry.key is dropped (Vec deallocated).
        // In a real zeroize implementation we'd use zeroize crate.
        Ok(())
    }

    /// Delete all keys bound to the given physical session key ID.
    pub fn delete_by_session_key(&mut self, session_key_id: HsmKeyId) -> HsmResult<()> {
        for table in &mut self.tables {
            for slot in table.entries.iter_mut() {
                if let Some(entry) = slot {
                    if entry.session_key_id == Some(session_key_id) {
                        table.used_bytes -= entry.cost;
                        *slot = None;
                    }
                }
            }
        }
        Ok(())
    }

    /// Clear all keys from the vault, resetting to empty state.
    pub fn clear(&mut self) {
        for table in &mut self.tables {
            for slot in table.entries.iter_mut() {
                *slot = None;
            }
            table.used_bytes = 0;
        }
    }

    /// Retrieve the key material for a given key ID.
    pub fn key(&self, key_id: HsmKeyId) -> HsmResult<&[u8]> {
        let entry = self.get_entry(key_id)?;
        Ok(&entry.key)
    }

    /// Return the firmware raw key size for a given kind.
    pub fn key_len(kind: HsmVaultKeyKind) -> HsmResult<u16> {
        fw_key_size(kind)
            .map(|s| s as u16)
            .ok_or(HsmError::InvalidKeyType)
    }

    /// Query the key kind.
    pub fn key_kind(&self, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        Ok(self.get_entry(key_id)?.kind)
    }

    /// Query the key attributes.
    pub fn key_attrs(&self, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        Ok(self.get_entry(key_id)?.attrs)
    }

    /// Query the key metadata.
    pub fn key_meta(&self, key_id: HsmKeyId) -> HsmResult<&[u8]> {
        Ok(&self.get_entry(key_id)?.meta)
    }

    /// Number of tables in this vault.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn get_entry(&self, key_id: HsmKeyId) -> HsmResult<&VaultEntry> {
        let (table_idx, entry_idx) = split_key_id(key_id);
        let table = self.tables.get(table_idx).ok_or(HsmError::KeyNotFound)?;
        table
            .entries
            .get(entry_idx)
            .and_then(|s| s.as_ref())
            .ok_or(HsmError::KeyNotFound)
    }
}

/// Split a packed key ID into `(table_index, entry_index)`.
fn split_key_id(key_id: HsmKeyId) -> (usize, usize) {
    let raw = u16::from(key_id);
    ((raw >> 8) as usize, (raw & 0xFF) as usize)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn aes256_attrs() -> HsmVaultKeyAttrs {
        HsmVaultKeyAttrs::new()
            .with_encrypt(true)
            .with_decrypt(true)
    }

    #[test]
    fn create_and_retrieve() {
        let mut vault = KeyVault::new(1);
        let key_data = [0xAA; 32];
        let kid = vault
            .create(
                &key_data,
                HsmVaultKeyKind::Aes256,
                None,
                aes256_attrs(),
                &[],
            )
            .unwrap();
        assert_eq!(vault.key(kid).unwrap(), &key_data);
    }

    #[test]
    fn create_returns_packed_ids() {
        let mut vault = KeyVault::new(2);
        let key = [0u8; 32];
        let k0 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        let k1 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        // Both in table 0, entries 0 and 1.
        assert_eq!(u16::from(k0), 0x0000);
        assert_eq!(u16::from(k1), 0x0001);
    }

    #[test]
    fn delete_and_reuse() {
        let mut vault = KeyVault::new(1);
        let key = [0u8; 32];
        let kid = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        vault.delete(kid).unwrap();
        // Slot 0 is free again.
        let kid2 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        assert_eq!(u16::from(kid2), 0x0000);
    }

    #[test]
    fn delete_nonexistent_fails() {
        let mut vault = KeyVault::new(1);
        let err = vault.delete(HsmKeyId::from(0u16)).unwrap_err();
        assert_eq!(err, HsmError::KeyNotFound);
    }

    #[test]
    fn delete_by_session_key() {
        let mut vault = KeyVault::new(1);
        let key = [0u8; 32];
        let sess_key = Some(HsmKeyId::from(5u16));

        // 3 session-scoped keys.
        let s0 = vault
            .create(&key, HsmVaultKeyKind::Aes256, sess_key, aes256_attrs(), &[])
            .unwrap();
        let s1 = vault
            .create(&key, HsmVaultKeyKind::Aes256, sess_key, aes256_attrs(), &[])
            .unwrap();
        let s2 = vault
            .create(&key, HsmVaultKeyKind::Aes256, sess_key, aes256_attrs(), &[])
            .unwrap();

        // 2 app-scoped keys.
        let a0 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        let a1 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();

        vault.delete_by_session_key(HsmKeyId::from(5u16)).unwrap();

        // Session keys gone.
        assert!(vault.key(s0).is_err());
        assert!(vault.key(s1).is_err());
        assert!(vault.key(s2).is_err());
        // App keys survive.
        assert!(vault.key(a0).is_ok());
        assert!(vault.key(a1).is_ok());
    }

    #[test]
    fn delete_by_session_key_no_match() {
        let mut vault = KeyVault::new(1);
        // No keys at all — should succeed silently.
        vault.delete_by_session_key(HsmKeyId::from(99u16)).unwrap();
    }

    #[test]
    fn single_table_byte_budget() {
        let mut vault = KeyVault::new(1);
        let key = [0u8; 32];
        // AES-256 storage cost = 32 (attrs) + 32 (aligned key) = 64 bytes.
        // Budget = 15104 / 64 = 236 keys.
        let expected = BLOB_MEMORY_SIZE / fw_storage_cost(HsmVaultKeyKind::Aes256, 32).unwrap();
        let mut count = 0;
        loop {
            match vault.create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[]) {
                Ok(_) => count += 1,
                Err(HsmError::NotEnoughSpace) => break,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(count, expected);
    }

    #[test]
    fn multi_table_capacity() {
        let key = [0u8; 32];
        let per_table = BLOB_MEMORY_SIZE / fw_storage_cost(HsmVaultKeyKind::Aes256, 32).unwrap();

        let mut vault3 = KeyVault::new(3);
        let mut count = 0;
        while vault3
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .is_ok()
        {
            count += 1;
        }
        assert_eq!(count, per_table * 3);
    }

    #[test]
    fn large_key_byte_budget() {
        let mut vault = KeyVault::new(1);
        // RSA 4K CRT: raw = 2564, aligned = 2568, cost = 2600.
        let cost = fw_storage_cost(HsmVaultKeyKind::Rsa4kPrivateCrt, 2564).unwrap();
        let expected = BLOB_MEMORY_SIZE / cost;
        let key = vec![0u8; 2564];
        let mut count = 0;
        let attrs = HsmVaultKeyAttrs::new().with_sign(true);
        loop {
            match vault.create(&key, HsmVaultKeyKind::Rsa4kPrivateCrt, None, attrs, &[]) {
                Ok(_) => count += 1,
                Err(HsmError::NotEnoughSpace) => break,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(count, expected);
    }

    #[test]
    fn entry_slot_limit() {
        // With tiny keys (AES-128 = cost 48), the slot limit (256) is
        // reached before the byte budget (15104/48 = 314).
        let mut vault = KeyVault::new(2);
        let key = [0u8; 16];
        let attrs = HsmVaultKeyAttrs::new().with_encrypt(true);
        let mut count = 0;
        while vault
            .create(&key, HsmVaultKeyKind::Aes128, None, attrs, &[])
            .is_ok()
        {
            count += 1;
        }
        // 256 per table × 2 tables (byte budget allows ~314 per table,
        // but slot limit caps at 256).
        assert_eq!(count, 256 * 2);
    }

    #[test]
    fn create_free_kind_fails() {
        let mut vault = KeyVault::new(1);
        let err = vault
            .create(
                &[],
                HsmVaultKeyKind::Free,
                None,
                HsmVaultKeyAttrs::new(),
                &[],
            )
            .unwrap_err();
        assert_eq!(err, HsmError::InvalidKeyType);
    }

    #[test]
    fn key_kind_query() {
        let mut vault = KeyVault::new(1);
        let kid = vault
            .create(
                &[0; 48],
                HsmVaultKeyKind::Ecc384Private,
                None,
                HsmVaultKeyAttrs::new().with_sign(true),
                &[],
            )
            .unwrap();
        assert_eq!(vault.key_kind(kid).unwrap(), HsmVaultKeyKind::Ecc384Private);
    }

    #[test]
    fn key_attrs_query() {
        let mut vault = KeyVault::new(1);
        let attrs = HsmVaultKeyAttrs::new()
            .with_sign(true)
            .with_local(true)
            .with_never_extractable(true);
        let kid = vault
            .create(&[0; 48], HsmVaultKeyKind::Ecc384Private, None, attrs, &[])
            .unwrap();
        assert_eq!(vault.key_attrs(kid).unwrap(), attrs);
    }

    #[test]
    fn key_meta_query() {
        let mut vault = KeyVault::new(1);
        let meta = b"my-key-label";
        let kid = vault
            .create(
                &[0; 32],
                HsmVaultKeyKind::Aes256,
                None,
                aes256_attrs(),
                meta,
            )
            .unwrap();
        assert_eq!(vault.key_meta(kid).unwrap(), meta);
    }

    #[test]
    fn key_len_all_fixed_kinds() {
        let cases: &[(HsmVaultKeyKind, u16)] = &[
            (HsmVaultKeyKind::Rsa2kPublic, 260),
            (HsmVaultKeyKind::Rsa3kPublic, 388),
            (HsmVaultKeyKind::Rsa4kPublic, 516),
            (HsmVaultKeyKind::Rsa2kPrivate, 516),
            (HsmVaultKeyKind::Rsa3kPrivate, 772),
            (HsmVaultKeyKind::Rsa4kPrivate, 1028),
            (HsmVaultKeyKind::Rsa2kPrivateCrt, 1284),
            (HsmVaultKeyKind::Rsa3kPrivateCrt, 1924),
            (HsmVaultKeyKind::Rsa4kPrivateCrt, 2564),
            (HsmVaultKeyKind::Ecc256Public, 64),
            (HsmVaultKeyKind::Ecc384Public, 96),
            (HsmVaultKeyKind::Ecc521Public, 136),
            (HsmVaultKeyKind::Ecc256Private, 32),
            (HsmVaultKeyKind::Ecc384Private, 48),
            (HsmVaultKeyKind::Ecc521Private, 68),
            (HsmVaultKeyKind::Aes128, 16),
            (HsmVaultKeyKind::Aes192, 24),
            (HsmVaultKeyKind::Aes256, 32),
            (HsmVaultKeyKind::AesXtsBulk256, 2),
            (HsmVaultKeyKind::AesGcmBulk256, 2),
            (HsmVaultKeyKind::AesGcmBulk256Unapproved, 2),
            (HsmVaultKeyKind::Secret256, 32),
            (HsmVaultKeyKind::Secret384, 48),
            (HsmVaultKeyKind::Secret521, 68),
            (HsmVaultKeyKind::EstablishCred, 144),
            (HsmVaultKeyKind::SessionEncryption, 144),
            (HsmVaultKeyKind::Session, 88),
            (HsmVaultKeyKind::_HmacSha256, 32),
            (HsmVaultKeyKind::_HmacSha384, 48),
            (HsmVaultKeyKind::_HmacSha512, 64),
            (HsmVaultKeyKind::MaskingKey, 80),
            (HsmVaultKeyKind::PartitionTrustAnchor, 48),
            (HsmVaultKeyKind::PartitionUniqueMachineSecret, 48),
        ];
        for &(kind, expected) in cases {
            assert_eq!(
                KeyVault::key_len(kind).unwrap(),
                expected,
                "mismatch for {kind:?}"
            );
        }
    }

    #[test]
    fn key_len_free_fails() {
        assert_eq!(
            KeyVault::key_len(HsmVaultKeyKind::Free).unwrap_err(),
            HsmError::InvalidKeyType
        );
    }

    #[test]
    fn vault_clear() {
        let mut vault = KeyVault::new(1);
        let key = [0u8; 32];
        let k0 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        let k1 = vault
            .create(&key, HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap();
        vault.clear();
        assert!(vault.key(k0).is_err());
        assert!(vault.key(k1).is_err());
    }

    #[test]
    fn empty_vault_no_tables() {
        let mut vault = KeyVault::new(0);
        let err = vault
            .create(&[0; 32], HsmVaultKeyKind::Aes256, None, aes256_attrs(), &[])
            .unwrap_err();
        assert_eq!(err, HsmError::NotEnoughSpace);
    }
}
