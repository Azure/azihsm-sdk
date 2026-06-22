// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The key vault.
//!
//! [`KeyVault`] holds the create/lookup/delete logic over a
//! [`TableStorage`]. Per-key blob layout matches the reference firmware
//! exactly: each key occupies a block-aligned run of
//! `[ATTRIBUTES_BLOB_SIZE attrs][key]`, where the attribute blob is
//!
//! ```text
//!   [0..8)   HsmVaultKeyAttrs (u64, little-endian)
//!   [8..24)  reserved
//!   [24..32) entry-specific; bytes [24..26) hold the key length for
//!            variable-length kinds (else zero)
//! ```
//!
//! Following the reference firmware, the SDK `meta` (key label) is **not**
//! stored — it is consumed by the masked-key export path, not the vault.
//!
//! Key material larger than [`DMA_THRESHOLD`] bytes is copied/zeroed via
//! the GDMA engine ([`HsmGdmaController`]); smaller keys use a CPU copy.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::IntoBytes;

use crate::block::blocks_for;
use crate::entry::Entry;
use crate::kind::key_len;
use crate::kind::KeyLen;
use crate::storage::Attributes;
use crate::storage::TableStorage;
use crate::storage::ATTRIBUTES_BLOB_SIZE;
use crate::storage::BLOCK_ALIGNMENT;
use crate::storage::ENTRIES_PER_TABLE;

/// Key material at or below this many bytes is copied/zeroed by the CPU;
/// larger material uses the GDMA engine.
pub const DMA_THRESHOLD: usize = 128;

/// The per-partition key vault.
pub struct KeyVault<S> {
    storage: S,
}

impl<S: TableStorage> KeyVault<S> {
    /// Wraps `storage` (the partition's tables) as a vault.
    #[inline]
    pub fn new(storage: S) -> Self {
        KeyVault { storage }
    }

    /// Stores a new key, returning its [`HsmKeyId`].
    ///
    /// `key.len()` is validated against `kind` (fixed size, or the
    /// variable range). Material over [`DMA_THRESHOLD`] is copied via
    /// `gdma`; the attribute blob is always copied by the CPU.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `kind` is `Free`, or `key.len()` does
    ///   not satisfy `kind`'s length contract.
    /// - [`HsmError::InvalidKeyType`] — `kind` is unknown.
    /// - [`HsmError::NotEnoughSpace`] / [`HsmError::DefragmentationNeeded`]
    ///   — no slot or blob space.
    pub async fn create<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
        app_id: u8,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session: Option<u16>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        let spec = key_len(kind)?;
        let persisted_len = spec.check(key.len())?;
        let total = storage_bytes(persisted_len);
        let need = blocks_for(total);

        // Find a table the partition owns with both a free entry slot and
        // a free block run.
        let mut saw_defrag = false;
        for table in 0..self.storage.table_count() {
            if !self.storage.is_valid_table(table) {
                continue;
            }

            let Some(slot) = self.free_slot(table) else {
                continue;
            };

            // Reserve the run directly in the table's bitmap (in place — no
            // working copy is materialized). The reservation is committed
            // before the `.await` so nothing bitmap-sized crosses it; on a
            // failed key write we roll back: scrub the staged region and
            // free the run.
            let start = match crate::block::alloc(self.storage.bitmap_mut(table)?, need) {
                Ok(s) => s,
                Err(HsmError::DefragmentationNeeded) => {
                    saw_defrag = true;
                    continue;
                }
                Err(HsmError::NotEnoughSpace) => continue,
                Err(e) => return Err(e),
            };

            // Stage the entry's fields directly in storage. The slot is
            // not yet live for lookups until the key write succeeds (a
            // failed write rolls it back via `evict`).
            {
                let entry = self.storage.entry_mut(table, slot)?;
                entry.set_block_offset(start);
                entry.set_disabled(false);
                entry.set_session(session.is_some());
                entry.set_session_or_tag(session.unwrap_or(0));
                entry.set_kind(kind);
                entry.set_app_id(app_id);
            }

            // Write attributes blob.
            let mut attrs_blob = Attributes::ZERO;
            attrs_blob.attrs = attrs;
            if matches!(spec, KeyLen::Variable { .. }) {
                attrs_blob.var_len = persisted_len;
            }
            self.write_attrs(table, start, attrs_blob)?;

            // Write key material. On failure, use evict to clean up the staged region.
            if let Err(e) = self.write_key(gdma, io, table, start, key).await {
                let entry = *self.storage.entry(table, slot)?;
                self.evict(gdma, io, table, slot, entry).await?;
                return Err(e);
            }

            return Ok(make_key_id(table, slot));
        }

        Err(if saw_defrag {
            HsmError::DefragmentationNeeded
        } else {
            HsmError::NotEnoughSpace
        })
    }

    /// Deletes a single key, zeroing its material.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`] — `key_id` does not refer to a live
    ///   key.
    pub async fn delete<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
        key_id: HsmKeyId,
    ) -> HsmResult<()> {
        let (table, slot) = split_key_id(key_id);
        let entry = self.entry(table, slot)?;
        self.evict(gdma, io, table, slot, entry).await
    }

    /// Deletes every session-scoped key bound to `session`.
    pub async fn delete_by_session<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
        session: u16,
    ) -> HsmResult<()> {
        for table in 0..self.storage.table_count() {
            if !self.storage.is_valid_table(table) {
                continue;
            }
            for slot in 0..ENTRIES_PER_TABLE {
                let entry = *self.storage.entry(table, slot)?;
                if !entry.is_free() && entry.session() && entry.session_or_tag() == session {
                    self.evict(gdma, io, table, slot, entry).await?;
                }
            }
        }
        Ok(())
    }

    /// Deletes every key in every owned table, zeroing all material.
    pub async fn clear<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
    ) -> HsmResult<()> {
        for table in 0..self.storage.table_count() {
            if !self.storage.is_valid_table(table) {
                continue;
            }
            for slot in 0..ENTRIES_PER_TABLE {
                let entry = *self.storage.entry(table, slot)?;
                if !entry.is_free() {
                    self.evict(gdma, io, table, slot, entry).await?;
                }
            }
        }
        Ok(())
    }

    /// Borrows a key's raw material.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`] — `key_id` does not refer to a live
    ///   key.
    pub fn key(&self, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let (table, slot) = split_key_id(key_id);
        let entry = self.entry(table, slot)?;
        let len = self.resolved_len(table, &entry)?;
        let key_off = entry.attrs_byte_offset() + ATTRIBUTES_BLOB_SIZE;
        // Bound-check against the blob rather than indexing blindly: a
        // corrupted block offset / persisted length must surface as
        // `KeyNotFound`, never a panic (untrusted-input boundary).
        let blob = self.storage.blob(table)?;
        let end = key_off.checked_add(len).ok_or(HsmError::KeyNotFound)?;
        if end > blob.len() {
            return Err(HsmError::KeyNotFound);
        }
        Ok(&blob[key_off..end])
    }

    /// Returns a key's [`HsmVaultKeyKind`].
    pub fn key_kind(&self, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        let (table, slot) = split_key_id(key_id);
        Ok(self.entry(table, slot)?.kind())
    }

    /// Returns a key's [`HsmVaultKeyAttrs`].
    pub fn key_attrs(&self, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        let (table, slot) = split_key_id(key_id);
        let entry = self.entry(table, slot)?;
        Ok(self.read_attrs(table, entry.attrs_byte_offset())?.attrs)
    }

    /// Returns the canonical byte length for a key `kind` — the fixed size
    /// for fixed kinds, the maximum for variable kinds.
    pub fn key_len(kind: HsmVaultKeyKind) -> HsmResult<u16> {
        key_len(kind)?.max_len().ok_or(HsmError::InvalidKeyType)
    }

    /// Deletes a single key using a CPU zeroize (no GDMA), for use from
    /// synchronous contexts such as a guard's `Drop` rollback.
    ///
    /// Currently exercised only by tests; gated on `cfg(test)` so it is not
    /// compiled into the firmware. Promote to a normal `pub fn` if a
    /// synchronous production caller (e.g. a rollback guard) is added.
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`] — `key_id` does not refer to a live
    ///   key.
    #[cfg(test)]
    pub fn delete_sync(&mut self, key_id: HsmKeyId) -> HsmResult<()> {
        let (table, slot) = split_key_id(key_id);
        let entry = self.entry(table, slot)?;
        let len = self.resolved_len(table, &entry)?;
        let total = storage_bytes(len as u16);
        let attrs_off = entry.attrs_byte_offset();
        {
            let blob = self.storage.blob_mut(table)?;
            blob[attrs_off..attrs_off + total].fill(0);
        }
        crate::block::free(
            self.storage.bitmap_mut(table)?,
            entry.block_offset(),
            blocks_for(total),
        );
        *self.storage.entry_mut(table, slot)? = Entry::default();
        Ok(())
    }

    /// Resolves a live key to its `(table, blob byte offset, length)`
    /// without borrowing vault storage.
    ///
    /// Lets a caller whose storage is `'static` (e.g. firmware GSRAM)
    /// build a key reference with its own lifetime instead of one tied to
    /// a transient [`KeyVault`].
    ///
    /// # Errors
    ///
    /// - [`HsmError::KeyNotFound`] — `key_id` does not refer to a live
    ///   key.
    pub fn key_location(&self, key_id: HsmKeyId) -> HsmResult<(usize, usize, usize)> {
        let (table, slot) = split_key_id(key_id);
        let entry = self.entry(table, slot)?;
        let len = self.resolved_len(table, &entry)?;
        let off = entry.attrs_byte_offset() + ATTRIBUTES_BLOB_SIZE;
        // Validate `off..off+len` lies within the table blob: callers
        // build a raw pointer/slice from this tuple (e.g. the Uno PAL),
        // so corrupted entry metadata must surface as `KeyNotFound`
        // rather than an out-of-bounds read / unsound `DmaBuf`.
        let blob_len = self.storage.blob(table)?.len();
        let end = off.checked_add(len).ok_or(HsmError::KeyNotFound)?;
        if end > blob_len {
            return Err(HsmError::KeyNotFound);
        }
        Ok((table, off, len))
    }

    /// Test-only borrow of the backing storage (for asserting on raw
    /// blob bytes, e.g. zeroization after delete).
    #[cfg(test)]
    pub(crate) fn storage(&self) -> &S {
        &self.storage
    }

    // ── internals ───────────────────────────────────────────────────

    fn free_slot(&self, table: usize) -> Option<usize> {
        (0..ENTRIES_PER_TABLE).find(|&i| self.storage.entry(table, i).is_ok_and(Entry::is_free))
    }

    fn entry(&self, table: usize, slot: usize) -> HsmResult<Entry> {
        if !self.storage.is_valid_table(table) || slot >= ENTRIES_PER_TABLE {
            return Err(HsmError::KeyNotFound);
        }
        let entry = *self.storage.entry(table, slot)?;
        if entry.is_free() || entry.disabled() {
            return Err(HsmError::KeyNotFound);
        }
        Ok(entry)
    }

    fn write_attrs(&mut self, table: usize, block: u16, attrs: Attributes) -> HsmResult<()> {
        let attrs_off = usize::from(block) * BLOCK_ALIGNMENT;
        let blob = self.storage.blob_mut(table)?;
        let bytes = attrs.as_bytes();
        blob[attrs_off..attrs_off + ATTRIBUTES_BLOB_SIZE].copy_from_slice(bytes);
        Ok(())
    }

    fn read_attrs(&self, table: usize, attrs_off: usize) -> HsmResult<Attributes> {
        let blob = self.storage.blob(table)?;
        // Checked slice: a corrupted/out-of-range `attrs_off` must return
        // an error, not panic. Copying into an aligned `Attributes` also
        // avoids any alignment assumption on the blob bytes.
        let end = attrs_off
            .checked_add(ATTRIBUTES_BLOB_SIZE)
            .ok_or(HsmError::KeyNotFound)?;
        let bytes = blob.get(attrs_off..end).ok_or(HsmError::KeyNotFound)?;
        let mut attrs = Attributes::ZERO;
        attrs.as_mut_bytes().copy_from_slice(bytes);
        Ok(attrs)
    }

    /// Resolves a stored key's length: fixed from `kind`, variable from
    /// the persisted length field.
    fn resolved_len(&self, table: usize, entry: &Entry) -> HsmResult<usize> {
        match key_len(entry.kind())? {
            KeyLen::Fixed(n) => Ok(usize::from(n)),
            KeyLen::Variable { .. } => {
                let attrs = self.read_attrs(table, entry.attrs_byte_offset())?;
                Ok(usize::from(attrs.var_len))
            }
            KeyLen::Invalid => Err(HsmError::InvalidKeyType),
        }
    }

    async fn write_key<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
        table: usize,
        block: u16,
        key: &DmaBuf,
    ) -> HsmResult<()> {
        let key_off = usize::from(block) * BLOCK_ALIGNMENT + ATTRIBUTES_BLOB_SIZE;
        let len = key.len();
        let blob = self.storage.blob_mut(table)?;
        let dst = &mut blob[key_off..key_off + len];
        if len > DMA_THRESHOLD {
            gdma.copy_mem(io, key, dst).await
        } else {
            dst.copy_from_slice(key);
            Ok(())
        }
    }

    /// Zeroes a key's storage, frees its blocks, and clears its slot.
    async fn evict<G: HsmGdmaController>(
        &mut self,
        gdma: &G,
        io: &impl HsmIo,
        table: usize,
        slot: usize,
        entry: Entry,
    ) -> HsmResult<()> {
        let len = self.resolved_len(table, &entry)?;
        let total = storage_bytes(len as u16);
        let attrs_off = entry.attrs_byte_offset();

        // Zeroize the whole [attrs][key] region.
        {
            let blob = self.storage.blob_mut(table)?;
            // Checked slice: inconsistent/corrupted entry metadata must
            // surface as an error rather than panic on out-of-range index.
            let end = attrs_off.checked_add(total).ok_or(HsmError::KeyNotFound)?;
            if end > blob.len() {
                return Err(HsmError::KeyNotFound);
            }
            let region = &mut blob[attrs_off..end];
            if total > DMA_THRESHOLD {
                gdma.zeroize_mem(io, region).await?;
            } else {
                region.zeroize();
            }
        }

        // Free the blocks and clear the slot.
        crate::block::free(
            self.storage.bitmap_mut(table)?,
            entry.block_offset(),
            blocks_for(total),
        );
        *self.storage.entry_mut(table, slot)? = Entry::default();
        Ok(())
    }
}

/// Packs `(table, entry)` into the wire key ID, matching the reference
/// firmware's `KeyNumber`.
#[inline]
fn make_key_id(table: usize, entry: usize) -> HsmKeyId {
    HsmKeyId::from(((table as u16) << 8) | entry as u16)
}

/// Splits a key ID into `(table, entry)`.
#[inline]
fn split_key_id(key_id: HsmKeyId) -> (usize, usize) {
    let raw = u16::from(key_id);
    (usize::from(raw >> 8), usize::from(raw & 0xFF))
}

/// Block-aligned total storage for a key of `key_len` bytes
/// (`attributes + align8(key)`).
#[inline]
fn storage_bytes(key_len: u16) -> usize {
    let aligned = (usize::from(key_len) + BLOCK_ALIGNMENT - 1) & !(BLOCK_ALIGNMENT - 1);
    ATTRIBUTES_BLOB_SIZE + aligned
}
