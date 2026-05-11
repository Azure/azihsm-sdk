// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] implementation for the standard PAL.
//!
//! Delegates to the per-partition [`KeyVault`] stored inside each
//! [`PartitionEntry`].  Uses [`active_part`](StdHsmPal::active_part) /
//! [`active_part_mut`](StdHsmPal::active_part_mut) helpers for partition
//! access.  All methods are synchronous on the single-threaded Embassy
//! executor.
//!
//! ## RAII guards
//!
//! [`vault_key_create`] returns a [`StdVaultKeyGuard`] in a
//! *provisional* state — the key is removed from the vault on drop
//! unless the caller calls [`StdVaultKeyGuard::dismiss`] to commit.
//! Each guard captures the partition's incarnation counter (`gen`) at
//! create time; if the partition has since been freed and reallocated,
//! the rollback is skipped to avoid corrupting an unrelated incarnation.
//!
//! [`KeyVault`]: crate::drivers::vault::KeyVault
//! [`PartitionEntry`]: crate::part::PartitionEntry

use super::*;
use crate::drivers::vault::KeyVault;

/// RAII guard returned by [`HsmVault::vault_key_create`].
///
/// On drop, deletes the provisional vault entry unless
/// [`dismiss`](Self::dismiss) was called first.  Skips rollback if the
/// partition's incarnation counter has changed since the guard was
/// created (i.e., the partition was freed and reallocated).
pub struct StdVaultKeyGuard<'a> {
    pal: &'a StdHsmPal,
    pid: HsmPartId,
    /// Captured partition incarnation counter; rollback is a no-op
    /// if the live counter no longer matches.
    gen: u32,
    key_id: HsmKeyId,
    committed: bool,
}

impl VaultKeyGuard for StdVaultKeyGuard<'_> {
    fn key_id(&self) -> HsmKeyId {
        self.key_id
    }

    fn dismiss(mut self) -> HsmKeyId {
        self.committed = true;
        self.key_id
    }
}

impl Drop for StdVaultKeyGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.pal.partition_gen(self.pid) != self.gen {
            // Partition was freed/reallocated since this guard was
            // created.  The original key no longer exists; another
            // incarnation now owns the slot.
            return;
        }
        if let Ok(entry) = self.pal.active_part_mut(self.pid) {
            let _ = entry.vault.delete(self.key_id);
        }
    }
}

impl HsmVault for StdHsmPal {
    type KeyGuard<'a> = StdVaultKeyGuard<'a>;

    /// Store a new key in the partition's vault.
    ///
    /// If `session_id` is `Some`, maps the logical session ID to the
    /// physical vault key ID via the session table before storing.
    ///
    /// Returns a [`StdVaultKeyGuard`] — the key is auto-deleted on
    /// drop unless the caller calls
    /// [`VaultKeyGuard::dismiss`].
    fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &[u8],
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
        meta: &[u8],
    ) -> HsmResult<Self::KeyGuard<'_>> {
        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;
        let session_key_id = session_id
            .map(|sid| entry.session_table.physical_id(sid))
            .transpose()?;
        let key_id = entry.vault.create(key, kind, session_key_id, attrs, meta)?;
        Ok(StdVaultKeyGuard {
            pal: self,
            pid,
            gen: self.partition_gen(pid),
            key_id,
            committed: false,
        })
    }

    /// Delete a key from the partition's vault.
    fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.delete(key_id)
    }

    /// Delete all session-scoped keys for the given logical session.
    ///
    /// Maps the logical session ID to the physical vault key ID, then
    /// removes all vault entries bound to that physical ID.
    fn vault_key_delete_by_session(&self, io: &impl HsmIo, session_id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        let physical_id = entry.session_table.physical_id(session_id)?;
        entry.vault.delete_by_session_key(physical_id)
    }

    /// Clear all keys from the partition's vault.
    fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.clear();
        Ok(())
    }

    /// Retrieve key material by ID.
    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let entry = self.active_part(io.pid())?;
        let bytes = entry.vault.key(key_id)?;
        // SAFETY: on the host, "DMA" is a fiction — every heap-allocated
        // byte is reachable by every code path. Branding the slice as
        // `DmaBuf` only satisfies the type system; no DMA hardware is
        // involved.
        Ok(unsafe { DmaBuf::from_raw(bytes) })
    }

    /// Return the firmware raw key size for a given kind.
    fn vault_key_len(&self, _io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::key_len(kind)
    }

    /// Query key kind.
    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        let entry = self.active_part(io.pid())?;
        entry.vault.key_kind(key_id)
    }

    /// Query key attributes.
    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        let entry = self.active_part(io.pid())?;
        entry.vault.key_attrs(key_id)
    }

    /// Query key metadata.
    fn vault_key_meta(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&[u8]> {
        let entry = self.active_part(io.pid())?;
        entry.vault.key_meta(key_id)
    }
}
