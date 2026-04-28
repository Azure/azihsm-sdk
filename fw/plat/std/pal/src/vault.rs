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
//! [`KeyVault`]: crate::drivers::vault::KeyVault
//! [`PartitionEntry`]: crate::part::PartitionEntry

use super::*;
use crate::drivers::vault::KeyVault;

impl HsmVault for StdHsmPal {
    /// Store a new key in the partition's vault.
    ///
    /// If `session_id` is `Some`, maps the logical session ID to the
    /// physical vault key ID via the session table before storing.
    ///
    /// Returns a [`VaultKeyGuard`] — the key is auto-deleted on drop
    /// unless the caller calls [`dismiss`](VaultKeyGuard::dismiss).
    fn vault_key_create(
        &self,
        pid: HsmPartId,
        key: &[u8],
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
        meta: &[u8],
    ) -> HsmResult<VaultKeyGuard<'_, Self>> {
        let entry = self.active_part_mut(pid)?;
        let session_key_id = session_id
            .map(|sid| entry.session_table.physical_id(sid))
            .transpose()?;
        let key_id = entry.vault.create(key, kind, session_key_id, attrs, meta)?;
        Ok(VaultKeyGuard::new(self, pid, key_id))
    }

    /// Delete a key from the partition's vault.
    fn vault_key_delete(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part_mut(pid)?;
        entry.vault.delete(key_id)
    }

    /// Delete all session-scoped keys for the given logical session.
    ///
    /// Maps the logical session ID to the physical vault key ID, then
    /// removes all vault entries bound to that physical ID.
    fn vault_key_delete_by_session(&self, pid: HsmPartId, session_id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(pid)?;
        let physical_id = entry.session_table.physical_id(session_id)?;
        entry.vault.delete_by_session_key(physical_id)
    }

    /// Clear all keys from the partition's vault.
    fn vault_clear(&self, pid: HsmPartId) -> HsmResult<()> {
        let entry = self.active_part_mut(pid)?;
        entry.vault.clear();
        Ok(())
    }

    /// Retrieve key material by ID.
    fn vault_key(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]> {
        let entry = self.active_part(pid)?;
        entry.vault.key(key_id)
    }

    /// Return the firmware raw key size for a given kind.
    fn vault_key_len(&self, _pid: HsmPartId, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::key_len(kind)
    }

    /// Query key kind.
    fn vault_key_kind(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        let entry = self.active_part(pid)?;
        entry.vault.key_kind(key_id)
    }

    /// Query key attributes.
    fn vault_key_attrs(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        let entry = self.active_part(pid)?;
        entry.vault.key_attrs(key_id)
    }

    /// Query key metadata.
    fn vault_key_meta(&self, pid: HsmPartId, key_id: HsmKeyId) -> HsmResult<&[u8]> {
        let entry = self.active_part(pid)?;
        entry.vault.key_meta(key_id)
    }
}
