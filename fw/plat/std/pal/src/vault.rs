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
//! `vault_key_create` commits the key immediately and returns its
//! [`HsmKeyId`]; rollback of a half-completed operation is left to a
//! future undo log.
//!
//! [`KeyVault`]: crate::drivers::vault::KeyVault
//! [`PartitionEntry`]: crate::part::PartitionEntry

use azihsm_fw_hsm_io::Sqe;

use super::*;
use crate::drivers::vault::KeyVault;

impl StdHsmPal {
    /// Enforce session-scoped key isolation.
    ///
    /// A key bound to a session (created with `Session` availability) may
    /// only be accessed from that same session; from any other session it
    /// is reported as [`HsmError::KeyNotFound`], mirroring the reference
    /// behaviour. Partition-scoped (`App`/persistent) keys carry no
    /// binding and stay accessible from any context, including internal
    /// firmware IOs whose SQE has no session.
    fn assert_key_session_access(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part(io.pid())?;
        let Some(bound) = entry.vault.key_session_binding(key_id)? else {
            return Ok(());
        };
        // Session-bound key: the current session (from the SQE) must map to
        // the same physical vault key id (the session key id) that the key
        // is bound to, else the key is not visible here.
        let sqe = Sqe::from(io.sqe());
        let current = if sqe.session_flags().id_valid() {
            entry
                .session_table
                .physical_id(HsmSessId::from(sqe.session_id()))
                .ok()
        } else {
            None
        };
        if current == Some(bound) {
            Ok(())
        } else {
            Err(HsmError::KeyNotFound)
        }
    }
}

impl HsmVault for StdHsmPal {
    /// Store a new key in the partition's vault.
    ///
    /// If `session_id` is `Some`, maps the logical session ID to the
    /// physical vault key ID via the session table before storing.
    /// The key is committed immediately.
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;
        let session_key_id = session_id
            .map(|sid| entry.session_table.physical_id(sid))
            .transpose()?;
        entry.vault.create(key, kind, session_key_id, attrs)
    }

    /// Delete a key from the partition's vault.
    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.delete(key_id)
    }

    /// Disable (soft-delete) a key — the undo log's reversible-delete
    /// staging step.  Hidden from lookups; `enable` rolls back, `delete`
    /// commits.
    fn vault_key_disable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.disable(key_id)
    }

    /// Re-enable a disabled key — the undo side of a reversible delete.
    fn vault_key_enable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.enable(key_id)
    }

    /// Delete all session-scoped keys for the given logical session.
    ///
    /// Maps the logical session ID to the physical vault key ID, then
    /// removes all vault entries bound to that physical ID.
    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        let physical_id = entry.session_table.physical_id(session_id)?;
        entry.vault.delete_by_session_key(physical_id)
    }

    /// Clear all keys from the partition's vault.
    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.vault.clear();
        Ok(())
    }

    /// Retrieve key material by ID.
    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        self.assert_key_session_access(io, key_id)?;
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
        self.assert_key_session_access(io, key_id)?;
        let entry = self.active_part(io.pid())?;
        entry.vault.key_kind(key_id)
    }

    /// Query key attributes.
    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        self.assert_key_session_access(io, key_id)?;
        let entry = self.active_part(io.pid())?;
        entry.vault.key_attrs(key_id)
    }
}
