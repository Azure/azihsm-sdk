// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] implementation for the standard PAL.
//!
//! Sessions are stored as vault keys.  `session_create` builds an
//! 88-byte blob (`[api_rev(8) || masking_key(80)]`), stores it in the
//! partition's [`KeyVault`] as `HsmVaultKeyKind::Session`, then
//! allocates a logical session slot in the [`SessionTable`] that maps
//! to the vault key's physical [`HsmKeyId`].
//!
//! `session_destroy` cascades cleanup: removes session-scoped vault
//! keys, deletes the session vault key itself, and frees the logical
//! slot.
//!
//! ## RAII guards
//!
//! [`session_create`] returns a [`StdSessionGuard`] in a *provisional*
//! state — on drop the session is torn down (vault key + scoped keys
//! removed, slot freed) unless the caller calls
//! [`StdSessionGuard::dismiss`] to commit.  Each guard captures the
//! partition's incarnation counter (`gen`) at create time; if the
//! partition has since been freed and reallocated, rollback is
//! skipped.
//!
//! [`KeyVault`]: crate::drivers::vault::KeyVault
//! [`SessionTable`]: crate::drivers::session::SessionTable

use super::*;

/// Size of the API revision portion of the session blob (bytes).
const SESSION_API_REV_SIZE: usize = 8;

/// Size of the masking key portion of the session blob (bytes).
/// AES-CBC-256 key (32) + HMAC-SHA-384 key (48) = 80.
const SESSION_MASKING_KEY_SIZE: usize = 80;

/// Total session blob size stored in the vault.
const SESSION_BLOB_SIZE: usize = SESSION_API_REV_SIZE + SESSION_MASKING_KEY_SIZE;

/// RAII guard returned by [`HsmSessionManager::session_create`].
///
/// On drop, tears down the provisional session unless
/// [`dismiss`](Self::dismiss) was called first.  Skips rollback if
/// the partition's incarnation counter has changed since the guard
/// was created.
pub struct StdSessionGuard<'a> {
    pal: &'a StdHsmPal,
    pid: HsmPartId,
    /// Captured partition incarnation counter; rollback is a no-op
    /// if the live counter no longer matches.
    gen: u32,
    sess_id: HsmSessId,
    committed: bool,
}

impl SessionGuard for StdSessionGuard<'_> {
    fn sess_id(&self) -> HsmSessId {
        self.sess_id
    }

    fn dismiss(mut self) -> HsmSessId {
        self.committed = true;
        self.sess_id
    }
}

impl Drop for StdSessionGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.pal.partition_gen(self.pid) != self.gen {
            return;
        }
        if let Ok(entry) = self.pal.active_part_mut(self.pid) {
            if let Ok(physical_id) = entry.session_table.physical_id(self.sess_id) {
                let _ = entry.vault.delete_by_session_key(physical_id);
                let _ = entry.vault.delete(physical_id);
            }
            let _ = entry.session_table.delete(self.sess_id);
        }
    }
}

impl HsmSessionManager for StdHsmPal {
    type Guard<'a> = StdSessionGuard<'a>;

    /// Check whether the partition's session table is full.
    fn session_limit_reached(&self, io: &impl HsmIo) -> bool {
        let Ok(entry) = self.active_part(io.pid()) else {
            return true;
        };
        entry.session_table.limit_reached()
    }

    /// Create (or re-key) a session.
    ///
    /// 1. Builds 88-byte blob: `[api_rev || masking_key]`.
    /// 2. Stores blob in vault as `HsmVaultKeyKind::Session`.
    /// 3. Allocates (or re-maps) a logical session slot.
    fn session_create(
        &self,
        io: &impl HsmIo,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<Self::Guard<'_>> {
        if api_rev.len() != SESSION_API_REV_SIZE || masking_key.len() != SESSION_MASKING_KEY_SIZE {
            return Err(HsmError::InvalidArg);
        }

        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;

        // On re-key: clean up old session-scoped keys and old session key
        // before creating the replacement.
        if let Some(reopen_id) = id {
            let old_phys = entry.session_table.physical_id(reopen_id)?;
            entry.vault.delete_by_session_key(old_phys)?;
            entry.vault.delete(old_phys)?;
        }

        // Build 88-byte session blob: [api_rev(8) || masking_key(80)].
        let mut blob = [0u8; SESSION_BLOB_SIZE];
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..].copy_from_slice(masking_key);

        // Store in vault as internal session key.
        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = entry
            .vault
            .create(&blob, HsmVaultKeyKind::Session, None, attrs, &[])?;

        // Allocate or re-map logical session slot.
        let result = match id {
            None => entry.session_table.create(physical_id),
            Some(reopen_id) => entry.session_table.recreate(reopen_id, physical_id),
        };

        // Rollback: if session table allocation fails, remove the vault key.
        match result {
            Ok(sess_id) => Ok(StdSessionGuard {
                pal: self,
                pid,
                gen: self.partition_gen(pid),
                sess_id,
                committed: false,
            }),
            Err(e) => {
                let _ = entry.vault.delete(physical_id);
                Err(e)
            }
        }
    }

    /// Destroy (close) a session with cascading vault cleanup.
    ///
    /// 1. Looks up physical vault key ID from logical session ID.
    /// 2. Deletes all session-scoped vault keys bound to that physical ID.
    /// 3. Deletes the session vault key itself.
    /// 4. Frees the logical session slot.
    fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;

        // Look up physical session key ID.
        let physical_id = entry.session_table.physical_id(id)?;

        // Delete all session-scoped keys bound to this physical ID.
        entry.vault.delete_by_session_key(physical_id)?;

        // Delete the session key itself.
        entry.vault.delete(physical_id)?;

        // Free the logical session slot.
        entry.session_table.delete(id)?;
        Ok(())
    }

    /// Query the lifecycle state of a session.
    fn session_state(&self, io: &impl HsmIo, id: HsmSessId) -> HsmSessionState {
        let Ok(entry) = self.active_part(io.pid()) else {
            return HsmSessionState::Invalid;
        };
        entry.session_table.state(id)
    }
}
