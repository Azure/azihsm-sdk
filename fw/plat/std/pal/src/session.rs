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

/// Legacy `Session`-kind blob size used by [`session_create`] for the
/// MBOR masking-key flow: `[api_rev(8) || masking_key(80)]` = 88 B.
const SESSION_BLOB_SIZE: usize = SESSION_API_REV_SIZE + SESSION_MASKING_KEY_SIZE;

/// `SessionCu`-kind blob size for **PlainText (CU)** sessions:
/// `api_rev(8) || param_key(32) || masking_key(80)` = 120 B.
const SESSION_CU_BLOB_SIZE: usize =
    SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN + SESSION_MASKING_KEY_LEN;

/// `SessionCu`-kind blob size for **Authenticated (CO)** sessions:
/// PlainText blob ‖ `mac_tx(48) ‖ mac_rx(48)` = 216 B.
const SESSION_CU_AUTH_BLOB_SIZE: usize = SESSION_CU_BLOB_SIZE + 2 * SESSION_MAC_DIR_KEY_LEN;

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
            // Pending slots have no vault entry yet; physical_id()
            // returns SessionNotFound and we just drop the slot.
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
    ///
    /// For [`Pending`](HsmSessionState::Pending) slots no vault entry
    /// exists yet, so steps 1–3 are skipped and only step 4 runs.
    fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;

        // Pending slots: no vault state to clean up.
        if matches!(entry.session_table.state(id), HsmSessionState::Pending) {
            entry.session_table.delete(id)?;
            return Ok(());
        }

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

    fn session_create_pending(
        &self,
        io: &impl HsmIo,
        role: SessionRole,
        handshake_state: &[u8],
    ) -> HsmResult<HsmSessId> {
        let entry = self.active_part_mut(io.pid())?;
        entry.session_table.create_pending(role, handshake_state)
    }

    fn session_pending_state(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        let blob = entry.session_table.pending_state(id)?;
        match out {
            None => Ok(blob.len()),
            Some(buf) => {
                if buf.len() < blob.len() {
                    return Err(HsmError::InvalidArg);
                }
                buf[..blob.len()].copy_from_slice(blob);
                Ok(blob.len())
            }
        }
    }

    fn session_promote(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        api_rev: &[u8],
        param_key: &[u8],
        masking_key: &[u8],
        mac_tx_key: Option<&[u8]>,
        mac_rx_key: Option<&[u8]>,
    ) -> HsmResult<()> {
        if api_rev.len() != SESSION_API_REV_SIZE
            || param_key.len() != SESSION_PARAM_KEY_LEN
            || masking_key.len() != SESSION_MASKING_KEY_LEN
        {
            return Err(HsmError::InvalidArg);
        }

        // Both MAC keys must be present together (Authenticated) or both
        // absent (PlainText) — mixed presence is a caller bug.
        let mac_pair = match (mac_tx_key, mac_rx_key) {
            (None, None) => None,
            (Some(tx), Some(rx)) => {
                if tx.len() != SESSION_MAC_DIR_KEY_LEN || rx.len() != SESSION_MAC_DIR_KEY_LEN {
                    return Err(HsmError::InvalidArg);
                }
                Some((tx, rx))
            }
            _ => return Err(HsmError::InvalidArg),
        };

        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;

        // Confirm the slot is Pending before doing any work.
        if !matches!(entry.session_table.state(id), HsmSessionState::Pending) {
            return Err(HsmError::SessionNotPending);
        }

        let attrs = HsmVaultKeyAttrs::new().with_internal(true);

        // Length-discriminated blob:
        // - PlainText:     api_rev(8) + param_key(32) + masking_key(80)         = 120 B
        // - Authenticated: above ‖ mac_tx(48) ‖ mac_rx(48)                       = 216 B
        let mut blob = [0u8; SESSION_CU_AUTH_BLOB_SIZE];
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN]
            .copy_from_slice(param_key);
        blob[SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN..SESSION_CU_BLOB_SIZE]
            .copy_from_slice(masking_key);

        let blob_len = match mac_pair {
            None => SESSION_CU_BLOB_SIZE,
            Some((tx, rx)) => {
                blob[SESSION_CU_BLOB_SIZE..SESSION_CU_BLOB_SIZE + SESSION_MAC_DIR_KEY_LEN]
                    .copy_from_slice(tx);
                blob[SESSION_CU_BLOB_SIZE + SESSION_MAC_DIR_KEY_LEN..SESSION_CU_AUTH_BLOB_SIZE]
                    .copy_from_slice(rx);
                SESSION_CU_AUTH_BLOB_SIZE
            }
        };

        let physical_id = entry.vault.create(
            &blob[..blob_len],
            HsmVaultKeyKind::SessionCu,
            None,
            attrs,
            &[],
        )?;

        // Promote the slot to Active and bind to the new vault entry.
        if let Err(e) = entry.session_table.promote(id, physical_id) {
            let _ = entry.vault.delete(physical_id);
            return Err(e);
        }
        Ok(())
    }

    fn session_param_key(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<&DmaBuf> {
        let entry = self.active_part(io.pid())?;
        let kid = entry.session_table.physical_id(id)?;
        let blob = entry.vault.key(kid)?;
        if blob.len() < SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN {
            return Err(HsmError::InternalError);
        }
        let key_bytes = &blob[SESSION_API_REV_SIZE..SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN];
        // SAFETY: same justification as `vault_key` — on the host,
        // any heap byte is reachable; branding the sub-slice as
        // `DmaBuf` only satisfies the type system.
        Ok(unsafe { DmaBuf::from_raw(key_bytes) })
    }

    fn session_try_consume_psk_change(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.session_table.try_consume_psk_change(id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod session_type_tests {
    use azihsm_fw_hsm_pal_traits::HsmError;
    use azihsm_fw_hsm_pal_traits::SessionRole;
    use azihsm_fw_hsm_pal_traits::SessionType;

    #[test]
    fn to_u8_matches_discriminant() {
        assert_eq!(SessionType::PlainText.to_u8(), 0);
        assert_eq!(SessionType::Authenticated.to_u8(), 1);
    }

    #[test]
    fn from_u8_round_trip() {
        assert_eq!(SessionType::from_u8(0).unwrap(), SessionType::PlainText);
        assert_eq!(SessionType::from_u8(1).unwrap(), SessionType::Authenticated);
    }

    #[test]
    fn from_u8_rejects_unknown_values() {
        for v in [2u8, 3, 0x7f, 0x80, 0xff] {
            assert!(
                matches!(SessionType::from_u8(v), Err(HsmError::InvalidSessionType)),
                "expected InvalidSessionType for v={v}"
            );
        }
    }

    #[test]
    fn validate_for_role_co_requires_authenticated() {
        assert!(SessionType::Authenticated
            .validate_for_role(SessionRole::CryptoOfficer)
            .is_ok());
        assert!(matches!(
            SessionType::PlainText.validate_for_role(SessionRole::CryptoOfficer),
            Err(HsmError::InvalidSessionType)
        ));
    }

    #[test]
    fn validate_for_role_cu_requires_plaintext() {
        assert!(SessionType::PlainText
            .validate_for_role(SessionRole::CryptoUser)
            .is_ok());
        assert!(matches!(
            SessionType::Authenticated.validate_for_role(SessionRole::CryptoUser),
            Err(HsmError::InvalidSessionType)
        ));
    }

    #[test]
    fn is_authenticated_flag() {
        assert!(SessionType::Authenticated.is_authenticated());
        assert!(!SessionType::PlainText.is_authenticated());
    }
}
