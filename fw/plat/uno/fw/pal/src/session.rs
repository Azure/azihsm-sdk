// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] for the Uno PAL.
//!
//! Mirrors the standard PAL's session model: a committed session is
//! stored as a vault key (`Session` for MBOR, `SessionEx` for promoted
//! TBOR sessions); a logical session slot in the partition's persistent
//! [`SessionStore`] maps to that vault key's physical [`HsmKeyId`].
//!
//! In-flight TBOR handshake (Pending) state is **also** held in the key
//! vault — `session_create_pending` stores the opaque handshake blob as
//! a session-scoped [`HsmVaultKeyKind::SessionExPending`] key, and
//! `session_promote` replaces it with the committed
//! [`HsmVaultKeyKind::SessionEx`] key. The session store's `pending_mask`
//! / `psk_change_mask` (the Uno `session_meta` region) track slot state;
//! Pending eviction within a role's slot range is lowest-index-first.
//!
//! The vault-touching methods are `async` (the Uno vault drives GDMA);
//! the read-only probes (`session_pending_state`, `session_param_key`,
//! `session_try_consume_psk_change`) are synchronous.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionManager;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::SESSION_MAC_DIR_KEY_LEN;
use azihsm_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;
use azihsm_fw_hsm_pal_traits::SESSION_PENDING_BLOB_MAX;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_uno_drivers_session_store::SessionStore;

use crate::UnoHsmPal;

/// API-revision portion of the session blob (bytes).
const SESSION_API_REV_SIZE: usize = 8;

/// Masking-key portion of the session blob: AES-CBC-256 (32) + HMAC-SHA-384
/// (48) = 80 bytes.
const SESSION_MASKING_KEY_SIZE: usize = 80;

/// `Session`-kind blob: `[api_rev(8) || masking_key(80)]` = 88 bytes.
const SESSION_BLOB_SIZE: usize = SESSION_API_REV_SIZE + SESSION_MASKING_KEY_SIZE;

/// `SessionEx` plaintext (CU) blob:
/// `[api_rev(8) || param_key(32) || masking_key(80)]` = 120 bytes.
const SESSION_CU_BLOB_SIZE: usize =
    SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN + SESSION_MASKING_KEY_SIZE;

/// `SessionEx` authenticated (CO) blob: the plaintext blob followed by
/// `mac_tx(48) || mac_rx(48)` = 216 bytes.
const SESSION_CU_AUTH_BLOB_SIZE: usize = SESSION_CU_BLOB_SIZE + 2 * SESSION_MAC_DIR_KEY_LEN;

impl HsmSessionManager for UnoHsmPal {
    fn session_limit_reached(&self, io: &impl HsmIo) -> bool {
        let Ok(table) = SessionStore::partition(io.pid()) else {
            return true;
        };
        table.limit_reached()
    }

    async fn session_create(
        &self,
        io: &impl HsmIo,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<HsmSessId> {
        if api_rev.len() != SESSION_API_REV_SIZE || masking_key.len() != SESSION_MASKING_KEY_SIZE {
            return Err(HsmError::InvalidArg);
        }
        let table = SessionStore::partition(io.pid())?;

        // On re-key: tear down the old session-scoped keys and the old
        // session key before creating the replacement.
        if let Some(reopen_id) = id {
            let old_phys = table.physical_id(reopen_id)?;
            let mut v = crate::vault::vault(io);
            v.delete_by_session(self, io, u16::from(reopen_id)).await?;
            v.delete(self, io, old_phys).await?;
        }

        // Build the 88-byte session blob in a DMA buffer:
        // [api_rev(8) || masking_key(80)].
        let blob = self.dma_alloc(io, SESSION_BLOB_SIZE)?;
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..].copy_from_slice(masking_key);

        // Store as an internal session key.
        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = {
            let mut v = crate::vault::vault(io);
            v.create(
                self,
                io,
                u8::from(io.pid()),
                blob,
                HsmVaultKeyKind::Session,
                None,
                attrs,
            )
            .await?
        };

        // Allocate (or re-map, on re-key) the logical session slot.
        let result = {
            let mut store = table;
            match id {
                None => store.create(physical_id),
                Some(reopen_id) => store.recreate(reopen_id, physical_id),
            }
        };

        // If the slot allocation fails, remove the just-stored vault key so
        // it does not leak.
        match result {
            Ok(sess_id) => Ok(sess_id),
            Err(e) => {
                let mut v = crate::vault::vault(io);
                let _ = v.delete(self, io, physical_id).await;
                Err(e)
            }
        }
    }

    async fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let mut table = SessionStore::partition(io.pid())?;

        // Resolve the physical vault key id before any async work (drops the
        // session-store borrow before the awaits).
        let physical_id = table.physical_id(id)?;

        // Delete every session-scoped key bound to this logical session,
        // then the session key itself.
        let mut v = crate::vault::vault(io);
        v.delete_by_session(self, io, u16::from(id)).await?;
        v.delete(self, io, physical_id).await?;

        // Free the logical session slot.
        table.delete(id)?;
        Ok(())
    }

    fn session_state(&self, io: &impl HsmIo, id: HsmSessId) -> HsmSessionState {
        let Ok(table) = SessionStore::partition(io.pid()) else {
            return HsmSessionState::Invalid;
        };
        table.state(id)
    }

    async fn session_create_pending(
        &self,
        io: &impl HsmIo,
        role: SessionRole,
        handshake_state: &DmaBuf,
    ) -> HsmResult<HsmSessId> {
        if handshake_state.is_empty() || handshake_state.len() > SESSION_PENDING_BLOB_MAX {
            return Err(HsmError::InvalidArg);
        }

        // Stash the opaque handshake blob as a session-scoped vault key.
        // The caller already owns it in a DMA buffer, so it is handed to
        // the vault directly — no intermediate copy.
        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = {
            let mut v = crate::vault::vault(io);
            v.create(
                self,
                io,
                u8::from(io.pid()),
                handshake_state,
                HsmVaultKeyKind::SessionExPending,
                None,
                attrs,
            )
            .await?
        };

        // Reserve the logical Pending slot; on eviction, delete the
        // abandoned handshake key. If slot reservation fails, remove the
        // just-stored key so it does not leak.
        let mut store = SessionStore::partition(io.pid())?;
        match store.create_pending(role, physical_id) {
            Ok((sess_id, evicted)) => {
                if let Some(old) = evicted {
                    let mut v = crate::vault::vault(io);
                    let _ = v.delete(self, io, old).await;
                }
                Ok(sess_id)
            }
            Err(e) => {
                let mut v = crate::vault::vault(io);
                let _ = v.delete(self, io, physical_id).await;
                Err(e)
            }
        }
    }

    fn session_pending_state(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        let table = SessionStore::partition(io.pid())?;
        let physical_id = table.pending_phys(id)?;
        let blob = self.vault_key(io, physical_id)?;
        let len = blob.len();
        match out {
            None => Ok(len),
            Some(buf) => {
                if buf.len() < len {
                    return Err(HsmError::InvalidArg);
                }
                buf[..len].copy_from_slice(blob);
                Ok(len)
            }
        }
    }

    async fn session_promote(
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
            || masking_key.len() != SESSION_MASKING_KEY_SIZE
        {
            return Err(HsmError::InvalidArg);
        }
        // CO (authenticated) supplies both MAC keys; CU (plaintext)
        // supplies neither — anything else is malformed.
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

        // Confirm the slot is Pending before doing any work.
        let mut store = SessionStore::partition(io.pid())?;
        if !matches!(store.state(id), HsmSessionState::Pending) {
            return Err(HsmError::SessionNotPending);
        }

        // Build the length-discriminated SessionEx blob:
        //   PlainText:     api_rev(8) ‖ param_key(32) ‖ masking_key(80)        = 120 B
        //   Authenticated: above ‖ mac_tx(48) ‖ mac_rx(48)                     = 216 B
        let blob_len = match mac_pair {
            None => SESSION_CU_BLOB_SIZE,
            Some(_) => SESSION_CU_AUTH_BLOB_SIZE,
        };
        let blob = self.dma_alloc(io, blob_len)?;
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN]
            .copy_from_slice(param_key);
        blob[SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN..SESSION_CU_BLOB_SIZE]
            .copy_from_slice(masking_key);
        if let Some((tx, rx)) = mac_pair {
            blob[SESSION_CU_BLOB_SIZE..SESSION_CU_BLOB_SIZE + SESSION_MAC_DIR_KEY_LEN]
                .copy_from_slice(tx);
            blob[SESSION_CU_BLOB_SIZE + SESSION_MAC_DIR_KEY_LEN..SESSION_CU_AUTH_BLOB_SIZE]
                .copy_from_slice(rx);
        }

        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = {
            let mut v = crate::vault::vault(io);
            v.create(
                self,
                io,
                u8::from(io.pid()),
                blob,
                HsmVaultKeyKind::SessionEx,
                None,
                attrs,
            )
            .await?
        };

        // Bind the slot to the committed SessionEx key. `promote` returns
        // the now-obsolete SessionExPending handshake key, which must be
        // deleted once SessionEx is established. Rollback of a
        // partially-applied promote is deferred to a future undo-log
        // framework.
        let old_pending = store.promote(id, physical_id)?;
        crate::vault::vault(io)
            .delete(self, io, old_pending)
            .await?;
        Ok(())
    }

    fn session_param_key(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<&DmaBuf> {
        let table = SessionStore::partition(io.pid())?;
        let physical_id = table.physical_id(id)?;
        // The param_key is the 32-byte field following the 8-byte api_rev
        // in the committed SessionEx blob.
        let blob = self.vault_key(io, physical_id)?;
        // A committed SessionEx blob is always long enough to carry the
        // param_key; a short blob indicates vault corruption, not a caller
        // error — surface it as `InternalError` (matches the trait contract
        // and the std PAL).
        if blob.len() < SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN {
            return Err(HsmError::InternalError);
        }
        Ok(blob
            .split_at(SESSION_API_REV_SIZE)
            .1
            .split_at(SESSION_PARAM_KEY_LEN)
            .0)
    }

    fn session_try_consume_psk_change(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let mut table = SessionStore::partition(io.pid())?;
        table.try_consume_psk_change(id)
    }
}
