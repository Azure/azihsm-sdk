// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] implementation for the Uno PAL.

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionManager;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::SessionRole;
use azihsm_fw_hsm_pal_traits::SESSION_MAC_DIR_KEY_LEN;
use azihsm_fw_hsm_pal_traits::SESSION_MASKING_KEY_LEN;
use azihsm_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;
use azihsm_fw_uno_drivers_vault::VaultStorage;

use crate::UnoHsmPal;

/// Size of the API revision portion of the session blob (bytes).
const SESSION_API_REV_SIZE: usize = 8;

/// Legacy `Session`-kind blob size: `[api_rev(8) || masking_key(80)]`.
const SESSION_BLOB_SIZE: usize = SESSION_API_REV_SIZE + SESSION_MASKING_KEY_LEN;

/// `SessionCu` PlainText blob: `api_rev(8) || param_key(32) || masking_key(80)`.
const SESSION_CU_BLOB_SIZE: usize =
    SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN + SESSION_MASKING_KEY_LEN;

/// `SessionCu` Authenticated blob: PlainText blob || `mac_tx(48) || mac_rx(48)`.
const SESSION_CU_AUTH_BLOB_SIZE: usize = SESSION_CU_BLOB_SIZE + 2 * SESSION_MAC_DIR_KEY_LEN;

impl HsmSessionManager for UnoHsmPal {
    fn session_limit_reached(&self, io: &impl HsmIo) -> bool {
        let Ok(entry) = self.active_part(io.pid()) else {
            return true;
        };
        entry.session_table().limit_reached()
    }

    async fn session_create(
        &self,
        io: &impl HsmIo,
        api_rev: &[u8],
        masking_key: &[u8],
        id: Option<HsmSessId>,
    ) -> HsmResult<HsmSessId> {
        if api_rev.len() != SESSION_API_REV_SIZE || masking_key.len() != SESSION_MASKING_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }

        let pid = io.pid();

        if let Some(reopen_id) = id {
            let old_phys = self.active_part(pid)?.session_table().physical_id(reopen_id)?;
            crate::vault::vault(io)
                .delete_by_session(self, io, u16::from(reopen_id))
                .await?;
            crate::vault::vault(io).delete(self, io, old_phys).await?;
        }

        let blob = self.dma_alloc(io, SESSION_BLOB_SIZE)?;
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..].copy_from_slice(masking_key);

        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = crate::vault::vault(io)
            .create(
                self,
                io,
                u8::from(pid),
                blob,
                HsmVaultKeyKind::Session,
                None,
                attrs,
            )
            .await?;

        let result = {
            let table = self.active_part(pid)?.session_table();
            match id {
                None => table.create(physical_id),
                Some(reopen_id) => table.recreate(reopen_id, physical_id),
            }
        };

        match result {
            Ok(sess_id) => Ok(sess_id),
            Err(e) => {
                let _ = crate::vault::vault(io).delete(self, io, physical_id).await;
                Err(e)
            }
        }
    }

    async fn session_destroy(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        let pid = io.pid();

        if matches!(
            self.active_part(pid)?.session_table().state(id),
            HsmSessionState::Pending
        ) {
            self.active_part(pid)?.session_table().delete(id)?;
            return Ok(());
        }

        let physical_id = self.active_part(pid)?.session_table().physical_id(id)?;

        crate::vault::vault(io)
            .delete_by_session(self, io, u16::from(id))
            .await?;
        crate::vault::vault(io).delete(self, io, physical_id).await?;

        self.active_part(pid)?.session_table().delete(id)?;
        Ok(())
    }

    fn session_state(&self, io: &impl HsmIo, id: HsmSessId) -> HsmSessionState {
        let Ok(entry) = self.active_part(io.pid()) else {
            return HsmSessionState::Invalid;
        };
        entry.session_table().state(id)
    }

    fn session_create_pending(
        &self,
        io: &impl HsmIo,
        role: SessionRole,
        handshake_state: &[u8],
    ) -> HsmResult<HsmSessId> {
        self.active_part(io.pid())?
            .session_table()
            .create_pending(role, handshake_state)
    }

    fn session_pending_state(
        &self,
        io: &impl HsmIo,
        id: HsmSessId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        let blob = entry.session_table().pending_state(id)?;
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
            || masking_key.len() != SESSION_MASKING_KEY_LEN
        {
            return Err(HsmError::InvalidArg);
        }

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
        if !matches!(
            self.active_part(pid)?.session_table().state(id),
            HsmSessionState::Pending
        ) {
            return Err(HsmError::SessionNotPending);
        }

        let blob_len = if mac_pair.is_some() {
            SESSION_CU_AUTH_BLOB_SIZE
        } else {
            SESSION_CU_BLOB_SIZE
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
        let physical_id = crate::vault::vault(io)
            .create(
                self,
                io,
                u8::from(pid),
                blob,
                HsmVaultKeyKind::SessionCu,
                None,
                attrs,
            )
            .await?;

        if let Err(e) = self
            .active_part(pid)?
            .session_table()
            .promote(id, physical_id)
        {
            let _ = crate::vault::vault(io).delete(self, io, physical_id).await;
            return Err(e);
        }
        Ok(())
    }

    fn session_param_key(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<&DmaBuf> {
        let kid = self.active_part(io.pid())?.session_table().physical_id(id)?;
        let (table, off, len) = crate::vault::vault(io).key_location(kid)?;
        if len < SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN {
            return Err(HsmError::InternalError);
        }
        let addr = VaultStorage::blob_addr(table) + off + SESSION_API_REV_SIZE;
        Ok(unsafe {
            DmaBuf::from_raw(core::slice::from_raw_parts(
                addr as *const u8,
                SESSION_PARAM_KEY_LEN,
            ))
        })
    }

    fn session_try_consume_psk_change(&self, io: &impl HsmIo, id: HsmSessId) -> HsmResult<()> {
        self.active_part(io.pid())?
            .session_table()
            .try_consume_psk_change(id)
    }
}
