// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] implementation for the Uno PAL.
//!
//! Key material lives in the GSRAM key-vault region. The platform-agnostic
//! allocator and key logic live in the [`KeyVault`] crate; the GSRAM table
//! layout and access live in the
//! [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage) driver. This
//! module just wires the async [`HsmVault`] trait methods to a per-call
//! [`KeyVault`] over that storage, using the PAL's own GDMA controller for
//! large-key copy/zeroize.
//!
//! All state is in GSRAM, so a [`KeyVault`] is constructed per call over a
//! lightweight [`VaultStorage`](azihsm_fw_uno_drivers_vault::VaultStorage)
//! handle that carries only the calling partition's resource mask — there
//! is no PAL-resident vault state.
//!
//! Following the reference firmware, the SDK `meta` (key label) is not
//! stored (see the [`KeyVault`] crate docs).

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_uno_drivers_vault::VaultStorage;
use azihsm_fw_uno_key_vault::KeyVault;

use crate::UnoHsmPal;

#[inline]
pub(crate) fn vault(io: &impl HsmIo) -> KeyVault<VaultStorage> {
    let _ = io;
    // Until partition provisioning lands, every partition owns all vault
    // tables. The per-partition resource mask (from the partition table)
    // is wired in once `PartTable` exists; for now scope to all 65 tables.
    let res_mask = u128::MAX;
    KeyVault::new(VaultStorage::new(res_mask))
}

impl HsmVault for UnoHsmPal {
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        let app_id = u8::from(io.pid());
        let session = session_id.map(u16::from);
        let mut v = vault(io);
        v.create(self, io, app_id, key, kind, session, attrs).await
    }

    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.delete(self, io, key_id).await
    }

    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()> {
        let mut v = vault(io);
        v.delete_by_session(self, io, u16::from(session_id)).await
    }

    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        let mut v = vault(io);
        v.clear(self, io).await
    }

    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let (table, off, len) = vault(io).key_location(key_id)?;
        let addr = VaultStorage::blob_addr(table) + off;
        // SAFETY: `key_location` validated the key is live; `addr..addr+len`
        // lies within that table's 'static GSRAM blob region.
        Ok(unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) })
    }

    fn vault_key_len(&self, _io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::<VaultStorage>::key_len(kind)
    }

    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        vault(io).key_kind(key_id)
    }

    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        vault(io).key_attrs(key_id)
    }
}
