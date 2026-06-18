// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] stub for the Uno PAL.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::VaultKeyGuard;

use crate::UnoHsmPal;

#[inline]
fn unsupported<T>() -> HsmResult<T> {
    Err(HsmError::UnsupportedCmd)
}

/// Stub vault key guard — never actually constructed (create returns Err).
pub struct UnoKeyGuard;

impl VaultKeyGuard for UnoKeyGuard {
    fn key_id(&self) -> HsmKeyId {
        unreachable!()
    }

    fn dismiss(self) -> HsmKeyId {
        unreachable!()
    }
}

impl HsmVault for UnoHsmPal {
    type KeyGuard<'a> = UnoKeyGuard;

    fn vault_key_create(
        &self,
        _io: &impl HsmIo,
        _key: &[u8],
        _kind: HsmVaultKeyKind,
        _session_id: Option<HsmSessId>,
        _attrs: HsmVaultKeyAttrs,
        _meta: &[u8],
    ) -> HsmResult<Self::KeyGuard<'_>> {
        unsupported()
    }

    fn vault_key_delete(&self, _io: &impl HsmIo, _key_id: HsmKeyId) -> HsmResult<()> {
        unsupported()
    }

    fn vault_key_delete_by_session(
        &self,
        _io: &impl HsmIo,
        _session_id: HsmSessId,
    ) -> HsmResult<()> {
        unsupported()
    }

    fn vault_clear(&self, _io: &impl HsmIo) -> HsmResult<()> {
        unsupported()
    }

    fn vault_key(&self, _io: &impl HsmIo, _key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        unsupported()
    }

    fn vault_key_len(&self, _io: &impl HsmIo, _kind: HsmVaultKeyKind) -> HsmResult<u16> {
        unsupported()
    }

    fn vault_key_kind(&self, _io: &impl HsmIo, _key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        unsupported()
    }

    fn vault_key_attrs(&self, _io: &impl HsmIo, _key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        unsupported()
    }

    fn vault_key_meta(&self, _io: &impl HsmIo, _key_id: HsmKeyId) -> HsmResult<&[u8]> {
        unsupported()
    }
}
