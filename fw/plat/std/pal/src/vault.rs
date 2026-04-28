// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stub [`HsmVault`] implementation for the standard PAL.
//!
//! All methods return [`HsmError::InternalError`] — vault key management
//! is not yet wired into the standard PAL.

use super::*;

impl HsmVault for StdHsmPal {
    fn vault_key_create(
        &self,
        _pid: HsmPartId,
        _key: &[u8],
        _kind: HsmVaultKeyKind,
        _session_id: Option<HsmSessId>,
        _attrs: HsmVaultKeyAttrs,
        _meta: &[u8],
    ) -> HsmResult<HsmKeyId> {
        Err(HsmError::InternalError)
    }

    fn vault_key_delete(&self, _pid: HsmPartId, _key_id: HsmKeyId) -> HsmResult<()> {
        Err(HsmError::InternalError)
    }

    fn vault_key_delete_by_session(
        &self,
        _pid: HsmPartId,
        _session_id: HsmSessId,
    ) -> HsmResult<()> {
        Err(HsmError::InternalError)
    }

    fn vault_clear(&self, _pid: HsmPartId) -> HsmResult<()> {
        Err(HsmError::InternalError)
    }

    fn vault_key(&self, _pid: HsmPartId, _key_id: HsmKeyId) -> HsmResult<&[u8]> {
        Err(HsmError::InternalError)
    }

    fn vault_key_len(&self, _pid: HsmPartId, _kind: HsmVaultKeyKind) -> HsmResult<u16> {
        Err(HsmError::InternalError)
    }

    fn vault_key_kind(&self, _pid: HsmPartId, _key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        Err(HsmError::InternalError)
    }

    fn vault_key_attrs(&self, _pid: HsmPartId, _key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        Err(HsmError::InternalError)
    }

    fn vault_key_meta(&self, _pid: HsmPartId, _key_id: HsmKeyId) -> HsmResult<&[u8]> {
        Err(HsmError::InternalError)
    }
}
