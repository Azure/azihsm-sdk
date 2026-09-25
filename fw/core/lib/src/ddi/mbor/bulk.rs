// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helper for committing freshly produced keys to storage.
//!
//! Bulk keys (AES-GCM / XTS) are not stored in the HSM vault as key
//! material: the bulk crypto runs on a dedicated platform backend, so the
//! vault records only a small opaque handle and the host addresses the key
//! by a backend-assigned `bulk_key_id`.  The core stays unaware of that
//! backend — each PAL folds any bulk registration into its
//! [`vault_key_create`](azihsm_fw_hsm_pal_traits::HsmVault::vault_key_create)
//! override and exposes the id through
//! [`bulk_key_id`](azihsm_fw_hsm_pal_traits::HsmVault::bulk_key_id).  Every
//! op that produces a key — generate, HKDF / KBKDF derive, unmask, RSA
//! unwrap — routes through [`commit_key`] so the storage path stays
//! identical.

use super::*;

/// True for the AES-GCM bulk vault kinds whose material lives in the
/// platform bulk-crypto backend rather than the vault.
pub(crate) fn is_gcm_bulk(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256 | HsmVaultKeyKind::AesGcmBulk256Unapproved
    )
}

/// Commit freshly produced key `material` to the vault and return its
/// handle plus, for bulk kinds, the backend-assigned `bulk_key_id`.
///
/// The core treats every key uniformly: it always calls
/// [`vault_key_create`](HsmVault::vault_key_create) and then queries
/// [`bulk_key_id`](HsmVault::bulk_key_id).  For bulk kinds the Uno PAL's
/// `vault_key_create` performs the backend roundtrip and stores only the
/// opaque handle, so `bulk_key_id` returns `Some`; ordinary keys store
/// their material and return `None`.  A bulk kind that produces no id
/// (backend-less platform) rolls back the vault entry and returns
/// `UnsupportedCmd`.
pub(crate) async fn commit_key<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    material: &DmaBuf,
    kind: HsmVaultKeyKind,
    sess_id: HsmSessId,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<(HsmKeyId, Option<u16>)> {
    let handle = pal
        .vault_key_create(
            io,
            material,
            kind,
            attrs.session().then_some(sess_id),
            attrs,
        )
        .await?;
    let bulk_key_id = match pal.bulk_key_id(io, handle) {
        Ok(id) => id,
        // Roll back the just-created key so a lookup failure can't leave the
        // vault entry (and Uno backend key/slot) behind with no handle.
        Err(e) => {
            let _ = pal.vault_key_delete(io, handle).await;
            return Err(e);
        }
    };
    if is_gcm_bulk(kind) && bulk_key_id.is_none() {
        let _ = pal.vault_key_delete(io, handle).await;
        return Err(HsmError::UnsupportedCmd);
    }
    Ok((handle, bulk_key_id))
}
