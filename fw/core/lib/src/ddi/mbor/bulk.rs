// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helper for registering AES-GCM *bulk* keys with the fast-path
//! (FP) engine.
//!
//! GCM bulk keys are not stored in the HSM vault as key material: the
//! bulk crypto runs on the FP fast-path engine, so the freshly produced
//! 32-byte key is handed to FP via
//! [`fp_bulk_key_create`](azihsm_fw_hsm_pal_traits::HsmVault::fp_bulk_key_create)
//! and the vault records only the 2-byte `bulk_key_id` handle FP returns.
//! Later fast-path GCM ops carry the session id and resolve the key by
//! this handle.  Every op that produces a bulk key — generate, HKDF /
//! KBKDF derive, and unmask — routes through this helper so the FP
//! registration and vault bookkeeping stay identical.

use super::*;

/// True for the AES-GCM bulk vault kinds whose material lives in the FP
/// engine rather than the vault.
pub(crate) fn is_gcm_bulk(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256 | HsmVaultKeyKind::AesGcmBulk256Unapproved
    )
}

/// Register `material` as a GCM bulk key with the FP engine and record
/// the returned handle in the vault.
///
/// Returns the vault key id (which aliases the 2-byte handle) and the FP
/// `bulk_key_id`.  The FP registration is scoped to `sess_id` when the
/// key is session-scoped (`attrs.session()`), matching the session id
/// later fast-path GCM ops carry.
pub(crate) async fn register_bulk_key<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    material: &DmaBuf,
    kind: HsmVaultKeyKind,
    sess_id: HsmSessId,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<(HsmKeyId, u16)> {
    let bulk_id = pal
        .fp_bulk_key_create(io, material, kind, sess_id, attrs.session())
        .await?;
    let id_bytes = pal.dma_alloc(io, core::mem::size_of::<u16>())?;
    id_bytes.copy_from_slice(&bulk_id.to_le_bytes());
    let session_binding = attrs.session().then_some(sess_id);
    let handle = pal
        .vault_key_create(io, id_bytes, kind, session_binding, attrs)
        .await?;
    Ok((handle, bulk_id))
}
