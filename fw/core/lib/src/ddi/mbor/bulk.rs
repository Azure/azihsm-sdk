// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helper for registering AES *bulk* keys with the platform's
//! bulk-crypto backend.
//!
//! Bulk keys (GCM / XTS) are not stored in the HSM vault as key material:
//! the bulk crypto runs on a dedicated backend, so the freshly produced
//! 32-byte key is handed to it via
//! [`bulk_key_create`](azihsm_fw_hsm_pal_traits::HsmVault::bulk_key_create)
//! and the vault records only the 2-byte `bulk_key_id` handle the backend
//! returns.  Later bulk ops carry the session id and resolve the key by
//! this handle.  Every op that produces a bulk key — generate, HKDF /
//! KBKDF derive, and unmask — routes through this helper so the backend
//! registration and vault bookkeeping stay identical.  The backend is
//! platform-specific and defined by each PAL implementation.

use super::*;

/// True for the AES-GCM bulk vault kinds whose material lives in the
/// bulk-crypto backend rather than the vault.
pub(crate) fn is_gcm_bulk(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256 | HsmVaultKeyKind::AesGcmBulk256Unapproved
    )
}

/// Register `material` as a GCM bulk key with the bulk-crypto backend and
/// record the returned handle in the vault.
///
/// Returns the vault key id (which aliases the 2-byte handle) and the
/// backend-assigned `bulk_key_id`.  The registration is scoped to
/// `sess_id` when the key is session-scoped (`attrs.session()`), matching
/// the session id later bulk ops carry.
///
/// # Concurrency
///
/// This helper contains two awaits — the backend registration and the
/// vault insert — but does not take a partition-lifecycle lock.  DDI
/// commands run on the single-threaded cooperative executor and may
/// interleave at await points, matching the "no partition_lock needed"
/// convention documented on the calling handlers (see
/// `aes_generate_key`).  Interleaving is safe here because:
///
/// * The only cross-await state is the local `bulk_id`, which is not
///   observable from the vault until [`HsmVault::vault_key_create`]
///   commits.
/// * If the vault write fails (`NotEnoughSpace`, torn-down partition,
///   etc.) the compensation branch releases the backend slot best-effort
///   before returning, so the backend cannot outlive a failed vault
///   insert.
/// * The reverse order — vault first, then backend — is not usable: the
///   vault must record the backend-assigned handle, so the backend id
///   has to exist first.
pub(crate) async fn register_bulk_key<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    material: &DmaBuf,
    kind: HsmVaultKeyKind,
    sess_id: HsmSessId,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<(HsmKeyId, u16)> {
    let bulk_id = pal
        .bulk_key_create(io, material, kind, sess_id, attrs.session())
        .await?;

    // The bulk key is now registered with the backend. Any failure while
    // recording its 2-byte handle in the vault must free that bulk key
    // (best-effort), otherwise its slot leaks with no vault entry pointing
    // at it.
    let store = async {
        let id_bytes = pal.dma_alloc(io, core::mem::size_of::<u16>())?;
        id_bytes.copy_from_slice(&bulk_id.to_le_bytes());
        let session_binding = attrs.session().then_some(sess_id);
        pal.vault_key_create(io, id_bytes, kind, session_binding, attrs)
            .await
    };
    match store.await {
        Ok(handle) => Ok((handle, bulk_id)),
        Err(e) => {
            let _ = pal.bulk_key_delete(io, bulk_id).await;
            Err(e)
        }
    }
}
