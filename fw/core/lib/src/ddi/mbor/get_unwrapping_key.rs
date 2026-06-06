// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetUnwrappingKey command handler.
//!
//! Returns the partition's RSA-2048 unwrapping key: its vault key ID,
//! the wire-format public key (`n_le || e_le`, 260 bytes), and an
//! opaque masked-key envelope the host may use to re-import the key
//! on a future session.
//!
//! The unwrapping key is **partition-scoped and lazily generated** —
//! the first call on a partition triggers RSA keygen, vaults the
//! private key, and caches `(key_id, pub_key)` in partition state;
//! every subsequent call (from the same or a different session) just
//! returns the cached values.  The partition lock serializes
//! concurrent first-call races so we never generate two competing
//! keys.
//!
//! `masked_key` is currently emitted as an empty placeholder — the
//! masking infrastructure for vault-stored keys is not yet wired up
//! at the firmware level, so we ship an empty envelope and rely on
//! a follow-up PR to populate it.  This means the existing
//! `test_get_unwrapping_key` integration assert
//! (`!masked_key.is_empty()`) will not pass on this handler until
//! masking lands; we add a dedicated smoke test that exercises
//! everything except the masked-key emptiness check.

use azihsm_fw_ddi_mbor_types::get_unwrapping_key::DdiGetUnwrappingKeyReq;
use azihsm_fw_ddi_mbor_types::get_unwrapping_key::DdiGetUnwrappingKeyResp;
use azihsm_fw_ddi_mbor_types::DdiPublicKeyFrameParams;

use super::*;

/// Handle `DdiGetUnwrappingKeyCmd`.
///
/// Takes the partition lock for the duration of the check-or-generate
/// sequence so concurrent callers on the same partition always see a
/// consistent `(key_id, pub_key)` pair and never trigger a duplicate
/// keygen.  Read-only path (key already generated) is short and
/// uncontended in practice.
pub(crate) async fn get_unwrapping_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetUnwrappingKeyReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Lazy generation under the partition lock: ensures concurrent
    // first calls don't race to vault two competing keys.
    let _lock = pal.partition_lock(io).await?;

    let key_id: u16 = match pal.part_unwrapping_key_id(io)? {
        Some(kid) => kid.into(),
        None => generate_and_cache_unwrap_key(pal, io).await?.into(),
    };
    let pub_wire_len = pal.part_unwrapping_pub_key(io, None)?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::GetUnwrappingKey, sess_id),
            buf,
        )?;
        let layout = DdiGetUnwrappingKeyResp::reserve(
            &mut encoder,
            key_id,
            DdiPublicKeyFrameParams {
                raw_len: pub_wire_len,
                key_kind: DdiKeyType::Rsa2kPublic,
            },
            0, /* masked_key length — empty placeholder until masking lands */
        )?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiGetUnwrappingKeyResp::from_layout(resp, &layout);

    // Copy the cached LE n||e wire bytes into the reserved pub-key
    // slot; the PAL already laid them out in the on-wire format.
    pal.part_unwrapping_pub_key(io, Some(frame.pub_key.raw))?;

    Ok(resp)
}

/// First-call helper: generates an RSA-2048 keypair, stores the
/// private key in the vault as a partition-scoped internal key, and
/// caches `key_id + wire-format pub key` on the partition.  Returns
/// the freshly committed vault key id so the caller doesn't have to
/// re-read it from the partition.
///
/// PCT is currently `None` — a follow-up will wire the
/// [`HsmRsaPct::EncryptDecrypt`] round-trip per FIPS 140-3.
async fn generate_and_cache_unwrap_key<P: HsmPal>(pal: &P, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    // Query the required buffer sizes.  Query mode performs no key
    // generation and does not use the scoped allocator, so the
    // scratch scope can close as soon as it returns.
    let (priv_max, pub_max) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            pal.rsa_gen_keypair(io, a, HsmRsaKey::Rsa2048Priv, None, HsmRsaPct::None)
                .await
        })
        .await?;

    // Allocate the output buffers *outside* any scope.  Direct
    // `pal.dma_alloc(io, ...)` calls share the per-IO bump watermark
    // with the scoped allocator, so allocations made inside an
    // `alloc_scoped(_async)` closure would be freed when the scope's
    // watermark is restored on drop (see the std PAL alloc "Lifetime
    // gotcha").  Allocating here keeps these IO-lifetime buffers valid
    // for the vault-create + caching steps below.
    let priv_key = pal.dma_alloc(io, priv_max)?;
    let pub_key = pal.dma_alloc(io, pub_max)?;

    // Generate the keypair into the long-lived buffers.  The scoped
    // allocator only covers the implementation's internal PKA scratch,
    // which is fine to free when this scope closes.
    let (priv_actual, pub_actual) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            pal.rsa_gen_keypair(
                io,
                a,
                HsmRsaKey::Rsa2048Priv,
                Some((&mut *priv_key, &mut *pub_key)),
                HsmRsaPct::None,
            )
            .await
        })
        .await?;

    // Vault-store the private key as a partition-scoped internal key
    // with the `unwrap` usage bit set.  RAII guard rolls the entry
    // back if any subsequent step fails.
    let attrs = HsmVaultKeyAttrs::new()
        .with_internal(true)
        .with_local(true)
        .with_unwrap(true);
    let guard = pal.vault_key_create(
        io,
        &priv_key[..priv_actual],
        HsmVaultKeyKind::Rsa2kPrivate,
        None, /* not session-scoped — partition lifetime */
        attrs,
        &[],
    )?;
    let key_id = guard.key_id();

    // Commit the cached pub key + key id on the partition.  Order:
    // set pub first, then key_id — if either fails, dropping the
    // guard rolls the vault back; `clear_enabled_state` will clear
    // stale pub bytes on the next partition reset.
    pal.part_set_unwrapping_pub_key(io, &pub_key[..pub_actual])?;
    pal.part_set_unwrapping_key_id(io, key_id)?;

    let _ = guard.dismiss();
    Ok(key_id)
}
