// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetUnwrappingKey command handler.
//!
//! Within an open session, return the partition's RSA-2048 *unwrapping*
//! key — the public key (raw wire `n_le ‖ e_le`) plus its vault key id,
//! used by the host to RSA-AES key-wrap a payload for
//! [`RsaUnwrap`](super::DdiOp::RsaUnwrap).
//!
//! The unwrapping key id lives in the partition's
//! [`RSA_UNWRAPPING_KEY_ID`](crate::part_state::part_unwrapping_key_id)
//! property.  The key is not generated on-device: the HSP publishes it
//! into a per-partition GSRAM slot, and the PAL imports it into the
//! vault (once) behind [`provision_unwrapping_key`] on first use, which
//! this handler calls under the partition lock before reading the id.
//! An absent id means the key is not yet available — the HSP has not
//! published it, or a hardware PAL is still materialising it — which this
//! handler surfaces as `PendingKeyGeneration` so the host retries.  The
//! emulator PAL instead generates the key lazily behind the property
//! read.  No public key is cached: it is derived from the vault private
//! key on demand (matching the reference firmware).
//!
//! [`provision_unwrapping_key`]: azihsm_fw_hsm_pal_traits::HsmPartitionManager::provision_unwrapping_key

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::get_unwrapping_key::DdiGetUnwrappingKeyReq;
use azihsm_fw_ddi_mbor_types::get_unwrapping_key::DdiGetUnwrappingKeyResp;
use azihsm_fw_ddi_mbor_types::DdiPublicKeyFrameParams;

use super::*;

/// Handle `DdiGetUnwrappingKeyCmd`.
pub(crate) async fn get_unwrapping_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetUnwrappingKeyReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Import the unwrapping key on first use.  It is not generated
    // in HSM core: the HSP publishes it into a per-partition GSRAM slot and
    // the PAL imports it (once) into the vault behind this hook, recording
    // its id in the property read below.  Take the partition lock first so
    // the multi-step import is serialised against a concurrent first use;
    // the hook is a no-op where the key is materialised by another route
    // (e.g. the emulator generates it lazily behind the property read).
    let _lock = pal.partition_lock(io).await?;
    pal.provision_unwrapping_key(io).await?;

    // Read the partition's RSA-2048 unwrapping key id from its property.
    // An absent id means the key is not yet available (the HSP has not
    // published it, or a hardware PAL is still generating it) — surface it
    // as such so the host retries.
    let key_id = match crate::part_state::part_unwrapping_key_id(pal, io) {
        Ok(id) => id,
        Err(HsmError::PartPropNotFound) => return Err(HsmError::PendingKeyGeneration),
        Err(e) => return Err(e),
    };

    // Query the wire length of the unwrapping public key derived from
    // the vault-stored private key — no separate public key is cached
    // (matches the reference firmware).  The actual serialization writes
    // straight into the reserved response slot below.
    let priv_key = pal.vault_key(io, key_id)?;
    let pub_len = pal.rsa_priv_pub_key(io, priv_key, None)?;

    // Envelope the unwrapping key for host re-import.  It is a
    // partition-scoped key, so it is masked under the partition masking
    // key (`MK`) and tagged `RsaUnwrap` so the unmask path can refuse
    // to re-import it as a general RSA key.
    let attrs = pal.vault_key_attrs(io, key_id)?;
    let masking_key =
        super::masking::resolve_masking_key(pal, io, HsmSessId::from(sess_id), false)?;
    let metadata = super::masking::masked_metadata(
        pal,
        DdiKeyType::RsaUnwrap,
        attrs,
        &[],
        priv_key.len() as u16,
    )?;
    let masked_len = mask(pal, io, masking_key, priv_key, &metadata, None).await?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::GetUnwrappingKey, sess_id),
            buf,
        )?;
        let layout = DdiGetUnwrappingKeyResp::reserve(
            &mut encoder,
            u16::from(key_id),
            DdiPublicKeyFrameParams {
                raw_len: pub_len,
                key_kind: DdiKeyType::Rsa2kPublic,
            },
            masked_len,
        )?;
        Ok((encoder.position(), layout))
    })?;

    // Serialize the wire-format public key directly into the frame's
    // reserved slot — the PAL converts its vault representation into the
    // wire form (incl. any big-endian↔little-endian flip).
    let frame = DdiGetUnwrappingKeyResp::from_layout(resp, &layout);
    let actual_pub_len = pal.rsa_priv_pub_key(io, priv_key, Some(frame.pub_key.raw))?;
    if actual_pub_len != pub_len {
        return Err(HsmError::InvalidArg);
    }

    // `mask` requires `out[..total_len]` to be zero on entry; zero the
    // reserved slot before filling it with the envelope.
    frame.masked_key.fill(0);
    mask(
        pal,
        io,
        masking_key,
        priv_key,
        &metadata,
        Some(frame.masked_key),
    )
    .await?;

    Ok(resp)
}
