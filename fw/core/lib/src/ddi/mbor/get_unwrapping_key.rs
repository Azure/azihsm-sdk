// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetUnwrappingKey command handler.
//!
//! Within an open session, return the partition's RSA-2048 *unwrapping*
//! key — the public key (raw wire `n_le ‖ e_le`) plus its vault key id,
//! used by the host to RSA-AES key-wrap a payload for
//! [`RsaUnwrap`](super::DdiOp::RsaUnwrap).
//!
//! The unwrapping key is materialised by the PAL and cached for the
//! lifetime of the partition.  RSA key generation is expensive, so it
//! is never done at partition enable: the std (emulator) PAL generates
//! it lazily on the first call, while hardware PALs generate it in the
//! background from partition init and report `PendingKeyGeneration`
//! until it is ready, prompting the host to retry.

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

    // Ensure the partition's RSA-2048 unwrapping key exists (generated
    // lazily by the std PAL, or in the background on hardware) and get
    // its vault key id.  On hardware this may return
    // `PendingKeyGeneration` while generation is in flight, which the
    // host retries.
    let key_id = pal.part_ensure_unwrapping_key(io).await?;

    // Query the wire length of the unwrapping public key derived from
    // the vault-stored private key — no separate public key is cached
    // (matches the reference firmware).  The actual serialization writes
    // straight into the reserved response slot below.
    let priv_key = pal.vault_key(io, key_id)?;
    let pub_len = pal.rsa_priv_pub_key(io, priv_key, None)?;

    // `masked_key` is the host's opaque re-import blob; firmware-side
    // masking is pending the corresponding unmask path — emit an empty
    // placeholder for now so the response is wire-valid.
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
            0, /* masked_key length — empty placeholder */
        )?;
        Ok((encoder.position(), layout))
    })?;

    // Serialize the wire-format public key directly into the frame's
    // reserved slot — the PAL converts its vault representation into the
    // wire form (incl. any big-endian↔little-endian flip).
    let frame = DdiGetUnwrappingKeyResp::from_layout(resp, &layout);
    pal.rsa_priv_pub_key(io, priv_key, Some(frame.pub_key.raw))?;

    Ok(resp)
}
