// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EcdhKeyExchange command handler.
//!
//! Within an open session, look up an ECC private key by id, derive
//! a shared secret against a host-supplied peer public key via ECDH,
//! persist the secret in the partition vault — optionally
//! session-scoped so it is torn down by
//! [`CloseSession`](super::close_session) — and return the assigned
//! `key_id` plus an opaque masked-key envelope the host may re-import
//! on a future session.

use azihsm_fw_ddi_mbor_types::ecdh_key_exchange::DdiEcdhKeyExchangeReq;
use azihsm_fw_ddi_mbor_types::ecdh_key_exchange::DdiEcdhKeyExchangeResp;

use super::*;

/// Handle `DdiEcdhKeyExchangeCmd`.
///
/// No `partition_lock` is needed: this handler does not perform any
/// multi-step read-then-mutate against partition state.  Its single
/// state mutation — `vault_key_create` — is sync and atomic.  A
/// concurrent `CloseSession` racing with our `ecdh_derive` await
/// would just turn the subsequent vault create into a clean
/// `SessionNotFound` error, never a partial commit.
pub(crate) async fn ecdh_key_exchange<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEcdhKeyExchangeReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let priv_key_id = HsmKeyId::from(body.priv_key_id);

    // Resolve the local private key's curve (non-ECC kinds map to
    // `InvalidKeyType` — same precedent as `ecc_sign`) and require
    // the `derive` perm on the vault entry.
    let curve = super::from_pal::ecc_curve(pal.vault_key_kind(io, priv_key_id)?)?;
    if !pal.vault_key_attrs(io, priv_key_id)?.derive() {
        return Err(HsmError::InvalidPermissions);
    }

    // ECDH only produces a same-bit-size secret; reject any
    // curve / target-key-type mismatch — same error as the sim.
    if body.key_type != super::from_pal::ecdh_secret_ddi(curve) {
        return Err(HsmError::InvalidKeyType);
    }

    let target_attrs = super::key_attrs::for_ecdh_secret(&body.key_properties.key_metadata)?;
    super::key_attrs::check_session_key_tag(target_attrs, body.key_tag)?;

    // The on-wire `pub_key_der` field is named "der" for historical
    // reasons but already carries wire-LE `x || y` (P-521 padded to
    // 4-byte words) after the host's `pub_key_der_pre_encode`.
    // The host emits a fixed-length frame for the selected curve,
    // and the PAL trait requires exactly `wire_pub_key_len` bytes
    // — reject any non-exact length so trailing junk isn't silently
    // accepted.
    let wire_pub_key_len = curve.wire_pub_key_len();
    if body.pub_key_der.len() != wire_pub_key_len {
        return Err(HsmError::InvalidArg);
    }

    // Derive into a DMA scratch slot; `vault_key_create` copies it
    // into vault-owned storage so the scratch can drop after.
    let secret = pal.dma_alloc(io, curve.secret_len())?;
    let priv_key = pal.vault_key(io, priv_key_id)?;
    pal.ecdh_derive(
        io,
        curve,
        priv_key,
        &body.pub_key_der[..wire_pub_key_len],
        secret,
    )
    .await?;

    // RAII vault entry — rolls back if response encoding below
    // fails.  `masked_key` is the host's opaque re-import blob;
    // firmware-side masking is pending the `UnmaskKey` handler, so
    // we emit an empty placeholder for wire validity.
    let guard = pal.vault_key_create(
        io,
        secret,
        super::from_pal::ecdh_secret(curve),
        target_attrs.session().then_some(HsmSessId::from(sess_id)),
        target_attrs,
        body.key_properties.key_label,
    )?;
    let key_id: u16 = guard.key_id().into();

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::EcdhKeyExchange, sess_id),
            &DdiEcdhKeyExchangeResp {
                key_id,
                masked_key: &[],
            },
            buf,
        )
    })?;
    let _ = guard.dismiss();
    Ok(resp)
}
