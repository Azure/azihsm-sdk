// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetUnwrappingKey` command handler.
//!
//! Within an open session, return the partition's RSA-2048 **unwrapping**
//! public key (raw wire `n_le ‖ e_le`), which the host uses to RSA-AES
//! key-wrap a payload for `UnwrapKey`.  The unwrapping key is a
//! device-provisioned partition-internal key; only its public half is
//! returned — the private half never leaves the device and `UnwrapKey`
//! resolves it internally by the partition's `RSA_UNWRAPPING_KEY_ID`
//! property.
//!
//! RSA key generation is expensive, so each PAL materialises the key
//! behind the property read: the std (emulator) PAL generates it lazily on
//! first read, while hardware PALs generate it in the background from
//! partition init and leave the property unset until ready.  An absent id
//! therefore means generation is still pending, surfaced as
//! `PendingKeyGeneration` so the host retries.  Available to both
//! Crypto-Officer and Crypto-User sessions.

use azihsm_fw_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_fw_ddi_tbor_types::TborGetUnwrappingKeyResp;
use azihsm_fw_ddi_tbor_types::UNWRAPPING_PUB_KEY_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;
use crate::part_state;

/// Handle a TBOR `GetUnwrappingKey` request.
///
/// No partition lock or undo log is required: the command only reads the
/// unwrapping key property and derives its public key — it makes no
/// observable state change.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborGetUnwrappingKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    validate_active_session(pal, io, sess_id)?;

    // Resolve the partition's RSA-2048 unwrapping key id.  The PAL
    // materialises the key behind this read; an absent id means generation
    // is still pending, surfaced so the host retries.
    let key_id = match part_state::part_unwrapping_key_id(pal, io) {
        Ok(id) => id,
        Err(HsmError::PartPropNotFound) => return Err(HsmError::PendingKeyGeneration),
        Err(e) => return Err(e),
    };

    // Derive the wire public key from the vault-stored private key.  Its
    // length is a fixed invariant for the RSA-2048 unwrapping key; a
    // mismatch signals an internal sizing bug.
    let priv_key = pal.vault_key(io, key_id)?;
    let pub_len = pal.rsa_priv_pub_key(io, priv_key, None)?;
    if pub_len != UNWRAPPING_PUB_KEY_LEN {
        return Err(HsmError::InternalError);
    }
    let pub_buf = pal.dma_alloc(io, pub_len)?;
    let actual = pal.rsa_priv_pub_key(io, priv_key, Some(pub_buf))?;
    if actual != pub_len {
        return Err(HsmError::InternalError);
    }

    encode_response(pal, io, pub_buf)
}

/// Encode the `GetUnwrappingKey` response around the public key.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    pub_key: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborGetUnwrappingKeyResp::encode(buf, 0, false)?
            .pub_key(pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
