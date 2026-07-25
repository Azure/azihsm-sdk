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
//! The key is materialised on first use through
//! `HsmPartitionManager::provision_unwrapping_key`, called under the partition
//! lock before the id property is read: hardware PALs import the key the HSP
//! staged into GSRAM, while the std (emulator) PAL generates it.  An absent id
//! therefore means materialisation is still pending, surfaced as
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
/// Takes the partition lock only around the first-use key materialisation
/// (provision + resolving the recorded id), then drops it before deriving the
/// public key and building the response so other per-partition commands aren't
/// blocked.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborGetUnwrappingKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    validate_active_session(pal, io, sess_id)?;

    // Scope the partition lock to just provision + id resolution, so the
    // read-modify-read is serialised against a concurrent first use but the
    // public-key derivation and response build below don't block other
    // per-partition commands. Hardware imports the key the HSP staged into
    // GSRAM; the emulator generates one.
    let key_id = {
        let _lock = pal.partition_lock(io).await?;
        pal.provision_unwrapping_key(io).await?;

        // An absent id means materialisation is still pending, surfaced so the
        // host retries.
        match part_state::part_unwrapping_key_id(pal, io) {
            Ok(id) => id,
            Err(HsmError::PartPropNotFound) => return Err(HsmError::PendingKeyGeneration),
            Err(e) => return Err(e),
        }
    };

    // Derive the wire public key from the vault-stored private key.  Its
    // length is a fixed invariant for the RSA-2048 unwrapping key; a
    // mismatch signals an internal sizing bug.
    let priv_key = pal.vault_key(io, key_id)?;
    let pub_len = pal.rsa_priv_pub_key(io, priv_key, None)?;
    if pub_len != UNWRAPPING_PUB_KEY_LEN {
        return Err(HsmError::InternalError);
    }

    // Build the response with the `pub_key` slot reserved (sized but
    // unwritten), then have the PAL derive the wire public key straight
    // into the reserved slot — no scratch buffer and no copy.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborGetUnwrappingKeyResp::encode(buf, 0, false)?
            .pub_key_reserve(UNWRAPPING_PUB_KEY_LEN)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // `decode_mut` hands out a `&mut` view into the reserved slot; the view
    // is scoped so its borrow of `resp` ends before `resp` is returned.
    {
        let out = TborGetUnwrappingKeyResp::decode_mut(resp)?;
        let actual = pal.rsa_priv_pub_key(io, priv_key, Some(out.pub_key))?;
        if actual != pub_len {
            return Err(HsmError::InternalError);
        }
    }

    Ok(resp)
}
