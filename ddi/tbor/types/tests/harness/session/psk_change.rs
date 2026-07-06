// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `PskChange` command.
//!
//! Wraps a 32-byte new PSK in an AEAD-GCM envelope keyed by
//! [`SessionHandshake::param_key`] (AAD =
//! [`build_psk_change_aad(session_id)`](build_psk_change_aad)) and
//! ships it via [`TborPskChangeReq`].
//!
//! Target slot is derived FW-side from the session role; the helper
//! has no slot parameter.

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::Rng;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::build_psk_change_aad;
use azihsm_ddi_tbor_types::TborPskChangeReq;
use azihsm_ddi_tbor_types::TborPskChangeResp;
use azihsm_ddi_tbor_types::PSK_LEN;

use super::finish::SessionHandshake;

/// Encrypt `new_psk` under `session.param_key` with the canonical
/// `psk-change-v1 ‖ session_id_le ‖ rsv0` AAD and issue `PskChange`
/// against `dev`.
///
/// `new_psk` must be exactly [`PSK_LEN`] (32) bytes — anything else
/// is an immediate [`DdiError::InvalidParameter`] without touching
/// the device.
pub fn psk_change(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session: &SessionHandshake,
    new_psk: &[u8],
) -> Result<(), DdiError> {
    if new_psk.len() != PSK_LEN {
        return Err(DdiError::InvalidParameter);
    }

    let envelope = encrypt_psk_envelope(session, new_psk)?;
    let req = TborPskChangeReq {
        session_id: session.session_id,
        psk_envelope: envelope,
    };
    let mut cookie = None;
    let _resp: TborPskChangeResp = dev.exec_op_tbor(&req, &mut cookie)?;
    Ok(())
}

/// Build the wire-ready AEAD-GCM envelope for a `PskChange` payload.
///
/// Exposed so negative-path tests can mutate the envelope (e.g.
/// flip a ciphertext byte) before shipping it via a raw
/// [`TborPskChangeReq`].
pub fn encrypt_psk_envelope(
    session: &SessionHandshake,
    new_psk: &[u8],
) -> Result<Vec<u8>, DdiError> {
    let aad = build_psk_change_aad(session.session_id);
    let iv = Rng::rand_vec(12).map_err(|_| DdiError::InvalidParameter)?;
    let total = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &aad,
        new_psk,
        None,
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &aad,
        new_psk,
        Some(&mut envelope),
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    envelope.truncate(written);
    Ok(envelope)
}
