// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `PartInit` command.
//!
//! Wraps the 32-byte `mach_seed` plaintext in an AEAD-GCM envelope
//! keyed by [`SessionHandshake::param_key`] (AAD =
//! [`build_part_init_mach_seed_aad(session_id)`](build_part_init_mach_seed_aad))
//! and ships it alongside `part_policy` + `pota_thumbprint` via
//! [`TborPartInitReq`].
//!
//! [`exec_op_tbor`]: azihsm_ddi_interface::DdiDev::exec_op_tbor

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::Rng;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborPartInitReq;
use azihsm_ddi_tbor_types::TborPartInitResp;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LABEL;
use azihsm_ddi_tbor_types::PART_INIT_MACH_SEED_AAD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;

use super::finish::SessionHandshake;

/// Issue `PartInit` on the CO session represented by `session`.
///
/// `mach_seed` is sealed client-side under `session.param_key` using
/// the canonical `part-init-seed-v1 ‖ session_id_le ‖ rsv0` AAD; the
/// device decrypts it inside the handler.  All three byte-bundle
/// inputs must be exactly the size pinned by the wire schema or
/// firmware constants; anything else surfaces
/// [`DdiError::InvalidParameter`] before the request reaches the
/// device.
pub fn part_init(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session: &SessionHandshake,
    mach_seed: &[u8],
    part_policy: &[u8],
    pota_thumbprint: &[u8],
) -> Result<TborPartInitResp, DdiError> {
    if mach_seed.len() != MACH_SEED_LEN
        || part_policy.len() != PART_POLICY_LEN
        || pota_thumbprint.len() != POTA_THUMBPRINT_LEN
    {
        return Err(DdiError::InvalidParameter);
    }

    let envelope = encrypt_mach_seed_envelope(session, mach_seed)?;
    let mut req = TborPartInitReq {
        session_id: session.session_id,
        mach_seed_envelope: envelope,
        ..Default::default()
    };
    req.part_policy.copy_from_slice(part_policy);
    req.pota_thumbprint.copy_from_slice(pota_thumbprint);

    dev.exec_op_tbor(&req, &mut None)
}

/// Build the wire-ready AEAD-GCM envelope for a `PartInit` `mach_seed`
/// payload.
///
/// Exposed so negative-path tests can mutate the envelope (flip a
/// ciphertext byte, swap AAD session id, …) before shipping it via a
/// raw [`TborPartInitReq`].
pub fn encrypt_mach_seed_envelope(
    session: &SessionHandshake,
    mach_seed: &[u8],
) -> Result<Vec<u8>, DdiError> {
    if mach_seed.len() != MACH_SEED_LEN {
        return Err(DdiError::InvalidParameter);
    }
    let aad = build_part_init_mach_seed_aad(session.session_id);
    let iv = Rng::rand_vec(12).map_err(|_| DdiError::InvalidParameter)?;
    let total = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &aad,
        mach_seed,
        None,
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        &aad,
        mach_seed,
        Some(&mut envelope),
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    envelope.truncate(written);
    Ok(envelope)
}

/// Builds the 32-byte AEAD AAD bound into a `PartInit` `mach_seed`
/// envelope.
///
/// Layout: [`PART_INIT_MACH_SEED_AAD_LABEL`] (17 B) `‖ session_id`
/// (2 B LE) `‖ rsv0` (13 B).
///
/// Host-side constructor used by `encrypt_mach_seed_envelope` and by
/// negative-path tests; the FW handler reconstructs the same bytes
/// from the wire-pinned constants and rejects any mismatch.
#[must_use]
pub fn build_part_init_mach_seed_aad(session_id: u16) -> [u8; PART_INIT_MACH_SEED_AAD_LEN] {
    let mut aad = [0u8; PART_INIT_MACH_SEED_AAD_LEN];
    aad[..PART_INIT_MACH_SEED_AAD_LABEL.len()].copy_from_slice(PART_INIT_MACH_SEED_AAD_LABEL);
    aad[PART_INIT_MACH_SEED_AAD_LABEL.len()..PART_INIT_MACH_SEED_AAD_LABEL.len() + 2]
        .copy_from_slice(&session_id.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mach_seed_aad_layout() {
        let aad = build_part_init_mach_seed_aad(0x1234);
        assert_eq!(
            &aad[..PART_INIT_MACH_SEED_AAD_LABEL.len()],
            PART_INIT_MACH_SEED_AAD_LABEL
        );
        assert_eq!(
            &aad[PART_INIT_MACH_SEED_AAD_LABEL.len()..PART_INIT_MACH_SEED_AAD_LABEL.len() + 2],
            &[0x34, 0x12],
        );
        assert_eq!(aad.len(), PART_INIT_MACH_SEED_AAD_LEN);
        assert_eq!(PART_INIT_MACH_SEED_AAD_LEN, 32);
    }
}
