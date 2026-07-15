// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain sealing-key generation over the TBOR transport at
//! the DDI layer.
//!
//! This module hosts the host-side dispatch for the in-session
//! `SdSealingKeyGen` command, mirroring the firmware handler:
//!
//! * **`SdSealingKeyGen`** (opcode `0x09`) — generate a new
//!   security-domain sealing key and return it as a **masked**
//!   (AEAD-GCM-256) private-key blob plus its public key. The key is
//!   not stored on the device; the masked blob is returned to the host
//!   and unmasked on-use by the security-domain backup commands.
//!
//! It runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the
//! active session id, which the firmware dispatcher cross-checks
//! against the SQE-carried session id. Unlike `PartInit`, no host-side
//! crypto is required — the request only conveys the active session id
//! and the requested key `scope`. The response returns the masked
//! sealing key, which the host retains and unmasks on-use (via
//! `UnmaskKey`) when a security-domain backup command needs it.
//!
//! The wire schema lives in [`azihsm_ddi_tbor_types`]. The `scope`
//! byte is the 1-byte `KeyScope` discriminant (host mirror of the
//! firmware `HsmKeyScope`); this host crate is firewalled from the
//! firmware PAL types, so it is carried as a raw `u8`.

use azihsm_crypto::DerEccPublicKey;
use azihsm_crypto::EccCurve;
use azihsm_crypto::aead_envelope;
use azihsm_ddi_tbor_types::*;

use super::*;

/// Length of the masked sealing-key blob's AAD region: a fixed 96-byte
/// masked-key metadata record.
const SEALING_META_LEN: usize = 96;

/// Length, in bytes, of the P-384 private scalar carried (encrypted) in
/// the masked sealing-key blob.
const SEALING_PRIV_SCALAR_LEN: usize = 48;

/// Length, in bytes, of the AES-256-GCM tag on the masked blob.
const SEALING_GCM_TAG_LEN: usize = 16;

/// Pin `SEALING_META_LEN` to the wire schema so a future
/// `MASKED_SEALING_KEY_LEN` change can't silently desync the validator.
/// The blob is `AEAD header ‖ IV ‖ AAD ‖ P-384 scalar ‖ GCM tag`.
const _: () = assert!(
    MASKED_SEALING_KEY_LEN
        == aead_envelope::HEADER_LEN
            + AES_GCM_IV_SIZE
            + SEALING_META_LEN
            + SEALING_PRIV_SCALAR_LEN
            + SEALING_GCM_TAG_LEN
);

/// Sanity-checks the firmware-returned masked sealing key before it is
/// cached and later handed back for unmask-on-use.
///
/// The host cannot verify the AEAD tag (the masking key is
/// device-internal), but it can confirm the firmware returned a
/// well-formed AES-256-GCM masked-key envelope of the expected shape:
/// valid header/magic, the GCM algorithm, and the 96-byte metadata AAD.
fn validate_masked_sealing_key(masked_key: &[u8; MASKED_SEALING_KEY_LEN]) -> HsmResult<()> {
    let env = aead_envelope::inspect(masked_key).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
    if !matches!(env.alg, aead_envelope::AeadAlg::AesGcm256) || env.aad.len() != SEALING_META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    Ok(())
}

/// Encodes the response's raw P-384 public key as a DER SPKI blob.
///
/// The wire form is `x ‖ y` affine coordinates, little-endian per
/// coordinate; DER SPKI expects big-endian, so each 48-byte half is
/// reversed before encoding.
fn sealing_pub_key_to_der(pub_key: &[u8; SD_SEALING_PUB_KEY_LEN]) -> HsmResult<Vec<u8>> {
    let coord = SD_SEALING_PUB_KEY_LEN / 2;
    let mut x = pub_key[..coord].to_vec();
    let mut y = pub_key[coord..].to_vec();
    x.reverse();
    y.reverse();

    let der = DerEccPublicKey::new(EccCurve::P384, &x, &y).map_err(|_| HsmError::InternalError)?;
    let der_len = der.to_der(None).map_err(|_| HsmError::InternalError)?;
    let mut out = vec![0u8; der_len];
    der.to_der(Some(&mut out))
        .map_err(|_| HsmError::InternalError)?;
    Ok(out)
}

/// Issue `SdSealingKeyGen` (opcode `0x09`) on the active session.
///
/// Ships the active session id and the requested key `scope`. The
/// firmware returns the new sealing key as a masked (AEAD-GCM-256)
/// private-key blob (plus its public key); the key is not stored on the
/// device. Per the firmware contract the blob is returned to the host
/// as-is — it is *not* re-imported into the partition vault here — and
/// is unmasked on-use by the security-domain backup commands.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `scope` - Requested key scope (lifecycle / visibility domain) as
///   the 1-byte `KeyScope` discriminant (mirror of the firmware
///   `HsmKeyScope`).
///
/// # Errors
///
/// Returns [`HsmError::InvalidSession`] on a non-security-domain (V1)
/// session, and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_sealing_key_gen(
    session: &HsmSession,
    scope: u8,
) -> HsmResult<([u8; MASKED_SEALING_KEY_LEN], Vec<u8>)> {
    let req = TborSdSealingKeyGenReq {
        session_id: session.ex_session_id()?,
        scope,
    };

    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    // Return the masked blob and the DER-encoded public key to the host.
    // The masked blob is not stored on the device or in the vault; it is
    // unmasked on-use by the backup commands. The array is returned by
    // value so the caller copies it once into the key's props.
    validate_masked_sealing_key(&resp.masked_key)?;
    let pub_key_der = sealing_pub_key_to_der(&resp.pub_key)?;
    Ok((resp.masked_key, pub_key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a masked-key blob with the given AEAD header fields
    /// (`magic ‖ alg ‖ rsv=0 ‖ aad_len_be`); the remaining envelope
    /// bytes are zeroed.
    fn masked_key_with_header(
        magic: [u8; 4],
        alg: u8,
        aad_len: u16,
    ) -> [u8; MASKED_SEALING_KEY_LEN] {
        let mut blob = [0u8; MASKED_SEALING_KEY_LEN];
        blob[0..4].copy_from_slice(&magic);
        blob[4] = alg;
        blob[5] = 0;
        blob[6..8].copy_from_slice(&aad_len.to_be_bytes());
        blob
    }

    /// AES-256-GCM `AeadAlg` discriminant.
    const ALG_AES_GCM_256: u8 = 0x03;

    #[test]
    fn validate_accepts_gcm256_envelope_with_96b_aad() {
        let blob = masked_key_with_header(*b"AEAD", ALG_AES_GCM_256, SEALING_META_LEN as u16);
        assert!(validate_masked_sealing_key(&blob).is_ok());
    }

    #[test]
    fn validate_rejects_bad_magic() {
        let blob = masked_key_with_header(*b"XXXX", ALG_AES_GCM_256, SEALING_META_LEN as u16);
        assert_eq!(
            validate_masked_sealing_key(&blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    #[test]
    fn validate_rejects_unsupported_alg() {
        let blob = masked_key_with_header(*b"AEAD", 0xFF, SEALING_META_LEN as u16);
        assert_eq!(
            validate_masked_sealing_key(&blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    #[test]
    fn validate_rejects_wrong_aad_len() {
        // 32 is a valid GCM AAD granularity but not the sealing
        // metadata size, so it must be rejected.
        let blob = masked_key_with_header(*b"AEAD", ALG_AES_GCM_256, 32);
        assert_eq!(
            validate_masked_sealing_key(&blob),
            Err(HsmError::MaskedKeyDecodeFailed),
        );
    }

    /// The wire public key is `x ‖ y`, little-endian per coordinate;
    /// the DER SPKI must carry the big-endian (reversed) coordinates.
    #[test]
    fn pub_key_to_der_reverses_coordinates() {
        let coord = SD_SEALING_PUB_KEY_LEN / 2;
        let mut raw = [0u8; SD_SEALING_PUB_KEY_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }

        let der = sealing_pub_key_to_der(&raw).expect("encode der");
        let parsed = DerEccPublicKey::from_der(&der).expect("parse der");

        let mut x_be = raw[..coord].to_vec();
        let mut y_be = raw[coord..].to_vec();
        x_be.reverse();
        y_be.reverse();

        assert_eq!(parsed.curve(), EccCurve::P384);
        assert_eq!(parsed.x(), x_be.as_slice());
        assert_eq!(parsed.y(), y_be.as_slice());
    }
}
