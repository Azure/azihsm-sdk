// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side TBOR session-establishment crypto.
//!
//! Pure helpers implementing the host (recipient) side of the
//! two-phase HPKE session handshake: VM ephemeral generation, HPKE
//! `auth_psk receive_export`, the Phase-1/Phase-2 confirm MACs,
//! `param_key` derivation, and the `seed_envelope` AEAD seal.
//!
//! The handshake conforms to the **wire protocol** (shared constants
//! and labels live in [`azihsm_ddi_tbor_types`]); it does not share
//! code with any particular firmware backend, which may be an
//! emulator or hardware. Conformance is verified by interop against a
//! live backend (see the emu-gated tests in `azihsm_api`) plus the
//! byte-layout/transcript checks below.
//!
//! This crate is the single host-side source of truth, consumed by
//! `azihsm_api`. It is intentionally backend-agnostic: callers map
//! [`SessionExCryptoError`] onto their own error domain at the boundary.

use azihsm_crypto::aead_envelope::*;
use azihsm_crypto::*;
use azihsm_ddi_tbor_types::*;
use zeroize::Zeroizing;

/// Result alias for the session-establishment crypto helpers.
///
/// Distinctly named (not `Result`) so a glob import of this crate
/// cannot shadow the standard `Result` at call sites.
pub type SessionExCryptoResult<T> = core::result::Result<T, SessionExCryptoError>;

/// HPKE suite used by the TBOR session protocol — must match the
/// firmware's `open_session_init` suite.
const SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// P-384 coordinate length in bytes.
const P384_COORD_LEN: usize = 48;

/// HMAC-SHA-384 confirm-MAC tag length in bytes.
const MAC_LEN: usize = 48;

/// Errors returned by the session-establishment crypto helpers.
///
/// Deliberately coarse and backend-agnostic; consumers map these onto
/// their own error domain at the call boundary.
#[derive(Debug, thiserror::Error)]
pub enum SessionExCryptoError {
    /// A cryptographic primitive (key import, HPKE, HMAC, HKDF, AEAD,
    /// RNG, …) failed.
    #[error("session handshake crypto operation failed")]
    Crypto,
    /// Malformed input (e.g. a wrongly sized/encoded public key or an
    /// unknown PSK id).
    #[error("malformed input for session handshake crypto")]
    InvalidInput,
    /// A confirm-MAC comparison did not match the expected tag.
    #[error("confirm MAC verification failed")]
    MacMismatch,
}

/// Decode a 97-byte SEC1 uncompressed P-384 point into a typed
/// [`EccPublicKey`].
pub fn ec_pub_from_sec1(sec1: &[u8]) -> SessionExCryptoResult<EccPublicKey> {
    if sec1.len() != PK_RESP_LEN || sec1[0] != 0x04 {
        return Err(SessionExCryptoError::InvalidInput);
    }
    let x_be = &sec1[1..1 + P384_COORD_LEN];
    let y_be = &sec1[1 + P384_COORD_LEN..];
    EccPublicKey::from_coordinates(EccCurve::P384, x_be, y_be)
        .map_err(|_| SessionExCryptoError::InvalidInput)
}
/// `HMAC-SHA-384(exported, label ‖ session_id_be ‖ pk_init ‖
/// pk_hsm ‖ pk_resp)`.
fn confirm_mac(
    exported: &[u8],
    label: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
) -> SessionExCryptoResult<[u8; MAC_LEN]> {
    let mut data =
        Vec::with_capacity(label.len() + 2 + pk_init.len() + pk_hsm.len() + pk_resp.len());
    data.extend_from_slice(label);
    data.extend_from_slice(&session_id.to_be_bytes());
    data.extend_from_slice(pk_init);
    data.extend_from_slice(pk_hsm);
    data.extend_from_slice(pk_resp);

    let key = HmacKey::from_bytes(exported).map_err(|_| SessionExCryptoError::Crypto)?;
    let mut algo = HmacAlgo::new(HashAlgo::sha384());
    let mut tag = [0u8; MAC_LEN];
    algo.sign(&key, &data, Some(&mut tag))
        .map_err(|_| SessionExCryptoError::Crypto)?;
    Ok(tag)
}

/// Per-handshake VM ephemeral keypair, kept together so `sk` stays
/// in sync with the wire `pk_sec1` and the decoded `pk`.
pub struct VmEphemeralKey {
    /// Ephemeral private key (recipient side of the HPKE handshake).
    pub sk: EccPrivateKey,
    /// Wire SEC1 encoding of `pk` (`0x04 ‖ X ‖ Y`, 97 B).
    pub pk_sec1: [u8; PK_INIT_LEN],
    /// Decoded ephemeral public key.
    pub pk: EccPublicKey,
}

/// Generate a fresh per-handshake P-384 ephemeral keypair.
pub fn generate_vm_ephemeral() -> SessionExCryptoResult<VmEphemeralKey> {
    let mut scalar = Zeroizing::new(vec![0u8; P384_COORD_LEN]);
    let sk = loop {
        Rng::rand_bytes(scalar.as_mut_slice()).map_err(|_| SessionExCryptoError::Crypto)?;
        if let Ok(sk) = EccPrivateKey::from_scalar(EccCurve::P384, scalar.as_slice()) {
            break sk;
        }
    };
    let pk = sk.public_key().map_err(|_| SessionExCryptoError::Crypto)?;
    let pk_sec1 = ec_pub_to_sec1(&pk)?;
    Ok(VmEphemeralKey { sk, pk_sec1, pk })
}

/// Encode a P-384 public key as SEC1 uncompressed
/// (`0x04 ‖ X_be ‖ Y_be`, 97 B) per RFC 9180 §7.1.1.
pub fn ec_pub_to_sec1(pk: &EccPublicKey) -> SessionExCryptoResult<[u8; PK_INIT_LEN]> {
    let (x_be, y_be) = pk.coord_vec().map_err(|_| SessionExCryptoError::Crypto)?;
    if x_be.len() != P384_COORD_LEN || y_be.len() != P384_COORD_LEN {
        return Err(SessionExCryptoError::InvalidInput);
    }
    let mut out = [0u8; PK_INIT_LEN];
    out[0] = 0x04;
    out[1..1 + P384_COORD_LEN].copy_from_slice(&x_be);
    out[1 + P384_COORD_LEN..].copy_from_slice(&y_be);
    Ok(out)
}

/// Build the HPKE info string:
/// `SESSION_HPKE_INFO ‖ psk_id ‖ session_type ‖ suite_id`.
pub fn build_hpke_info(psk_id: u8, session_type: u8, suite_id: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(SESSION_HPKE_INFO.len() + 3);
    info.extend_from_slice(SESSION_HPKE_INFO);
    info.push(psk_id);
    info.push(session_type);
    info.push(suite_id);
    info
}

/// Canonical default PSK for the given `psk_id` (`0` = CO,
/// `1` = CU) on a partition that has not been rotated.
pub fn default_psk(psk_id: u8) -> SessionExCryptoResult<&'static [u8; PSK_LEN]> {
    match psk_id {
        0 => Ok(&DEFAULT_PSK_CO),
        1 => Ok(&DEFAULT_PSK_CU),
        _ => Err(SessionExCryptoError::InvalidInput),
    }
}

/// Run HPKE `auth_psk receive_export` to derive the 48-byte
/// `exported` secret, mirroring the firmware's `send_export`.
#[allow(clippy::too_many_arguments)]
pub fn receive_exported(
    sk_init: &EccPrivateKey,
    pk_init: &EccPublicKey,
    pk_hsm: &EccPublicKey,
    pk_resp_sec1: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id_byte: &[u8],
) -> SessionExCryptoResult<Vec<u8>> {
    let enc = ec_pub_from_sec1(pk_resp_sec1)?;
    let cfg = HpkeReceiveExportConfig::auth_psk(
        SUITE,
        sk_init,
        pk_init,
        info,
        SESSION_HPKE_EXPORTER_CONTEXT,
        pk_hsm,
        PskParams {
            psk,
            psk_id: psk_id_byte,
        },
    );
    receive_export_vec(&cfg, &enc, SUITE.nh()).map_err(|_| SessionExCryptoError::Crypto)
}

/// Compute the Phase-1 confirm MAC and compare it against the
/// backend's `mac_resp`.
pub fn verify_phase1_mac(
    exported: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
    expected: &[u8],
) -> SessionExCryptoResult<()> {
    let computed = confirm_mac(
        exported,
        SESSION_PHASE1_LABEL,
        session_id,
        pk_init,
        pk_hsm,
        pk_resp,
    )?;
    if computed.as_slice() != expected {
        return Err(SessionExCryptoError::MacMismatch);
    }
    Ok(())
}

/// Compute the Phase-2 confirm MAC the host ships in `mac_fin`
/// (`confirm_mac` with `SESSION_PHASE2_LABEL`).
pub fn build_phase2_mac(
    exported: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
) -> SessionExCryptoResult<[u8; MAC_LEN]> {
    confirm_mac(
        exported,
        SESSION_PHASE2_LABEL,
        session_id,
        pk_init,
        pk_hsm,
        pk_resp,
    )
}

/// `HKDF-Expand(prk, label ‖ len_be, len)` — mirrors the firmware's
/// `hkdf_expand_labeled` helper used by `open_session_finish`.
fn hkdf_expand_labeled(prk: &[u8], label: &[u8], out_len: usize) -> SessionExCryptoResult<Vec<u8>> {
    let len_be = u16::try_from(out_len)
        .map_err(|_| SessionExCryptoError::InvalidInput)?
        .to_be_bytes();
    let mut info = Vec::with_capacity(label.len() + 2);
    info.extend_from_slice(label);
    info.extend_from_slice(&len_be);

    let hash = HashAlgo::sha384();
    let algo = HkdfAlgo::new(HkdfMode::Expand, &hash, None, Some(&info));
    let prk_key = GenericSecretKey::from_bytes(prk).map_err(|_| SessionExCryptoError::Crypto)?;
    let derived = algo
        .derive(&prk_key, out_len)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    derived.to_vec().map_err(|_| SessionExCryptoError::Crypto)
}

/// Derive the per-session `param_key` (32 B AES-256) from the HPKE
/// exported secret via [`hkdf_expand_labeled`] with
/// `SESSION_PARAM_KEY_LABEL`. Returns a typed [`AesKey`] ready to drive
/// `aead_envelope::seal`.
pub fn derive_param_key(exported: &[u8]) -> SessionExCryptoResult<AesKey> {
    let bytes = Zeroizing::new(hkdf_expand_labeled(
        exported,
        SESSION_PARAM_KEY_LABEL,
        SESSION_PARAM_KEY_LEN,
    )?);
    AesKey::from_bytes(&bytes).map_err(|_| SessionExCryptoError::Crypto)
}

/// Seal a 32-byte `seed` under `param_key` as a no-AAD AEAD-GCM
/// envelope. Returns the exact `SEED_ENVELOPE_LEN`-byte wire blob that
/// occupies the `seed_envelope` field of `TborSessionOpenFinishReq`.
pub fn seal_seed_envelope(param_key: &AesKey, seed: &[u8]) -> SessionExCryptoResult<Vec<u8>> {
    // Check seed length
    if seed.len() != SESSION_SEED_LEN {
        return Err(SessionExCryptoError::InvalidInput);
    }

    // Generate a random 12-byte IV and seal the seed under param_key with no AAD.
    let iv = Rng::rand_vec(12).map_err(|_| SessionExCryptoError::Crypto)?;
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, &[], seed, None)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    // The framed envelope is a fixed-size wire blob; reject any sizing
    // that does not match the `SEED_ENVELOPE_LEN` contract here rather
    // than letting a mismatch surface as a late `try_into` failure in
    // the caller.
    if total != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    let mut envelope = vec![0u8; SEED_ENVELOPE_LEN];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        &[],
        seed,
        Some(&mut envelope),
    )
    .map_err(|_| SessionExCryptoError::Crypto)?;
    if written != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    Ok(envelope)
}

/// Derive the authenticated-session MAC **TX** key from the HPKE
/// exported secret via [`hkdf_expand_labeled`] with
/// `SESSION_MAC_TX_LABEL`.
pub fn derive_mac_tx_key(exported: &[u8]) -> SessionExCryptoResult<Vec<u8>> {
    hkdf_expand_labeled(exported, SESSION_MAC_TX_LABEL, SESSION_MAC_DIR_KEY_LEN)
}

/// Derive the authenticated-session MAC **RX** key from the HPKE
/// exported secret via [`hkdf_expand_labeled`] with
/// `SESSION_MAC_RX_LABEL`.
pub fn derive_mac_rx_key(exported: &[u8]) -> SessionExCryptoResult<Vec<u8>> {
    hkdf_expand_labeled(exported, SESSION_MAC_RX_LABEL, SESSION_MAC_DIR_KEY_LEN)
}
