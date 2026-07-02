// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side mirror of the FW session-establishment crypto.
//!
//! Implements the math needed by the [`init`](super::init) and
//! [`finish`](super::finish) helpers without pulling in any FW
//! handler code:
//!
//! * SEC1 ↔ `EccPublicKey` conversion for the wire `pk_init` /
//!   `pk_resp` / `pk_hsm` fields (97 B `0x04 ‖ X_be ‖ Y_be` per
//!   RFC 9180 §7.1.1).
//! * `pk_hsm` retrieval via the MBOR cert-chain (`GetCertChainInfo`
//!   + `GetCertificate`) — the production attestation path.
//! * HPKE info-block construction matching
//!   `azihsm_ddi_tbor_types::SESSION_HPKE_INFO` ‖ seed ‖ psk_id ‖
//!   session_type.
//! * Phase-1 / Phase-2 confirm MAC computation
//!   (`HMAC-SHA-384(exported, label ‖ id_be ‖ pk_init ‖ pk_hsm ‖ pk_resp)`).
//! * HKDF-Expand-labeled (`HKDF-Expand(exported, label ‖ len_be, len)`)
//!   to derive `param_key`, mirroring [`session_open_finish`].
//!
//! Every helper here is sync — it never touches the device. Device
//! IO lives in [`init`](super::init) and [`finish`](super::finish).

use std::convert::TryFrom;

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::receive_export_vec;
use azihsm_crypto::AesKey;
use azihsm_crypto::DeriveOp;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccKeyOp;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::GenericSecretKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HkdfAlgo;
use azihsm_crypto::HkdfMode;
use azihsm_crypto::HmacAlgo;
use azihsm_crypto::HmacKey;
use azihsm_crypto::HpkeReceiveExportConfig;
use azihsm_crypto::HpkeSuite;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::PskParams;
use azihsm_crypto::Rng;
use azihsm_crypto::SignOp;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info;
use azihsm_ddi_mbor_test_helpers::helper_get_certificate;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::PK_RESP_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::SESSION_HPKE_EXPORTER_CONTEXT;
use azihsm_ddi_tbor_types::SESSION_HPKE_INFO;
use azihsm_ddi_tbor_types::SESSION_PARAM_KEY_LABEL;
use azihsm_ddi_tbor_types::SESSION_PARAM_KEY_LEN;
use azihsm_ddi_tbor_types::SESSION_PHASE1_LABEL;
use azihsm_ddi_tbor_types::SESSION_PHASE2_LABEL;

/// HPKE suite used by the TBOR session protocol — must match
/// `azihsm_fw_core::ddi::tbor::session_open_init::SUITE`.
pub(super) const SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// P-384 coordinate length in bytes.
const P384_COORD_LEN: usize = 48;

/// Per-handshake VM ephemeral keypair, kept together so the caller
/// holds onto `sk_init` from Phase 1 through Phase 2 and the wire
/// `pk_init` slice never falls out of sync with the secret.
pub(super) struct VmEphemeralKey {
    pub sk: EccPrivateKey,
    /// SEC1-uncompressed `0x04 ‖ X_be ‖ Y_be`, ready to ship on the
    /// wire per RFC 9180 §7.1.1.
    pub pk_sec1: [u8; PK_INIT_LEN],
    /// Same point as `pk_sec1`, decoded back into a typed
    /// [`EccPublicKey`] so the HPKE receive-export call doesn't have
    /// to re-import it.
    pub pk: EccPublicKey,
}

/// Generate a fresh per-handshake P-384 ephemeral keypair.
pub(super) fn generate_vm_ephemeral() -> Result<VmEphemeralKey, DdiError> {
    let mut scalar = vec![0u8; P384_COORD_LEN];
    let sk = loop {
        Rng::rand_bytes(&mut scalar).map_err(|_| DdiError::InvalidParameter)?;
        if let Ok(sk) = EccPrivateKey::from_scalar(EccCurve::P384, &scalar) {
            break sk;
        }
    };
    let pk = sk.public_key().map_err(|_| DdiError::InvalidParameter)?;
    let pk_sec1 = ec_pub_to_sec1(&pk)?;
    Ok(VmEphemeralKey { sk, pk_sec1, pk })
}

/// Encode a P-384 public key as SEC1 uncompressed
/// (`0x04 ‖ X_be ‖ Y_be`, 97 B) per RFC 9180 §7.1.1.
fn ec_pub_to_sec1(pk: &EccPublicKey) -> Result<[u8; PK_INIT_LEN], DdiError> {
    let (x_be, y_be) = pk.coord_vec().map_err(|_| DdiError::InvalidParameter)?;
    if x_be.len() != P384_COORD_LEN || y_be.len() != P384_COORD_LEN {
        return Err(DdiError::InvalidParameter);
    }
    let mut out = [0u8; PK_INIT_LEN];
    out[0] = 0x04;
    out[1..1 + P384_COORD_LEN].copy_from_slice(&x_be);
    out[1 + P384_COORD_LEN..].copy_from_slice(&y_be);
    Ok(out)
}

/// Decode a 97-byte SEC1 uncompressed P-384 point
/// (`0x04 ‖ X_be ‖ Y_be`) into a typed [`EccPublicKey`].
pub(super) fn ec_pub_from_sec1(sec1: &[u8]) -> Result<EccPublicKey, DdiError> {
    if sec1.len() != PK_RESP_LEN || sec1[0] != 0x04 {
        return Err(DdiError::InvalidParameter);
    }
    let x_be = &sec1[1..1 + P384_COORD_LEN];
    let y_be = &sec1[1 + P384_COORD_LEN..];
    EccPublicKey::from_coordinates(EccCurve::P384, x_be, y_be)
        .map_err(|_| DdiError::InvalidParameter)
}

/// Look up the partition identity public key (`pk_hsm`) via the MBOR
/// cert-chain — the production attestation path. The leaf cert is the
/// partition-ID cert; its SubjectPublicKeyInfo carries the P-384 key
/// the FW uses as `pk_s` in HPKE `auth_psk`.
pub(super) fn fetch_pk_hsm(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<(EccPublicKey, [u8; PK_RESP_LEN]), DdiError> {
    let info = helper_get_cert_chain_info(dev)?;
    let num_certs = info.data.num_certs;
    if num_certs == 0 {
        return Err(DdiError::InvalidParameter);
    }
    let leaf = helper_get_certificate(dev, num_certs - 1)?;
    let der = leaf.data.certificate.as_slice();
    let pk_der = extract_subject_public_key_der(der)?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| DdiError::InvalidParameter)?;
    let sec1 = ec_pub_to_sec1(&pk)?;
    Ok((pk, sec1))
}

/// Pull the DER-encoded SubjectPublicKeyInfo out of an X.509
/// certificate. Uses [`x509::X509Certificate`] — the same parser the
/// MBOR test harness uses for the same purpose.
fn extract_subject_public_key_der(cert_der: &[u8]) -> Result<Vec<u8>, DdiError> {
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    let cert = X509Certificate::from_der(cert_der).map_err(|_| DdiError::InvalidParameter)?;
    cert.get_public_key_der()
        .map_err(|_| DdiError::InvalidParameter)
}

/// Build the HPKE `info` block:
/// Build the HPKE info string used by `SessionOpenInit`:
/// `SESSION_HPKE_INFO ‖ psk_id ‖ session_type ‖ suite_id`.
///
/// Bytes match `azihsm_fw_core::ddi::tbor::session_open_init::build_hpke_info`.
pub(super) fn build_hpke_info(psk_id: u8, session_type: u8, suite_id: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(SESSION_HPKE_INFO.len() + 3);
    info.extend_from_slice(SESSION_HPKE_INFO);
    info.push(psk_id);
    info.push(session_type);
    info.push(suite_id);
    info
}

/// Look up the canonical default PSK bytes for the given `psk_id`.
///
/// `psk_id = 0` → CO; `psk_id = 1` → CU. Mirrors the FW
/// `HsmPartitionManager::part_psk` for a fresh partition that has
/// not yet been rotated.
pub(super) fn default_psk(psk_id: u8) -> Result<&'static [u8; PSK_LEN], DdiError> {
    match psk_id {
        0 => Ok(&DEFAULT_PSK_CO),
        1 => Ok(&DEFAULT_PSK_CU),
        _ => Err(DdiError::InvalidParameter),
    }
}

/// Run HPKE `auth_psk receive_export` to derive the 48-byte
/// `exported` secret on the host side, mirroring the FW's
/// `send_export`.
///
/// * `sk_init` / `pk_init` — host (recipient) keypair.
/// * `pk_hsm` — FW (sender) identity, retrieved via [`fetch_pk_hsm`].
/// * `pk_resp` — KEM `enc` returned by `SessionOpenInit` (the FW's
///   per-handshake ephemeral encapsulation).
/// * `info` — output of [`build_hpke_info`].
/// * `psk` / `psk_id_byte` — partition PSK and its 1-byte id.
#[allow(clippy::too_many_arguments)]
pub(super) fn receive_exported(
    sk_init: &EccPrivateKey,
    pk_init: &EccPublicKey,
    pk_hsm: &EccPublicKey,
    pk_resp_sec1: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id_byte: &[u8],
) -> Result<Vec<u8>, DdiError> {
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
    receive_export_vec(&cfg, &enc, SUITE.nh()).map_err(|_| DdiError::TborDecodeError)
}

/// Compute one of the session-establishment confirm MACs:
/// `HMAC-SHA-384(exported, label ‖ session_id_be ‖ pk_init ‖ pk_hsm ‖ pk_resp)`.
///
/// Used in two places:
/// * Phase-1 verify on the host (`label = SESSION_PHASE1_LABEL`,
///   compares against `mac_resp` from `SessionOpenInit`).
/// * Phase-2 compute on the host (`label = SESSION_PHASE2_LABEL`,
///   produces `mac_fin` sent to `SessionOpenFinish`).
pub(super) fn confirm_mac(
    exported: &[u8],
    label: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
) -> Result<[u8; 48], DdiError> {
    let mut data =
        Vec::with_capacity(label.len() + 2 + pk_init.len() + pk_hsm.len() + pk_resp.len());
    data.extend_from_slice(label);
    data.extend_from_slice(&session_id.to_be_bytes());
    data.extend_from_slice(pk_init);
    data.extend_from_slice(pk_hsm);
    data.extend_from_slice(pk_resp);

    let key = HmacKey::from_bytes(exported).map_err(|_| DdiError::InvalidParameter)?;
    let mut algo = HmacAlgo::new(HashAlgo::sha384());
    let mut tag = [0u8; 48];
    algo.sign(&key, &data, Some(&mut tag))
        .map_err(|_| DdiError::TborDecodeError)?;
    Ok(tag)
}

/// Compute the Phase-1 confirm MAC and compare it against `expected`.
/// Returns `Ok(())` on match, `Err(...)` on mismatch — the caller maps
/// the error to a test failure. This is host-side test code with no
/// adversary; ordinary `==` is fine.
pub(super) fn verify_phase1_mac(
    exported: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
    expected: &[u8],
) -> Result<(), DdiError> {
    let computed = confirm_mac(
        exported,
        SESSION_PHASE1_LABEL,
        session_id,
        pk_init,
        pk_hsm,
        pk_resp,
    )?;
    if computed.as_slice() != expected {
        return Err(DdiError::TborDecodeError);
    }
    Ok(())
}

/// Compute the Phase-2 confirm MAC the host ships in `mac_fin`.
pub(super) fn build_phase2_mac(
    exported: &[u8],
    session_id: u16,
    pk_init: &[u8],
    pk_hsm: &[u8],
    pk_resp: &[u8],
) -> Result<[u8; 48], DdiError> {
    confirm_mac(
        exported,
        SESSION_PHASE2_LABEL,
        session_id,
        pk_init,
        pk_hsm,
        pk_resp,
    )
}

/// `HKDF-Expand(prk, label ‖ len_be, len)` — mirrors the FW
/// `hkdf_expand_labeled` helper in
/// `azihsm_fw_core::ddi::tbor::session_open_finish`.
pub(super) fn hkdf_expand_labeled(
    prk: &[u8],
    label: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, DdiError> {
    let len_be = u16::try_from(out_len)
        .map_err(|_| DdiError::InvalidParameter)?
        .to_be_bytes();
    let mut info = Vec::with_capacity(label.len() + 2);
    info.extend_from_slice(label);
    info.extend_from_slice(&len_be);

    let hash = HashAlgo::sha384();
    let algo = HkdfAlgo::new(HkdfMode::Expand, &hash, None, Some(&info));
    let prk_key = GenericSecretKey::from_bytes(prk).map_err(|_| DdiError::InvalidParameter)?;
    let derived = algo
        .derive(&prk_key, out_len)
        .map_err(|_| DdiError::TborDecodeError)?;
    derived.to_vec().map_err(|_| DdiError::TborDecodeError)
}

/// Derive the per-session `param_key` (32 B AES-256) from the
/// HPKE exported secret. Returns a typed [`AesKey`] so callers can
/// immediately drive `aead_envelope::seal` / `open`.
pub(super) fn derive_param_key(exported: &[u8]) -> Result<AesKey, DdiError> {
    let bytes = hkdf_expand_labeled(exported, SESSION_PARAM_KEY_LABEL, SESSION_PARAM_KEY_LEN)?;
    AesKey::from_bytes(&bytes).map_err(|_| DdiError::InvalidParameter)
}

/// Seal a 32-byte `seed` under `param_key` as a no-AAD AEAD-GCM
/// envelope. Returns the exact 68-byte wire blob that occupies the
/// `seed_envelope` field of `TborSessionOpenFinishReq`.
pub(super) fn seal_seed_envelope(param_key: &AesKey, seed: &[u8]) -> Result<Vec<u8>, DdiError> {
    let iv = Rng::rand_vec(12).map_err(|_| DdiError::InvalidParameter)?;
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, &[], seed, None)
        .map_err(|_| DdiError::TborDecodeError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        &[],
        seed,
        Some(&mut envelope),
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    envelope.truncate(written);
    Ok(envelope)
}

/// Derive the authenticated-session MAC TX key (host → FW direction
/// from the host's perspective; mirrors FW
/// `SESSION_MAC_TX_LABEL`).  Returns `None` shape is the caller's
/// problem — this helper unconditionally derives the bytes.
pub(super) fn derive_mac_tx_key(exported: &[u8]) -> Result<Vec<u8>, DdiError> {
    hkdf_expand_labeled(
        exported,
        azihsm_ddi_tbor_types::SESSION_MAC_TX_LABEL,
        azihsm_ddi_tbor_types::SESSION_MAC_DIR_KEY_LEN,
    )
}

/// Derive the authenticated-session MAC RX key.
pub(super) fn derive_mac_rx_key(exported: &[u8]) -> Result<Vec<u8>, DdiError> {
    hkdf_expand_labeled(
        exported,
        azihsm_ddi_tbor_types::SESSION_MAC_RX_LABEL,
        azihsm_ddi_tbor_types::SESSION_MAC_DIR_KEY_LEN,
    )
}
