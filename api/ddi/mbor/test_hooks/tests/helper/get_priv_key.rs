// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Suite-private helpers for the `GetPrivKey` integration tests.

use azihsm_crypto::*;
use azihsm_ddi::Ddi;
use azihsm_ddi::DdiError;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_test_hooks::helper_get_priv_key;
use azihsm_ddi_mbor_types::*;

use crate::common::*;

pub(super) const DIGEST: [u8; 32] = [100; 32];

fn ecc_gen_key_mcr(
    dev: &mut <DdiTest as Ddi>::Dev,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    session_id: Option<u16>,
    key_usage: DdiKeyUsage,
) -> (u16, DdiDerPublicKey, MborByteArray<3072>) {
    let key_props = helper_key_properties(key_usage, DdiKeyAvailability::App);
    let resp = helper_ecc_generate_key_pair(
        dev,
        session_id,
        Some(DdiApiRev { major: 1, minor: 0 }),
        curve,
        key_tag,
        key_props,
    )
    .unwrap();

    (
        resp.data.private_key_id,
        resp.data.pub_key,
        resp.data.masked_key,
    )
}

pub(super) fn generate_ecc_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
) -> (u16, DdiDerPublicKey) {
    let (private_key_id, public_key, _) = ecc_gen_key_mcr(
        dev,
        DdiEccCurve::P256,
        None,
        Some(session_id),
        DdiKeyUsage::SignVerify,
    );
    (private_key_id, public_key)
}

pub(super) fn create_aes_key(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> u16 {
    let key_properties =
        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
    helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes128,
        None,
        key_properties,
    )
    .unwrap()
    .data
    .key_id
}

pub(super) fn aes_encrypt_hardware(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    key_id: u16,
    plaintext: &[u8],
) -> Vec<u8> {
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(plaintext).unwrap(),
        MborByteArray::from_slice(&[0; 16]).unwrap(),
    )
    .unwrap();

    resp.data.msg.data()[..resp.data.msg.len()].to_vec()
}

pub(super) fn aes_decrypt_local(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let key = AesKey::from_bytes(key).unwrap();
    Decrypter::decrypt_vec(&mut AesCbcAlgo::with_no_padding(&[0; 16]), &key, ciphertext).unwrap()
}

pub(super) fn retrieve_private_key(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    key_id: u16,
) -> Option<(DdiKeyType, Vec<u8>)> {
    let resp = helper_get_priv_key(dev, Some(session_id), key_id);
    if let Err(err) = &resp {
        if is_unsupported_cmd(err) {
            return None;
        }
    }
    let resp = resp.unwrap();
    Some((
        resp.data.key_kind,
        resp.data.key_data.data()[..resp.data.key_data.len()].to_vec(),
    ))
}

pub(super) fn ecc_sign_local(private_key: Vec<u8>, curve: EccCurve, digest: &[u8]) -> Vec<u8> {
    let der = DerEccPrivateKey::new(curve, &private_key);
    let private_key = EccPrivateKey::from_bytes(&der.to_der_vec().unwrap()).unwrap();
    Signer::sign_vec(&mut EccAlgo::default(), &private_key, digest).unwrap()
}

pub(super) fn ecc_verify_local(
    signature: &[u8],
    public_key: &DdiDerPublicKey,
    digest: &[u8],
) -> bool {
    let public_key =
        EccPublicKey::from_bytes(&public_key.der.data()[..public_key.der.len()]).unwrap();
    Verifier::verify(&mut EccAlgo::default(), &public_key, digest, signature).unwrap()
}

pub(super) fn create_ecdh_secrets(
    session_id: u16,
    dev: &mut <DdiTest as Ddi>::Dev,
    secret_key_type: DdiKeyType,
) -> (u16, u16) {
    let (secret_key_type, curve) = match secret_key_type {
        DdiKeyType::Secret256 => (DdiKeyType::Secret256, DdiEccCurve::P256),
        DdiKeyType::Secret384 => (DdiKeyType::Secret384, DdiEccCurve::P384),
        DdiKeyType::Secret521 => (DdiKeyType::Secret521, DdiEccCurve::P521),
        _ => (DdiKeyType::Secret256, DdiEccCurve::P256),
    };

    let (private_key_id1, public_key1, _) =
        ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::Derive);
    let (private_key_id2, public_key2, _) =
        ecc_gen_key_mcr(dev, curve, None, Some(session_id), DdiKeyUsage::Derive);

    let key_properties = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
    let secret_key_id1 = helper_ecdh_key_exchange(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        private_key_id1,
        MborByteArray::from_slice(&public_key2.der.data()[..public_key2.der.len()]).unwrap(),
        None,
        secret_key_type,
        key_properties,
    )
    .unwrap()
    .data
    .key_id;

    let key_properties = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
    let secret_key_id2 = helper_ecdh_key_exchange(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        private_key_id2,
        MborByteArray::from_slice(&public_key1.der.data()[..public_key1.der.len()]).unwrap(),
        None,
        secret_key_type,
        key_properties,
    )
    .unwrap()
    .data
    .key_id;

    (secret_key_id1, secret_key_id2)
}

pub(super) fn create_hmac_key(
    session_id: u16,
    key_type: DdiKeyType,
    dev: &mut <DdiTest as Ddi>::Dev,
    key_len: Option<u8>,
) -> u16 {
    let (secret_key_id, _) = create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);
    let key_properties =
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

    helper_hkdf_derive(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        secret_key_id,
        DdiHashAlgorithm::Sha256,
        None,
        None,
        key_type,
        None,
        key_properties,
        key_len,
    )
    .unwrap()
    .data
    .key_id
}

pub(super) fn validate_variable_hmac_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_type: DdiKeyType,
    min_len: u8,
    len_count: u8,
    hash: HashAlgo,
) {
    let mut random = [0];
    Rng::rand_bytes(&mut random).unwrap();
    let key_len = random[0] % len_count + min_len;
    let key_id = create_hmac_key(session_id, key_type, dev, Some(key_len));

    let Some((returned_type, raw_key)) = retrieve_private_key(dev, session_id, key_id) else {
        return;
    };
    assert_eq!(returned_type, key_type);
    assert_eq!(raw_key.len(), usize::from(key_len));

    let message = [0; 64];
    let resp = helper_hmac(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        MborByteArray::from_slice(&message).unwrap(),
    )
    .unwrap();

    let key = HmacKey::from_bytes(&raw_key).unwrap();
    let local_tag = Signer::sign_vec(&mut HmacAlgo::new(hash), &key, &message).unwrap();
    assert_eq!(
        &resp.data.tag.data()[..resp.data.tag.len()],
        local_tag.as_slice()
    );
}

pub(super) fn generate_aes_bulk_256_key(
    dev: &<DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: DdiAesKeySize,
) -> Result<DdiAesGenerateKeyCmdResp, DdiError> {
    assert!(key_size.is_bulk_key(), "key size must describe a bulk key");
    let key_properties =
        helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_size,
        None,
        key_properties,
    )
}

pub(super) fn close_app_session(dev: &<DdiTest as Ddi>::Dev, session_id: u16) {
    let resp = helper_close_session(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    );
    assert!(
        resp.is_ok(),
        "Failed to close session {session_id}: {resp:?}"
    );
}
