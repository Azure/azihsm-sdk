// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared key-creation and crypto-operation helpers used by resiliency
//! test modules (fault-injection tests, stress tests).

use azihsm_api::*;

// Key-generation helpers

/// Generate an AES-256 session key for encryption/decryption tests.
pub(super) fn generate_aes_key(session: &HsmSession) -> HsmAesKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build AES key props");
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key")
}

/// Generate an ECC P-256 key pair for signing tests.
pub(super) fn generate_ecc_sign_key_pair(
    session: &HsmSession,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}

/// Generate an ECC key pair with derive capability for ECDH.
pub(super) fn generate_ecc_derive_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair for ECDH")
}

/// Perform ECDH key derivation and return the shared secret.
pub(super) fn ecdh_derive(
    session: &HsmSession,
    priv_key: &HsmEccPrivateKey,
    peer_pub_key: &HsmEccPublicKey,
) -> HsmGenericSecretKey {
    let pub_key_der = peer_pub_key
        .pub_key_der_vec()
        .expect("Failed to get peer public key DER");
    let mut algo = EcdhAlgo::new(&pub_key_der);
    let bits = priv_key
        .ecc_curve()
        .expect("ECC curve missing")
        .key_size_bits() as u32;
    let secret_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build secret key props");
    HsmKeyManager::derive_key(session, &mut algo, priv_key, secret_props)
        .expect("Failed to derive ECDH shared secret")
}

// Crypto-operation helpers

/// Hash data with SHA-256.
pub(super) fn hash_data(session: &HsmSession, data: &[u8]) -> Vec<u8> {
    let mut hash_algo = HsmHashAlgo::Sha256;
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

/// AES-CBC encrypt with output buffer (length query + actual encrypt).
pub(super) fn cbc_encrypt(key: &HsmAesKey, iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    let cipher_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}

/// AES-CBC decrypt with output buffer (length query + actual decrypt).
pub(super) fn cbc_decrypt(key: &HsmAesKey, iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    let plain_len = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0u8; plain_len];
    let written = {
        let mut algo =
            HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES-CBC algo");
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);
    Ok(out)
}
