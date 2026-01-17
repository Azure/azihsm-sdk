// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

use crate::algo::ecc::*;

fn supported_hkdf_hash_algos() -> &'static [HsmHashAlgo] {
    &[
        HsmHashAlgo::Sha1,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    ]
}

fn derive_ecdh_shared_secrets(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmGenericSecretKey, HsmGenericSecretKey) {
    let (priv_key_a, pub_key_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party A");

    let (priv_key_b, pub_key_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party B");

    let shared_secret_a = ecdh_derive_shared_secret(session, &priv_key_a, &pub_key_b)
        .expect("Failed to derive shared secret for party A");
    let shared_secret_b = ecdh_derive_shared_secret(session, &priv_key_b, &pub_key_a)
        .expect("Failed to derive shared secret for party B");

    (shared_secret_a, shared_secret_b)
}

fn derive_aes_key_from_shared_secret(
    session: &HsmSession,
    hkdf_algo: &mut HsmHkdfAlgo,
    shared_secret: &HsmGenericSecretKey,
    bits: u32,
) -> HsmAesKey {
    let aes_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES key props");

    let derived_key = HsmKeyManager::derive_key(session, hkdf_algo, shared_secret, aes_key_props)
        .expect("Failed to derive AES key");

    assert_eq!(derived_key.kind(), HsmKeyKind::Aes);
    assert_eq!(derived_key.bits(), bits);
    derived_key
        .try_into()
        .expect("Derived key was not an AES key")
}

fn assert_aes_cbc_roundtrip(enc_key: &HsmAesKey, dec_key: &HsmAesKey, plaintext: &[u8]) {
    let iv = [0u8; 16];
    let mut aes_algo_enc =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    let ciphertext = HsmEncrypter::encrypt_vec(&mut aes_algo_enc, enc_key, plaintext)
        .expect("Encryption failed");

    let mut aes_algo_dec =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    let decrypted = HsmDecrypter::decrypt_vec(&mut aes_algo_dec, dec_key, &ciphertext)
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

fn run_hkdf_matrix_for_curve(session: &HsmSession, curve: HsmEccCurve) {
    let (shared_secret_a, shared_secret_b) = derive_ecdh_shared_secrets(session, curve);

    for &hash_algo in supported_hkdf_hash_algos() {
        for &bits in &[128u32, 192u32, 256u32] {
            let mut hkdf_algo =
                HsmHkdfAlgo::new(hash_algo, None, None).expect("Failed HKDF algo creation");

            let derived_aes_key_a =
                derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_a, bits);
            let derived_aes_key_b =
                derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_b, bits);

            let plaintext =
                format!("HKDF curve={curve:?} hash={hash_algo:?} aes_bits={bits}").into_bytes();
            assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
        }
    }

    // Salt + info should also work.
    let salt = b"hkdf-salt";
    let info = b"hkdf-info";
    let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info))
        .expect("Failed HKDF algo creation");

    let derived_aes_key_a =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_a, 256);
    let derived_aes_key_b =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_b, 256);
    assert_aes_cbc_roundtrip(
        &derived_aes_key_a,
        &derived_aes_key_b,
        b"HKDF with salt+info derived key roundtrip",
    );

    // If info differs between parties, the derived keys should not match.
    let info_a = b"hkdf-info-a";
    let info_b = b"hkdf-info-b";
    let mut hkdf_algo_a = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info_a))
        .expect("Failed HKDF algo creation");
    let mut hkdf_algo_b = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), Some(info_b))
        .expect("Failed HKDF algo creation");

    let derived_aes_key_a =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo_a, &shared_secret_a, 256);
    let derived_aes_key_b =
        derive_aes_key_from_shared_secret(session, &mut hkdf_algo_b, &shared_secret_b, 256);

    let iv = [0u8; 16];
    let mut aes_algo_enc =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    let ciphertext = HsmEncrypter::encrypt_vec(
        &mut aes_algo_enc,
        &derived_aes_key_a,
        b"HKDF salt/info mismatch should fail",
    )
    .expect("Encryption failed");

    let mut aes_algo_dec =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES CBC algo creation failed");
    if let Ok(plaintext) =
        HsmDecrypter::decrypt_vec(&mut aes_algo_dec, &derived_aes_key_b, &ciphertext)
    {
        assert_ne!(plaintext, b"HKDF salt/info mismatch should fail");
    }
}

#[session_test]
fn test_hkdf_matrix_p256(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P256);
}

#[session_test]
fn test_hkdf_matrix_p384(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P384);
}

#[session_test]
fn test_hkdf_matrix_p521(session: HsmSession) {
    run_hkdf_matrix_for_curve(&session, HsmEccCurve::P521);
}

#[session_test]
fn test_hkdf_with_only_salt(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let salt = b"hkdf-salt-only";
    for &bits in &[128u32, 192u32, 256u32] {
        let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(salt), None)
            .expect("Failed HKDF algo creation");

        let derived_aes_key_a =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_a, bits);
        let derived_aes_key_b =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_b, bits);

        let plaintext = format!("HKDF salt-only AES-{bits} roundtrip").into_bytes();
        assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
    }
}

#[session_test]
fn test_hkdf_with_only_info(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let info = b"hkdf-info-only";
    for &bits in &[128u32, 192u32, 256u32] {
        let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(info))
            .expect("Failed HKDF algo creation");

        let derived_aes_key_a =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_a, bits);
        let derived_aes_key_b =
            derive_aes_key_from_shared_secret(&session, &mut hkdf_algo, &shared_secret_b, bits);

        let plaintext = format!("HKDF info-only AES-{bits} roundtrip").into_bytes();
        assert_aes_cbc_roundtrip(&derived_aes_key_a, &derived_aes_key_b, &plaintext);
    }
}

#[session_test]
fn test_hkdf_invalid_aes_key_size_fails(session: HsmSession) {
    let (shared_secret_a, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);
    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("Failed HKDF Algo creation");

    let aes_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(42)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES key props");

    let result =
        HsmKeyManager::derive_key(&session, &mut hkdf_algo, &shared_secret_a, aes_key_props);
    let err = match result {
        Ok(_) => panic!("HKDF derive should fail for invalid AES key size"),
        Err(err) => err,
    };
    assert_eq!(err, HsmError::InvalidArgument);
}

#[session_test]
fn test_hkdf_unsupported_derived_key_kind_fails(session: HsmSession) {
    let (shared_secret_a, _) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);
    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("Failed HKDF Algo creation");

    let unsupported_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .expect("Failed to build ECC key props");

    let result = HsmKeyManager::derive_key(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        unsupported_props,
    );
    let err = match result {
        Ok(_) => panic!("HKDF derive should fail for unsupported derived key kind"),
        Err(err) => err,
    };
    assert_eq!(err, HsmError::InvalidKeyProps);
}
