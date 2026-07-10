// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto::Rng;

use crate::algo::ecc::*;

// ================================
// Helper functions
// ================================

/// Generates a random IV of the given size.
pub fn test_iv(size: usize) -> Vec<u8> {
    Rng::rand_vec(size).expect("RNG failure generating IV")
}

/// Returns the KBKDF HMAC hash algorithms covered by the C++ matrix tests.
fn supported_kbkdf_hash_algos() -> &'static [HsmHashAlgo] {
    &[
        HsmHashAlgo::Sha1,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    ]
}

/// Creates a KBKDF SP 800-108 Counter Mode algorithm instance.
fn kbkdf_counter_algo(
    hash: HsmHashAlgo,
    label: Option<&[u8]>,
    context: Option<&[u8]>,
) -> HsmKbkdfAlgo {
    HsmKbkdfAlgo::new(hash, label, context).expect("Failed KBKDF Counter Mode algo creation")
}

/// Generates two ECDH keypairs and derives matching shared secrets for both parties.
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

/// Derives an AES key from a shared secret using KBKDF with the given parameters.
fn derive_aes_key_from_shared_secret(
    session: &HsmSession,
    kbkdf_algo: &mut HsmKbkdfAlgo,
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

    let derived_key = HsmKeyManager::derive_key(session, kbkdf_algo, shared_secret, aes_key_props)
        .expect("Failed to derive AES key");

    assert_eq!(derived_key.kind(), HsmKeyKind::Aes);
    assert_eq!(derived_key.bits(), bits);
    derived_key
        .try_into()
        .expect("Derived key was not an AES key")
}

/// Verifies AES-CBC encryption and decryption roundtrip correctness.
fn assert_aes_cbc_roundtrip(enc_key: &HsmAesKey, dec_key: &HsmAesKey, plaintext: &[u8]) {
    let iv = test_iv(16);

    let mut enc =
        HsmAesCbcAlgo::with_padding(iv.clone()).expect("AES-CBC algo creation failed (enc)");

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, enc_key, plaintext).expect("AES-CBC encryption failed");

    let mut dec = HsmAesCbcAlgo::with_padding(iv).expect("AES-CBC algo creation failed (dec)");

    let decrypted = HsmDecrypter::decrypt_vec(&mut dec, dec_key, &ciphertext)
        .expect("AES-CBC decryption failed");

    assert_eq!(decrypted, plaintext, "AES-CBC roundtrip mismatch");
}

/// Verifies two AES-CBC keys do not recover the same plaintext.
fn assert_aes_cbc_roundtrip_does_not_recover_plaintext(
    enc_key: &HsmAesKey,
    dec_key: &HsmAesKey,
    plaintext: &[u8],
) {
    let iv = [0u8; 16];

    let mut enc =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo creation failed (enc)");

    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut enc, enc_key, plaintext).expect("AES-CBC encryption failed");

    let mut dec =
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("AES-CBC algo creation failed (dec)");

    if let Ok(decrypted) = HsmDecrypter::decrypt_vec(&mut dec, dec_key, &ciphertext) {
        assert_ne!(
            decrypted, plaintext,
            "mismatched KBKDF-derived key recovered original plaintext"
        );
    }
}

/// Derives with custom output key properties and returns only success/failure.
fn kbkdf_derive_with_props(
    session: &HsmSession,
    hash: HsmHashAlgo,
    props: HsmKeyProps,
) -> Result<(), HsmError> {
    let (secret, _) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);
    let mut kbkdf = kbkdf_counter_algo(hash, Some(b"failure-label"), Some(b"failure-context"));

    HsmKeyManager::derive_key(session, &mut kbkdf, &secret, props).map(|_| ())
}

/// Runs the KBKDF matrix across HMAC hashes and AES key sizes for a curve.
fn run_kbkdf_counter_matrix_for_curve(session: &HsmSession, curve: HsmEccCurve) {
    let (shared_secret_a, shared_secret_b) = derive_ecdh_shared_secrets(session, curve);

    for &hash_algo in supported_kbkdf_hash_algos() {
        for &bits in &[128u32, 192u32, 256u32] {
            let label = format!("kbkdf-label-{curve:?}-{hash_algo:?}-{bits}");
            let context = format!("kbkdf-context-{curve:?}-{hash_algo:?}-{bits}");

            let mut kbkdf_a =
                kbkdf_counter_algo(hash_algo, Some(label.as_bytes()), Some(context.as_bytes()));
            let mut kbkdf_b =
                kbkdf_counter_algo(hash_algo, Some(label.as_bytes()), Some(context.as_bytes()));

            let key_a =
                derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &shared_secret_a, bits);
            let key_b =
                derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &shared_secret_b, bits);

            let plaintext =
                format!("KBKDF curve={curve:?} hash={hash_algo:?} aes_bits={bits}").into_bytes();
            assert_aes_cbc_roundtrip(&key_a, &key_b, &plaintext);
        }
    }
}

/// Verifies label-only KBKDF derives interoperable AES keys.
fn run_kbkdf_label_only_roundtrip(session: &HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let mut kbkdf_a = kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-only"), None);
    let mut kbkdf_b = kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-only"), None);

    let key_a = derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"label only");
}

/// Verifies context-only KBKDF derives interoperable AES keys.
fn run_kbkdf_context_only_roundtrip(session: &HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let mut kbkdf_a = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, Some(b"context-only"));
    let mut kbkdf_b = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, Some(b"context-only"));

    let key_a = derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"context only");
}

/// Verifies a specific KBKDF hash algorithm works with label and context.
fn run_kbkdf_hash_label_context_roundtrip(session: &HsmSession, hash: HsmHashAlgo, msg: &[u8]) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let mut kbkdf_a =
        kbkdf_counter_algo(hash, Some(b"kbkdf-hash-label"), Some(b"kbkdf-hash-context"));
    let mut kbkdf_b =
        kbkdf_counter_algo(hash, Some(b"kbkdf-hash-label"), Some(b"kbkdf-hash-context"));

    let key_a = derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, msg);
}

/// Verifies KBKDF derives a specific AES key size.
fn run_kbkdf_aes_size_roundtrip(session: &HsmSession, bits: u32) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let label = format!("aes-{bits}-label");
    let context = format!("aes-{bits}-context");

    let mut kbkdf_a = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(label.as_bytes()),
        Some(context.as_bytes()),
    );
    let mut kbkdf_b = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(label.as_bytes()),
        Some(context.as_bytes()),
    );

    let key_a = derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &secret_a, bits);
    let key_b = derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &secret_b, bits);

    let msg = format!("kbkdf aes {bits}").into_bytes();
    assert_aes_cbc_roundtrip(&key_a, &key_b, &msg);
}

/// Verifies identical shared secret and identical KBKDF parameters derive compatible keys.
fn run_kbkdf_same_secret_same_params_roundtrip(session: &HsmSession) {
    let (secret, _) = derive_ecdh_shared_secrets(session, HsmEccCurve::P256);

    let mut kbkdf_a = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(b"same-secret-label"),
        Some(b"same-secret-context"),
    );
    let mut kbkdf_b = kbkdf_counter_algo(
        HsmHashAlgo::Sha256,
        Some(b"same-secret-label"),
        Some(b"same-secret-context"),
    );

    let key_a = derive_aes_key_from_shared_secret(session, &mut kbkdf_a, &secret, 256);
    let key_b = derive_aes_key_from_shared_secret(session, &mut kbkdf_b, &secret, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"same secret same params");
}

// ================================
// Test cases
// ================================

/// Verifies KBKDF Counter Mode matrix coverage for P256.
#[session_test]
fn test_kbkdf_matrix_p256(session: HsmSession) {
    run_kbkdf_counter_matrix_for_curve(&session, HsmEccCurve::P256);
}

/// Verifies KBKDF Counter Mode matrix coverage for P384.
#[session_test]
fn test_kbkdf_matrix_p384(session: HsmSession) {
    run_kbkdf_counter_matrix_for_curve(&session, HsmEccCurve::P384);
}

/// Verifies KBKDF Counter Mode matrix coverage for P521.
#[session_test]
fn test_kbkdf_matrix_p521(session: HsmSession) {
    run_kbkdf_counter_matrix_for_curve(&session, HsmEccCurve::P521);
}

/// Verifies KBKDF rejects deriving an AES-GCM key.
#[session_test]
fn test_kbkdf_derive_aes_gcm_key_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES-GCM key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES-GCM output key kind");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects deriving a SharedSecret key.
#[session_test]
fn test_kbkdf_derive_unsupported_key_kind_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("Failed to build shared-secret key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject SharedSecret output key kind");
    assert_eq!(err, HsmError::InvalidArgument);
}

/// Verifies KBKDF rejects deriving with zero output bit length.
#[session_test]
fn test_kbkdf_derive_zero_bit_len_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(0)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build zero-bit AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject zero-bit AES output");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF works when only a label is supplied.
#[session_test]
fn test_kbkdf_label_only_roundtrip(session: HsmSession) {
    run_kbkdf_label_only_roundtrip(&session);
}

/// Verifies KBKDF works when only a context is supplied.
#[session_test]
fn test_kbkdf_context_only_roundtrip(session: HsmSession) {
    run_kbkdf_context_only_roundtrip(&session);
}

/// Verifies KBKDF roundtrip with HMAC-SHA512 label/context parameters.
#[session_test]
fn test_kbkdf_hmac_sha512_label_context_roundtrip(session: HsmSession) {
    run_kbkdf_hash_label_context_roundtrip(&session, HsmHashAlgo::Sha512, b"kbkdf hmac sha512");
}

/// Verifies KBKDF roundtrip with HMAC-SHA384 label/context parameters.
#[session_test]
fn test_kbkdf_hmac_sha384_label_context_roundtrip(session: HsmSession) {
    run_kbkdf_hash_label_context_roundtrip(&session, HsmHashAlgo::Sha384, b"kbkdf hmac sha384");
}

/// Verifies KBKDF can derive a 128-bit AES key.
#[session_test]
fn test_kbkdf_derive_aes_128_roundtrip(session: HsmSession) {
    run_kbkdf_aes_size_roundtrip(&session, 128);
}

/// Verifies KBKDF can derive a 192-bit AES key.
#[session_test]
fn test_kbkdf_derive_aes_192_roundtrip(session: HsmSession) {
    run_kbkdf_aes_size_roundtrip(&session, 192);
}

/// Verifies KBKDF rejects AES output keys without encrypt/decrypt usage flags.
#[session_test]
fn test_kbkdf_derive_aes_without_usage_flags_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .build()
        .expect("Failed to build AES key props without usage flags");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES key without usage flags");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects unsupported AES key sizes.
#[session_test]
fn test_kbkdf_derive_invalid_aes_key_size_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(129)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build invalid-size AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject unsupported AES key size");
    assert_eq!(err, HsmError::InvalidArgument);
}

/// Verifies KBKDF rejects non-secret output key classes.
#[session_test]
fn test_kbkdf_derive_non_secret_key_class_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build public AES key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject non-secret output key class");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF works when both label and context are omitted.
#[session_test]
fn test_kbkdf_no_label_no_context_roundtrip(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut kbkdf_a = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, None);
    let mut kbkdf_b = kbkdf_counter_algo(HsmHashAlgo::Sha256, None, None);

    let key_a = derive_aes_key_from_shared_secret(&session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip(&key_a, &key_b, b"kbkdf no label no context");
}

/// Verifies KBKDF derives compatible keys from the same shared secret and parameters.
#[session_test]
fn test_kbkdf_same_secret_same_params_roundtrip(session: HsmSession) {
    run_kbkdf_same_secret_same_params_roundtrip(&session);
}

/// Verifies changing KBKDF label changes the derived key material.
#[session_test]
fn test_kbkdf_different_label_produces_non_interoperable_key(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut kbkdf_a =
        kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-a"), Some(b"same-context"));

    let mut kbkdf_b =
        kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"label-b"), Some(b"same-context"));

    let key_a = derive_aes_key_from_shared_secret(&session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip_does_not_recover_plaintext(
        &key_a,
        &key_b,
        b"different KBKDF label should not interoperate",
    );
}

/// Verifies changing KBKDF context changes the derived key material.
#[session_test]
fn test_kbkdf_different_context_produces_non_interoperable_key(session: HsmSession) {
    let (secret_a, secret_b) = derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut kbkdf_a =
        kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"same-label"), Some(b"context-a"));

    let mut kbkdf_b =
        kbkdf_counter_algo(HsmHashAlgo::Sha256, Some(b"same-label"), Some(b"context-b"));

    let key_a = derive_aes_key_from_shared_secret(&session, &mut kbkdf_a, &secret_a, 256);
    let key_b = derive_aes_key_from_shared_secret(&session, &mut kbkdf_b, &secret_b, 256);

    assert_aes_cbc_roundtrip_does_not_recover_plaintext(
        &key_a,
        &key_b,
        b"different KBKDF context should not interoperate",
    );
}

/// Verifies KBKDF rejects AES output keys with only encrypt usage enabled.
#[session_test]
fn test_kbkdf_derive_aes_encrypt_only_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .build()
        .expect("Failed to build AES encrypt-only key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES encrypt-only output key");
    assert_eq!(err, HsmError::InvalidKeyProps);
}

/// Verifies KBKDF rejects AES output keys with only decrypt usage enabled.
#[session_test]
fn test_kbkdf_derive_aes_decrypt_only_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_decrypt(true)
        .build()
        .expect("Failed to build AES decrypt-only key props");

    let err = kbkdf_derive_with_props(&session, HsmHashAlgo::Sha256, props)
        .expect_err("KBKDF derive should reject AES decrypt-only output key");
    assert_eq!(err, HsmError::InvalidKeyProps);
}
