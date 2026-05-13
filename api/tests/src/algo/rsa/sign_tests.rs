// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;
use crypto::*;

use super::*;

// ================================
// Helper functions
// ================================

/// Generate an RSA key pair configured for wrapping and unwrapping operations
fn get_rsa_unwrapping_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate unwrapping key");

    (priv_key, pub_key)
}

/// Import an external RSA key into HSM by wrapping with RSA-AES and unwrapping into key objects
fn import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let hash_algo = HsmHashAlgo::Sha384;
    let kek_size = 32;

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, kek_size);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, der)
        .expect("Failed to wrap AES Key");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);
    let (priv_key, pub_key) = unwrap_algo
        .unwrap_key_pair(
            &unwrapping_priv_key,
            &wrapped_key,
            priv_key_props,
            pub_key_props,
        )
        .expect("Failed to unwrap RSA AES key pair");

    (priv_key, pub_key)
}

// ============================================================
// test case section
// ============================================================

/// Ensure RSA-2048 PKCS#1 sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_2048_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let mut hash_algo = HsmHashAlgo::Sha256;
    let message = b"Hello, RSA 2048!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-3072 PKCS#1 sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_3072_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let mut hash_algo = HsmHashAlgo::Sha384;
    let message = b"Hello, RSA 3072!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-4096 PKCS#1 sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_4096_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let mut hash_algo = HsmHashAlgo::Sha512;
    let message = b"Hello, RSA 4096!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-2048 PSS sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_2048_pss_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let mut hash_algo = HsmHashAlgo::Sha256;
    let message = b"Hello, RSA 2048!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-3072 PSS sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_3072_pss_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let mut hash_algo = HsmHashAlgo::Sha384;
    let message = b"Hello, RSA 3072!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-4096 PSS sign/verify succeeds using pre-hashed input
#[session_test]
fn test_rsa_4096_pss_sign_verify(session: HsmSession) {
    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let mut hash_algo = HsmHashAlgo::Sha512;
    let message = b"Hello, RSA 4096!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure verification fails when using a different public key
#[session_test]
fn test_rsa_verify_wrong_public_key_fails(session: HsmSession) {
    let priv1 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let priv2 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");

    let (priv1, _) = import_rsa_key(
        &session,
        &priv1.to_vec().expect("Failed to export RSA Key"),
        2048,
    );
    let (_, pub2) = import_rsa_key(
        &session,
        &priv2.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = HsmSigner::sign_vec(&mut algo, &priv1, &hash).expect("Failed to sign message");

    let result =
        HsmVerifier::verify(&mut algo, &pub2, &hash, &sig).expect("Failed to verify signature");
    // Verification should return false when using the wrong public key.
    assert!(
        !result,
        "Verification should return false with the wrong public key"
    );
}

/// Ensure verification fails when signature is corrupted
#[session_test]
fn test_rsa_verify_modified_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let mut sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    sig[0] ^= 0xFF; // corrupt signature

    let valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when hash differs
#[session_test]
fn test_rsa_verify_wrong_hash_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;

    let hash1 =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"msg1").expect("Failed to hash message");
    let hash2 =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"msg2").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash1).expect("Failed to sign message");

    let valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash2, &sig).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when using different hash algorithm
#[session_test]
fn test_rsa_verify_mismatched_hash_algo_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo1 = HsmHashAlgo::Sha256;
    let hash_algo2 = HsmHashAlgo::Sha384;

    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo1, b"hello").expect("Failed to hash message");

    let mut sign_algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo1);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash).expect("Failed to sign message");

    let mut verify_algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo2);

    let valid = HsmVerifier::verify(&mut verify_algo, &pub_key, &hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure PSS verification fails with different salt length
#[session_test]
fn test_rsa_pss_salt_len_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut sign_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash).expect("Failed to sign message");

    let mut verify_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 20);

    let valid = HsmVerifier::verify(&mut verify_algo, &pub_key, &hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure unwrap fails when private key lacks sign capability
#[session_test]
fn test_rsa_unwrap_without_sign_permission_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    // Missing can_sign(true)
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .build()
        .unwrap();

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA private key DER");
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    //  EXPECT FAILURE HERE
    let result = unwrap_algo.unwrap_key_pair(&unwrap_priv, &wrapped, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Ensure verification fails when padding schemes differ
#[session_test]
fn test_rsa_verify_pkcs1_vs_pss_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    // Sign with PKCS1
    let mut sign_algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash).expect("Failed to sign message");

    // Verify with PSS
    let mut verify_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let valid = HsmVerifier::verify(&mut verify_algo, &pub_key, &hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure PKCS1 signatures are deterministic
#[session_test]
fn test_rsa_pkcs1_deterministic_signature(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, _) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let sig1 = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");
    let sig2 = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    assert_eq!(sig1, sig2);
}

/// Ensure verification fails when PSS signature is verified as PKCS1
#[session_test]
fn test_rsa_pss_vs_pkcs1_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut sign_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, &hash).expect("Failed to sign message");

    let mut verify_algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let valid = HsmVerifier::verify(&mut verify_algo, &pub_key, &hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when signature is truncated
#[session_test]
fn test_rsa_verify_truncated_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let mut sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    sig.truncate(sig.len() / 2);

    let valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when signature is too large
#[session_test]
fn test_rsa_verify_oversized_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let mut sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    sig.extend_from_slice(&[0u8; 10]); // make too large

    let valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when key size differs
#[session_test]
fn test_rsa_verify_mismatched_key_size_fails(session: HsmSession) {
    let priv1 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key"); // 2048
    let priv2 = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key"); // 3072

    let (priv1, _) = import_rsa_key(
        &session,
        &priv1.to_vec().expect("Failed to export RSA Key"),
        2048,
    );
    let (_, pub2) = import_rsa_key(
        &session,
        &priv2.to_vec().expect("Failed to export RSA Key"),
        3072,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = HsmSigner::sign_vec(&mut algo, &priv1, &hash).expect("Failed to sign message");

    let valid =
        HsmVerifier::verify(&mut algo, &pub2, &hash, &sig).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure PSS signatures are non-deterministic
#[session_test]
fn test_rsa_pss_non_deterministic_signature(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, _) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    // Generate baseline signature
    let sig1 = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    // Retry a few times to detect non-determinism
    let mut saw_difference = false;

    for _ in 0..5 {
        let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

        if sig != sig1 {
            saw_difference = true;
            break;
        }
    }

    assert!(
        saw_difference,
        "Expected RSA-PSS signatures to vary across repeated signing attempts"
    );
}

/// Ensure verification fails with empty signature
#[session_test]
fn test_rsa_verify_empty_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (_priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let valid =
        HsmVerifier::verify(&mut algo, &pub_key, &hash, &[]).expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure verification fails when provided hash is empty
#[session_test]
fn test_rsa_verify_empty_hash_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let (priv_key, pub_key) = import_rsa_key(&session, &priv_key.to_vec().unwrap(), 2048);

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    // valid signature
    let valid_hash = vec![0xAA; 32];
    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &valid_hash).unwrap();

    // invalid hash
    let empty_hash = vec![];

    let valid = HsmVerifier::verify(&mut algo, &pub_key, &empty_hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure PSS works with zero salt length
#[session_test]
fn test_rsa_pss_zero_salt_len(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 0);

    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    let result = HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig);

    assert!(result.unwrap());
}

/// Ensure signing and verifying large message works
#[session_test]
fn test_rsa_sign_verify_large_message(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let large_msg = vec![0xAB; 10_000];

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, &large_msg).expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    let result = HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig);

    assert!(result.unwrap());
}

/// Ensure verification fails when hash length does not match expected digest size
#[session_test]
fn test_rsa_verify_invalid_hash_length_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let valid_hash = vec![0xAA; 32];
    let sig =
        HsmSigner::sign_vec(&mut algo, &priv_key, &valid_hash).expect("Failed to sign message");

    let bad_hash = vec![0xAA; 10]; // invalid length

    let valid = HsmVerifier::verify(&mut algo, &pub_key, &bad_hash, &sig)
        .expect("Verification call failed");

    assert!(!valid, "Verification should report invalid signature");
}

/// Ensure repeated verification with same inputs consistently succeeds
#[session_test]
fn test_rsa_verify_repeatability(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign message");

    for _ in 0..3 {
        let result = HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig);
        assert!(result.unwrap());
    }
}

/// Ensure PSS signing fails when salt length exceeds maximum allowed
#[session_test]
fn test_rsa_pss_salt_len_too_large_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, _pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    // deliberately too large
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 300);

    let result = HsmSigner::sign_vec(&mut algo, &priv_key, &hash);

    assert!(
        result.is_err(),
        "Expected failure for excessive salt length, got {:?}",
        result
    );
}
/// Ensure PSS works with maximum valid salt length
#[session_test]
fn test_rsa_pss_max_salt_len(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    // max salt = 256 - 32 - 2 = 222
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 222);

    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, &hash)
        .expect("Signing should succeed at max salt length");

    let result = HsmVerifier::verify(&mut algo, &pub_key, &hash, &sig);

    assert!(result.unwrap());
}

/// Ensure verification fails for all-zero and all-0xFF signatures
#[session_test]
fn test_rsa_verify_all_zero_and_all_ff_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let (_priv_key, pub_key) = import_rsa_key(
        &session,
        &priv_key.to_vec().expect("Failed to export RSA Key"),
        2048,
    );

    let mut hash_algo = HsmHashAlgo::Sha256;
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, b"hello").expect("Failed to hash message");

    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let sig_len = 256; // RSA-2048

    let all_zero_sig = vec![0u8; sig_len];
    let all_ff_sig = vec![0xFFu8; sig_len];

    let valid_zero = HsmVerifier::verify(&mut algo, &pub_key, &hash, &all_zero_sig)
        .expect("Verification call failed");
    let valid_ff = HsmVerifier::verify(&mut algo, &pub_key, &hash, &all_ff_sig)
        .expect("Verification call failed");

    assert!(
        !valid_zero,
        "Verification should report invalid signature for all-zero signature"
    );
    assert!(
        !valid_ff,
        "Verification should report invalid signature for all-0xFF signature"
    );
}
