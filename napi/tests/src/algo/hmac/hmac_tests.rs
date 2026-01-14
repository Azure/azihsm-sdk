// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

use crate::algo::ecc::*;

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

fn derive_hmac_key_from_shared_secret(
    session: &HsmSession,
    hkdf_algo: &mut HsmHkdfAlgo,
    shared_secret: &HsmGenericSecretKey,
    key_kind: HsmKeyKind,
) -> HsmHmacKey {
    let bits = match key_kind {
        HsmKeyKind::HmacSha256 => 256,
        HsmKeyKind::HmacSha384 => 384,
        HsmKeyKind::HmacSha512 => 512,
        _ => panic!("Expected an HMAC key kind, got {key_kind:?}"),
    };

    let hmac_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(key_kind)
        .bits(bits)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let derived_key = HsmKeyManager::derive_key(session, hkdf_algo, shared_secret, hmac_key_props)
        .expect("Failed to derive HMAC key");

    assert_eq!(derived_key.kind(), key_kind);
    derived_key
        .try_into()
        .expect("Failed to convert to HsmHmacKey")
}

fn streaming_sign(key: HsmHmacKey, msg: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
    let algo = HsmHmacAlgo::new();
    let mut ctx = HsmSigner::sign_init(algo, key).expect("Failed to initialize HMAC sign ctx");

    assert!(!chunk_sizes.is_empty(), "chunk_sizes must not be empty");

    let mut offset = 0;
    let mut i = 0;
    while offset < msg.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(msg.len() - offset);
        assert!(size != 0, "chunk_sizes must not contain 0");

        let chunk = &msg[offset..offset + size];
        offset += size;
        i += 1;

        HsmSignStreamingOpContext::update(&mut ctx, chunk).expect("Failed to update sign ctx");
    }

    HsmSignStreamingOpContext::finish_vec(&mut ctx).expect("Failed to finish HMAC sign")
}

fn streaming_verify(key: HsmHmacKey, msg: &[u8], chunk_sizes: &[usize], tag: &[u8]) -> bool {
    let algo = HsmHmacAlgo::new();
    let mut ctx =
        HsmVerifier::verify_init(algo, key).expect("Failed to initialize HMAC verify ctx");

    assert!(!chunk_sizes.is_empty(), "chunk_sizes must not be empty");

    let mut offset = 0;
    let mut i = 0;
    while offset < msg.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(msg.len() - offset);
        assert!(size != 0, "chunk_sizes must not contain 0");

        let chunk = &msg[offset..offset + size];
        offset += size;
        i += 1;

        HsmVerifyStreamingOpContext::update(&mut ctx, chunk).expect("Failed to update verify ctx");
    }

    HsmVerifyStreamingOpContext::finish(&mut ctx, tag).expect("Failed to finish HMAC verify")
}
// Validates single-shot HMAC sign/verify roundtrip and wrong-message failure.
#[session_test]
fn test_hmac_sign_verify_roundtrip(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("HKDF algo creation failed");

    let key_a = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        HsmKeyKind::HmacSha256,
    );
    let key_b = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_b,
        HsmKeyKind::HmacSha256,
    );

    let data = b"HMAC sign/verify roundtrip";

    let mut sign_algo = HsmHmacAlgo::new();
    let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, data).expect("HMAC sign failed");

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, data, &tag).expect("HMAC verify failed");
    assert!(is_valid, "HMAC tag verification failed");

    let mut verify_algo = HsmHmacAlgo {};
    let is_valid = HsmVerifier::verify(&mut verify_algo, &key_b, b"tampered", &tag)
        .expect("HMAC verify failed");
    assert!(!is_valid, "HMAC verification should fail for wrong data");
}

// Ensures verification fails when a valid tag is modified.
#[session_test]
fn test_hmac_verify_fails_for_modified_tag(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("HKDF algo creation failed");

    let key_a = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        HsmKeyKind::HmacSha256,
    );
    let key_b = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_b,
        HsmKeyKind::HmacSha256,
    );

    let data = b"HMAC verify should fail for modified tag";

    let mut sign_algo = HsmHmacAlgo::new();
    let mut tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, data).expect("HMAC sign failed");
    assert!(!tag.is_empty(), "HMAC tag should not be empty");

    tag[0] ^= 0xFF;

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, data, &tag).expect("HMAC verify failed");

    assert!(!is_valid, "HMAC verification should fail for modified tag");
}

// Validates streaming sign/verify roundtrip using index-driven chunking over one buffer.
#[session_test]
fn test_hmac_streaming_sign_verify_roundtrip(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("HKDF algo creation failed");

    let key_a = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        HsmKeyKind::HmacSha256,
    );
    let key_b = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_b,
        HsmKeyKind::HmacSha256,
    );

    let msg = vec![0xaa; 1000];
    let tag = streaming_sign(key_a, msg.as_ref(), &[10, 5, 400, 100, 50]);
    assert!(!tag.is_empty(), "HMAC tag should not be empty");

    let is_valid = streaming_verify(key_b, msg.as_ref(), &[10, 50, 200, 400, 10], &tag);
    assert!(is_valid, "Streaming HMAC verification failed");
}

// Ensures streaming verification fails when a streaming tag is modified.
#[session_test]
fn test_hmac_streaming_verify_fails_for_modified_tag(session: HsmSession) {
    let (shared_secret_a, shared_secret_b) =
        derive_ecdh_shared_secrets(&session, HsmEccCurve::P256);

    let mut hkdf_algo =
        HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).expect("HKDF algo creation failed");

    let key_a = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_a,
        HsmKeyKind::HmacSha256,
    );
    let key_b = derive_hmac_key_from_shared_secret(
        &session,
        &mut hkdf_algo,
        &shared_secret_b,
        HsmKeyKind::HmacSha256,
    );

    let msg = vec![0xbb; 512];
    let mut tag = streaming_sign(key_a, msg.as_ref(), &[100, 150, 30]);
    tag[0] ^= 0x01;

    let is_valid = streaming_verify(key_b, msg.as_ref(), &[20, 60, 200], &tag);
    assert!(
        !is_valid,
        "Streaming HMAC verification should fail for modified tag"
    );
}
