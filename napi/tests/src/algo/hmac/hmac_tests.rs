// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

use crate::algo::ecc::*;

// Maps an HMAC key kind to the hash algorithm used for HKDF.
pub(crate) fn hkdf_hash_for_hmac_key_kind(key_kind: HsmKeyKind) -> HsmHashAlgo {
    match key_kind {
        HsmKeyKind::HmacSha256 => HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha384 => HsmHashAlgo::Sha384,
        HsmKeyKind::HmacSha512 => HsmHashAlgo::Sha512,
        _ => panic!("Expected an HMAC key kind, got {key_kind:?}"),
    }
}

// Chooses an ECDH curve to derive shared secrets for a given HMAC key kind.
pub(crate) fn ecc_curve_for_hmac_key_kind(key_kind: HsmKeyKind) -> HsmEccCurve {
    match key_kind {
        HsmKeyKind::HmacSha256 => HsmEccCurve::P256,
        HsmKeyKind::HmacSha384 => HsmEccCurve::P384,
        HsmKeyKind::HmacSha512 => HsmEccCurve::P521,
        _ => panic!("Expected an HMAC key kind, got {key_kind:?}"),
    }
}

// Lists the HMAC variants covered by the parameterized tests.
fn hmac_test_key_kinds() -> [HsmKeyKind; 3] {
    [
        HsmKeyKind::HmacSha256,
        HsmKeyKind::HmacSha384,
        HsmKeyKind::HmacSha512,
    ]
}

// Converts an HMAC key kind to its key size in bits.
fn hmac_key_kind_to_bits(key_kind: HsmKeyKind) -> u32 {
    match key_kind {
        HsmKeyKind::HmacSha256 => 256,
        HsmKeyKind::HmacSha384 => 384,
        HsmKeyKind::HmacSha512 => 512,
        _ => panic!("Expected an HMAC key kind, got {key_kind:?}"),
    }
}

// Creates deterministic, non-constant message bytes (useful for chunking/streaming coverage).
fn test_message_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

// Derives a pair of ECDH shared secrets (party A and party B) that should match.
pub(crate) fn derive_ecdh_shared_secrets(
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

// Derives an HMAC key from an ECDH shared secret using HKDF.
fn derive_hmac_key_from_shared_secret(
    session: &HsmSession,
    hkdf_algo: &mut HsmHkdfAlgo,
    shared_secret: &HsmGenericSecretKey,
    key_kind: HsmKeyKind,
) -> HsmHmacKey {
    let bits = hmac_key_kind_to_bits(key_kind);

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

// Convenience helper to derive matching HMAC keys for two parties using ECDH + HKDF.
fn derive_ecdh_hmac_keypair(
    session: &HsmSession,
    curve: HsmEccCurve,
    hkdf_hash: HsmHashAlgo,
    key_kind: HsmKeyKind,
) -> (HsmHmacKey, HsmHmacKey) {
    let (shared_secret_a, shared_secret_b) = derive_ecdh_shared_secrets(session, curve);

    let mut hkdf_algo = HsmHkdfAlgo::new(hkdf_hash, None, None).expect("HKDF algo creation failed");

    let key_a =
        derive_hmac_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_a, key_kind);
    let key_b =
        derive_hmac_key_from_shared_secret(session, &mut hkdf_algo, &shared_secret_b, key_kind);
    (key_a, key_b)
}

// Computes an HMAC tag using buffered streaming updates.
fn streaming_sign(key: HsmHmacKey, msg: &[u8], chunk_sizes: &[usize]) -> Vec<u8> {
    let algo = HsmHmacAlgo::new();
    let mut ctx = HsmSigner::sign_init(algo, key).expect("Failed to initialize HMAC sign ctx");

    assert!(!chunk_sizes.is_empty(), "chunk_sizes must not be empty");

    let mut offset = 0;
    for &requested_size in chunk_sizes.iter().cycle() {
        if offset >= msg.len() {
            break;
        }

        assert!(requested_size != 0, "chunk_sizes must not contain 0");
        let end = (offset + requested_size).min(msg.len());
        HsmSignStreamingOpContext::update(&mut ctx, &msg[offset..end])
            .expect("Failed to update sign ctx");
        offset = end;
    }

    HsmSignStreamingOpContext::finish_vec(&mut ctx).expect("Failed to finish HMAC sign")
}

// Verifies an HMAC tag using buffered streaming updates.
fn streaming_verify(key: HsmHmacKey, msg: &[u8], chunk_sizes: &[usize], tag: &[u8]) -> bool {
    let algo = HsmHmacAlgo::new();
    let mut ctx =
        HsmVerifier::verify_init(algo, key).expect("Failed to initialize HMAC verify ctx");

    assert!(!chunk_sizes.is_empty(), "chunk_sizes must not be empty");

    let mut offset = 0;
    for &requested_size in chunk_sizes.iter().cycle() {
        if offset >= msg.len() {
            break;
        }

        assert!(requested_size != 0, "chunk_sizes must not contain 0");
        let end = (offset + requested_size).min(msg.len());
        HsmVerifyStreamingOpContext::update(&mut ctx, &msg[offset..end])
            .expect("Failed to update verify ctx");
        offset = end;
    }

    HsmVerifyStreamingOpContext::finish(&mut ctx, tag).expect("Failed to finish HMAC verify")
}

// Validates single-shot HMAC sign/verify roundtrip and wrong-message failure.
#[session_test]
fn test_hmac_sign_verify_roundtrip(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = test_message_bytes(0x00, 16);

    let mut sign_algo = HsmHmacAlgo::new();
    let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, &data).expect("HMAC sign failed");

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, &data, &tag).expect("HMAC verify failed");
    assert!(is_valid, "HMAC tag verification failed");

    let mut tampered = data.clone();
    tampered[0] ^= 0x01;

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, &tampered, &tag).expect("HMAC verify failed");
    assert!(!is_valid, "HMAC verification should fail for wrong data");
}

// Ensures verification fails when a valid tag is modified.
#[session_test]
fn test_hmac_verify_fails_for_modified_tag(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = test_message_bytes(0xde, 16);

    let mut sign_algo = HsmHmacAlgo::new();
    let mut tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, &data).expect("HMAC sign failed");
    assert!(!tag.is_empty(), "HMAC tag should not be empty");

    tag[0] ^= 0xFF;

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, &data, &tag).expect("HMAC verify failed");

    assert!(!is_valid, "HMAC verification should fail for modified tag");
}

// Validates streaming sign/verify roundtrip using index-driven chunking over one buffer.
#[session_test]
fn test_hmac_streaming_sign_verify_roundtrip(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = test_message_bytes(0xaa, 1000);
    let tag = streaming_sign(key_a, msg.as_ref(), &[10, 5, 400, 100, 50]);
    assert!(!tag.is_empty(), "HMAC tag should not be empty");

    let is_valid = streaming_verify(key_b, msg.as_ref(), &[10, 50, 200, 400, 10], &tag);
    assert!(is_valid, "Streaming HMAC verification failed");
}

// Ensures streaming verification fails when a streaming tag is modified.
#[session_test]
fn test_hmac_streaming_verify_fails_for_modified_tag(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = test_message_bytes(0xbb, 512);
    let mut tag = streaming_sign(key_a, msg.as_ref(), &[100, 150, 30]);
    tag[0] ^= 0x01;

    let is_valid = streaming_verify(key_b, msg.as_ref(), &[20, 60, 200], &tag);
    assert!(
        !is_valid,
        "Streaming HMAC verification should fail for modified tag"
    );
}

// Covers sign/verify across HmacSha256/HmacSha384/HmacSha512.
#[session_test]
fn test_hmac_sign_verify_roundtrip_multi_algo(session: HsmSession) {
    for key_kind in hmac_test_key_kinds() {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let (key_a, key_b) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);

        let data = test_message_bytes(0x10, 128);

        let mut sign_algo = HsmHmacAlgo::new();
        let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, &data).expect("HMAC sign failed");
        assert!(!tag.is_empty(), "HMAC tag should not be empty");

        let mut verify_algo = HsmHmacAlgo::new();
        let is_valid =
            HsmVerifier::verify(&mut verify_algo, &key_b, &data, &tag).expect("HMAC verify failed");
        assert!(is_valid, "HMAC tag verification failed for {key_kind:?}");

        let mut tampered = data.clone();
        tampered[0] ^= 0x01;

        let mut verify_algo = HsmHmacAlgo::new();
        let is_valid = HsmVerifier::verify(&mut verify_algo, &key_b, &tampered, &tag)
            .expect("HMAC verify failed");
        assert!(
            !is_valid,
            "HMAC verification should fail for wrong data ({key_kind:?})"
        );
    }
}

// Ensures streaming tag generation matches single-shot for the same key+message.
#[session_test]
fn test_hmac_streaming_matches_single_shot_multi_algo(session: HsmSession) {
    for key_kind in hmac_test_key_kinds() {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let (key_a, key_b) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);

        let msg = test_message_bytes(0x5a, 1000);

        let mut sign_algo = HsmHmacAlgo::new();
        let tag_single =
            HsmSigner::sign_vec(&mut sign_algo, &key_a, &msg).expect("HMAC sign failed");
        let tag_stream = streaming_sign(key_a, &msg, &[1, 7, 64, 13, 128, 3]);

        assert_eq!(
            tag_single, tag_stream,
            "Streaming tag must match single-shot for {key_kind:?}"
        );

        let is_valid = streaming_verify(key_b, &msg, &[32, 5, 900], &tag_stream);
        assert!(is_valid, "Streaming HMAC verify failed for {key_kind:?}");
    }
}

// Ensures verification fails when using an unrelated derived key.
#[session_test]
fn test_hmac_verify_fails_with_wrong_key_multi_algo(session: HsmSession) {
    for key_kind in hmac_test_key_kinds() {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);

        let (key_a1, _key_b1) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);
        let (_key_a2, key_b2) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);

        let data = test_message_bytes(0x44, 64);
        let mut sign_algo = HsmHmacAlgo::new();
        let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a1, &data).expect("HMAC sign failed");

        let mut verify_algo = HsmHmacAlgo::new();
        let is_valid = HsmVerifier::verify(&mut verify_algo, &key_b2, &data, &tag)
            .expect("HMAC verify failed");
        assert!(
            !is_valid,
            "Verification must fail with wrong key for {key_kind:?}"
        );
    }
}

// Ensures verification fails if the verifying key kind doesn't match the signing key kind.
#[session_test]
fn test_hmac_verify_fails_with_wrong_key_kind(session: HsmSession) {
    let data = test_message_bytes(0x22, 48);

    let (key_a_256, _key_b_256) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );
    let (_key_a_384, key_b_384) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha384,
        HsmKeyKind::HmacSha384,
    );

    let mut sign_algo = HsmHmacAlgo::new();
    let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a_256, &data).expect("HMAC sign failed");

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b_384, &data, &tag).expect("HMAC verify failed");
    assert!(
        !is_valid,
        "Verification must fail when key kind (and tag size) mismatches"
    );
}

// Ensures verification fails for truncated or extended tags (length mismatch).
#[session_test]
fn test_hmac_verify_fails_for_wrong_tag_length_multi_algo(session: HsmSession) {
    for key_kind in hmac_test_key_kinds() {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let (key_a, key_b) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);

        let data = test_message_bytes(0x77, 96);
        let mut sign_algo = HsmHmacAlgo::new();
        let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, &data).expect("HMAC sign failed");
        assert!(tag.len() >= 2, "Tag must be at least 2 bytes");

        let mut truncated = tag.clone();
        truncated.pop();

        let mut extended = tag.clone();
        extended.push(0);

        let mut verify_algo = HsmHmacAlgo::new();
        let is_valid = HsmVerifier::verify(&mut verify_algo, &key_b, &data, &truncated)
            .expect("HMAC verify failed");
        assert!(
            !is_valid,
            "Verification must fail for truncated tag ({key_kind:?})"
        );

        let mut verify_algo = HsmHmacAlgo::new();
        let is_valid = HsmVerifier::verify(&mut verify_algo, &key_b, &data, &extended)
            .expect("HMAC verify failed");
        assert!(
            !is_valid,
            "Verification must fail for extended tag ({key_kind:?})"
        );
    }
}

// Ensures buffered streaming contexts reject messages exceeding the device limit (1024 bytes).
#[session_test]
fn test_hmac_streaming_update_rejects_oversize_message(session: HsmSession) {
    let (key_a, _key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let algo = HsmHmacAlgo::new();
    let mut ctx = HsmSigner::sign_init(algo, key_a).expect("Failed to initialize HMAC sign ctx");

    let oversize = vec![0u8; 1025];
    let err = HsmSignStreamingOpContext::update(&mut ctx, &oversize)
        .expect_err("Oversize streaming update must fail");
    assert_eq!(err, HsmError::IndexOutOfRange);
}
