// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

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

/// Verifies that HMAC sign context rejects update and finish after successful finish.
#[session_test]
fn test_hmac_streaming_sign_update_after_finish_fails(session: HsmSession) {
    let (key_a, _key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let algo = HsmHmacAlgo::new();
    let mut ctx = HsmSigner::sign_init(algo, key_a).expect("Failed to initialize HMAC sign ctx");

    let msg = b"test message";
    HsmSignStreamingOpContext::update(&mut ctx, msg).expect("update should succeed");

    let _tag =
        HsmSignStreamingOpContext::finish_vec(&mut ctx).expect("first finish should succeed");

    // update after finish must fail
    let res = HsmSignStreamingOpContext::update(&mut ctx, b"more data");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState, got {:?}",
        res
    );

    // second finish must fail
    let res = HsmSignStreamingOpContext::finish_vec(&mut ctx);
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState, got {:?}",
        res
    );
}

/// Verifies that HMAC verify context rejects update and finish after successful finish.
#[session_test]
fn test_hmac_streaming_verify_update_after_finish_fails(session: HsmSession) {
    let (key_a, _key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = b"test message";
    let tag = streaming_sign(key_a.clone(), msg, &[msg.len()]);

    let algo = HsmHmacAlgo::new();
    let mut ctx =
        HsmVerifier::verify_init(algo, key_a).expect("Failed to initialize HMAC verify ctx");

    HsmVerifyStreamingOpContext::update(&mut ctx, msg).expect("update should succeed");

    let result =
        HsmVerifyStreamingOpContext::finish(&mut ctx, &tag).expect("first finish should succeed");
    assert!(result, "first verification should succeed");

    // update after finish must fail
    let res = HsmVerifyStreamingOpContext::update(&mut ctx, b"more data");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState, got {:?}",
        res
    );

    // second finish must fail
    let res = HsmVerifyStreamingOpContext::finish(&mut ctx, &tag);
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState, got {:?}",
        res
    );
}

#[session_test]
fn test_hmac_empty_message_roundtrip(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = vec![];

    let mut sign_algo = HsmHmacAlgo::new();
    let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, &data)
        .expect("HMAC sign failed for empty input");

    let mut verify_algo = HsmHmacAlgo::new();
    let is_valid =
        HsmVerifier::verify(&mut verify_algo, &key_b, &data, &tag).expect("HMAC verify failed");

    assert!(is_valid, "Empty message HMAC should verify");
}

#[session_test]
fn test_hmac_streaming_empty_message(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg: Vec<u8> = vec![];

    let tag = streaming_sign(key_a, &msg, &[1]);
    let is_valid = streaming_verify(key_b, &msg, &[1], &tag);

    assert!(is_valid, "Streaming HMAC should support empty message");
}

#[session_test]
fn test_hmac_deterministic_output(session: HsmSession) {
    let (key_a, _key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = test_message_bytes(0x42, 128);

    let mut algo1 = HsmHmacAlgo::new();
    let tag1 = HsmSigner::sign_vec(&mut algo1, &key_a, &data).unwrap();

    let mut algo2 = HsmHmacAlgo::new();
    let tag2 = HsmSigner::sign_vec(&mut algo2, &key_a, &data).unwrap();

    assert_eq!(tag1, tag2, "HMAC must be deterministic");
}

/// Ensures verification fails when the tag is empty.
#[session_test]
fn test_hmac_verify_fails_with_empty_tag(session: HsmSession) {
    let (_key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = b"test data";

    let mut verify_algo = HsmHmacAlgo::new();
    let result = HsmVerifier::verify(&mut verify_algo, &key_b, data, &[]);

    assert_eq!(result, Ok(false), "Empty tag must not verify");
}

/// Ensures streaming finish works correctly without any update calls (empty message).
#[session_test]
fn test_hmac_streaming_finish_without_update(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let mut sign_ctx = HsmSigner::sign_init(HsmHmacAlgo::new(), key_a).expect("sign_init failed");

    let tag = HsmSignStreamingOpContext::finish_vec(&mut sign_ctx).expect("finish should succeed");

    let mut verify_ctx =
        HsmVerifier::verify_init(HsmHmacAlgo::new(), key_b).expect("verify_init failed");

    let is_valid =
        HsmVerifyStreamingOpContext::finish(&mut verify_ctx, &tag).expect("verify finish failed");

    assert!(is_valid, "Empty streaming HMAC should verify");
}

/// Ensures streaming works at the exact device limit (1024 bytes).
#[session_test]
fn test_hmac_streaming_exact_limit(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = vec![0u8; 1024];

    let tag = streaming_sign(key_a, &msg, &[256, 256, 512]);

    let is_valid = streaming_verify(key_b, &msg, &[128, 512, 384], &tag);

    assert!(is_valid, "1024-byte streaming should succeed");
}

/// Ensures verification fails when key kinds differ (including tag length mismatch).
#[session_test]
fn test_hmac_verify_fails_with_mismatched_key_kind_and_tag_length(session: HsmSession) {
    let (key_a, _) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let (_, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        HsmKeyKind::HmacSha384,
    );

    let data = b"hash mismatch test";

    let mut sign_algo = HsmHmacAlgo::new();
    let tag = HsmSigner::sign_vec(&mut sign_algo, &key_a, data).expect("HMAC sign failed");

    let mut verify_algo = HsmHmacAlgo::new();
    let result = HsmVerifier::verify(&mut verify_algo, &key_b, data, &tag);

    let is_valid = result.expect("HMAC verify failed unexpectedly");

    assert!(
        !is_valid,
        "Verification must fail across different hash families"
    );
}

#[session_test]
fn test_hmac_verify_fails_with_mismatched_derivation_hash(session: HsmSession) {
    let key_kind = HsmKeyKind::HmacSha256; // same tag length

    let (key_a, _) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256, // HKDF hash A
        key_kind,
    );

    let (_, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha384, // HKDF hash B (DIFFERENT)
        key_kind,
    );

    let data = b"hash mismatch test";

    let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, data).unwrap();

    let result = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, data, &tag);

    assert_eq!(
        result,
        Ok(false),
        "Verification must fail cleanly for mismatched derivation hash"
    );
}

/// Ensures derived HMAC keys differ when HKDF salt differs.
#[session_test]
fn test_hmac_derived_key_changes_with_hkdf_salt(session: HsmSession) {
    let curve = HsmEccCurve::P256;
    let key_kind = HsmKeyKind::HmacSha256;

    let (shared_a, _) = derive_ecdh_shared_secrets(&session, curve);

    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"salt1"), None).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, Some(b"salt2"), None).unwrap();

    let key1 = derive_hmac_key_from_shared_secret(&session, &mut hkdf1, &shared_a, key_kind);
    let key2 = derive_hmac_key_from_shared_secret(&session, &mut hkdf2, &shared_a, key_kind);

    let msg = b"same message";

    let tag1 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key1, msg).unwrap();
    let tag2 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key2, msg).unwrap();

    assert_ne!(
        tag1, tag2,
        "Different salt must produce different HMAC keys"
    );
}

/// Ensures derived HMAC keys differ when HKDF info differs.
#[session_test]
fn test_hmac_derived_key_changes_with_hkdf_info(session: HsmSession) {
    let curve = HsmEccCurve::P256;
    let key_kind = HsmKeyKind::HmacSha256;

    let (shared_a, _) = derive_ecdh_shared_secrets(&session, curve);

    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(b"info1")).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, Some(b"info2")).unwrap();

    let key1 = derive_hmac_key_from_shared_secret(&session, &mut hkdf1, &shared_a, key_kind);
    let key2 = derive_hmac_key_from_shared_secret(&session, &mut hkdf2, &shared_a, key_kind);

    let msg = b"same message";

    let tag1 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key1, msg).unwrap();
    let tag2 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key2, msg).unwrap();

    assert_ne!(
        tag1, tag2,
        "Different info must produce different HMAC keys"
    );
}

/// Ensures HMAC algo instance can be reused safely.
#[session_test]
fn test_hmac_algo_reuse(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data1 = b"msg1";
    let data2 = b"msg2";

    let mut algo = HsmHmacAlgo::new();

    let tag1 = HsmSigner::sign_vec(&mut algo, &key_a, data1).unwrap();
    let tag2 = HsmSigner::sign_vec(&mut algo, &key_a, data2).unwrap();

    let valid1 = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, data1, &tag1).unwrap();
    let valid2 = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, data2, &tag2).unwrap();

    assert!(valid1 && valid2);
}

/// Ensures single-shot HMAC rejects input exceeding device limit.
#[session_test]
fn test_hmac_large_input_single_shot_rejected(session: HsmSession) {
    let (key_a, _key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = test_message_bytes(0x55, 1025);

    let result = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, &data);

    assert!(
        matches!(result, Err(HsmError::IndexOutOfRange)),
        "Single-shot HMAC must reject >1024 bytes"
    );
}

#[session_test]
fn test_hmac_streaming_chunking_independence(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = test_message_bytes(0x33, 512);

    let tag1 = streaming_sign(key_a.clone(), &msg, &[512]);
    let tag2 = streaming_sign(key_a.clone(), &msg, &[1]);
    let tag3 = streaming_sign(key_a, &msg, &[13, 7, 64, 3, 99]);

    assert_eq!(tag1, tag2);
    assert_eq!(tag1, tag3);

    let valid = streaming_verify(key_b, &msg, &[128, 128, 256], &tag1);
    assert!(valid);
}

/// Ensures verification fails when keys are derived from different curves
/// even if hash algorithm and key kind match.
#[session_test]
fn test_hmac_verify_fails_with_mismatched_curve(session: HsmSession) {
    let key_kind = HsmKeyKind::HmacSha256;
    let hash = HsmHashAlgo::Sha256;

    // Same hash + key kind, different curves
    let (key_a, _) = derive_ecdh_hmac_keypair(&session, HsmEccCurve::P256, hash, key_kind);

    let (_, key_b) = derive_ecdh_hmac_keypair(&session, HsmEccCurve::P384, hash, key_kind);

    let data = b"curve mismatch test";

    let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, data).expect("sign failed");

    let result = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, data, &tag);

    assert_eq!(
        result,
        Ok(false),
        "Verification must fail when derived from different curves"
    );
}

#[session_test]
fn test_hmac_single_shot_tag_verified_by_streaming(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = test_message_bytes(0x91, 512);

    // single-shot sign
    let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, &msg)
        .expect("single-shot sign failed");

    // streaming verify
    let is_valid = streaming_verify(key_b, &msg, &[17, 33, 128, 7, 327], &tag);

    assert!(is_valid, "Streaming verify must accept single-shot tag");
}

#[session_test]
fn test_hmac_streaming_zero_length_update(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = b"zero length update test";

    let mut ctx = HsmSigner::sign_init(HsmHmacAlgo::new(), key_a).unwrap();

    // zero-length update should be a no-op (not fail)
    HsmSignStreamingOpContext::update(&mut ctx, &[]).unwrap();

    HsmSignStreamingOpContext::update(&mut ctx, msg).unwrap();
    let tag = HsmSignStreamingOpContext::finish_vec(&mut ctx).unwrap();

    let valid = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, msg, &tag)
        .expect("verify should not error after zero-length update");
    assert!(valid, "Zero-length update should not break HMAC");
}

#[session_test]
fn test_hmac_algo_reuse_after_failure(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let mut algo = HsmHmacAlgo::new();

    // Empty-tag verification is a normal verification miss, not an operational error.
    let valid = HsmVerifier::verify(&mut algo, &key_b, b"msg", &[]).unwrap();
    assert!(!valid, "Empty tag should produce a verification miss");

    // Reuse after verification miss.
    let tag = HsmSigner::sign_vec(&mut algo, &key_a, b"msg").unwrap();

    let valid = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, b"msg", &tag).unwrap();

    assert!(valid, "Algo should remain usable after failure");
}

#[session_test]
fn test_hmac_tag_length_matches_hash(session: HsmSession) {
    for key_kind in hmac_test_key_kinds() {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);

        let (key_a, _) = derive_ecdh_hmac_keypair(&session, curve, hkdf_hash, key_kind);

        let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, b"msg").unwrap();

        let expected_len = match key_kind {
            HsmKeyKind::HmacSha256 => 32,
            HsmKeyKind::HmacSha384 => 48,
            HsmKeyKind::HmacSha512 => 64,
            _ => unreachable!(),
        };

        assert_eq!(tag.len(), expected_len);
    }
}

/// Ensures a tag produced via streaming with one key does not verify with a different key.
#[session_test]
fn test_hmac_verify_fails_with_different_key_after_streaming_sign(session: HsmSession) {
    let (key_a, _) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let (_, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let mut ctx = HsmSigner::sign_init(HsmHmacAlgo::new(), key_a).unwrap();

    // try to "reuse" with different key by finishing and verifying
    HsmSignStreamingOpContext::update(&mut ctx, b"msg").unwrap();
    let tag = HsmSignStreamingOpContext::finish_vec(&mut ctx).unwrap();

    let result = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, b"msg", &tag);

    assert_eq!(result, Ok(false), "Context must be bound to original key");
}

#[session_test]
fn test_hmac_streaming_state_after_failed_update(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let mut ctx = HsmSigner::sign_init(HsmHmacAlgo::new(), key_a).unwrap();

    // trigger failure
    assert!(matches!(
        HsmSignStreamingOpContext::update(&mut ctx, &vec![0u8; 1025]),
        Err(HsmError::IndexOutOfRange)
    ));
    // continue using context
    HsmSignStreamingOpContext::update(&mut ctx, b"valid").unwrap();
    let tag = HsmSignStreamingOpContext::finish_vec(&mut ctx).unwrap();

    let result = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, b"valid", &tag);

    assert_eq!(
        result,
        Ok(true),
        "Context should remain usable after failed update",
    );
}

#[session_test]
fn test_hmac_verify_rejects_extra_data_after_valid_update(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = b"message";
    let tag = streaming_sign(key_a, msg, &[msg.len()]);

    let mut ctx = HsmVerifier::verify_init(HsmHmacAlgo::new(), key_b).unwrap();

    HsmVerifyStreamingOpContext::update(&mut ctx, msg).unwrap();

    // extra data that should invalidate verification
    HsmVerifyStreamingOpContext::update(&mut ctx, b"extra").unwrap();

    let result = HsmVerifyStreamingOpContext::finish(&mut ctx, &tag).unwrap();

    assert!(!result, "Extra data must invalidate HMAC verification");
}

#[session_test]
fn test_hmac_different_keys_produce_different_tags(session: HsmSession) {
    let (key_a1, _) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let (key_a2, _) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = b"same message";

    let tag1 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a1, msg).unwrap();
    let tag2 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a2, msg).unwrap();

    assert_ne!(
        tag1, tag2,
        "Different keys must produce different HMAC tags"
    );
}

#[session_test]
fn test_hmac_verify_idempotent(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = b"idempotent test";
    let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, msg).unwrap();

    let mut algo = HsmHmacAlgo::new();

    let r1 = HsmVerifier::verify(&mut algo, &key_b, msg, &tag).unwrap();
    let r2 = HsmVerifier::verify(&mut algo, &key_b, msg, &tag).unwrap();

    assert_eq!(r1, r2, "Verify should be idempotent");
}

#[session_test]
fn test_hmac_verify_fails_same_prefix_same_length(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg1 = b"prefix_message_aaaa";
    let msg2 = b"prefix_message_bbbb"; // same length, same prefix

    let tag = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key_a, msg1).unwrap();

    let result = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, msg2, &tag);

    assert!(
        !result.unwrap_or(false),
        "Same-length prefix mismatch must fail"
    );
}

#[session_test]
fn test_hmac_streaming_alternating_chunk_sizes(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let msg = test_message_bytes(0xAB, 1023);

    let tag = streaming_sign(key_a, &msg, &[1, 1022]); // extreme alternation

    let valid = streaming_verify(key_b, &msg, &[1022, 1], &tag);

    assert!(valid, "Alternating chunk sizes must not affect correctness");
}

#[session_test]
fn test_hmac_streaming_mid_boundary_corruption(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let mut msg = test_message_bytes(0x11, 512);

    let tag = streaming_sign(key_a, &msg, &[256, 256]);

    // corrupt boundary byte
    msg[256] ^= 0x01;

    let valid = streaming_verify(key_b, &msg, &[256, 256], &tag);

    assert!(!valid, "Mid-boundary corruption must fail");
}

#[session_test]
fn test_hmac_derived_key_determinism(session: HsmSession) {
    let curve = HsmEccCurve::P256;
    let key_kind = HsmKeyKind::HmacSha256;

    let (shared_a, _) = derive_ecdh_shared_secrets(&session, curve);

    let mut hkdf1 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();
    let mut hkdf2 = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let key1 = derive_hmac_key_from_shared_secret(&session, &mut hkdf1, &shared_a, key_kind);
    let key2 = derive_hmac_key_from_shared_secret(&session, &mut hkdf2, &shared_a, key_kind);

    let tag1 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key1, b"msg").unwrap();
    let tag2 = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key2, b"msg").unwrap();

    assert_eq!(tag1, tag2, "HKDF derivation must be deterministic");
}

/// Ensures single-shot HMAC signing returns BufferTooSmall for a short output buffer,
/// and succeeds when the output buffer is large enough.
#[session_test]
fn test_hmac_sign_buffer_too_small_then_success(session: HsmSession) {
    let (key_a, key_b) = derive_ecdh_hmac_keypair(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmKeyKind::HmacSha256,
    );

    let data = b"buffer too small test";

    let mut small_tag_buf = [0u8; 31];
    let result = HsmSigner::sign(
        &mut HsmHmacAlgo::new(),
        &key_a,
        data,
        Some(&mut small_tag_buf),
    );

    assert!(
        matches!(result, Err(HsmError::BufferTooSmall)),
        "Expected BufferTooSmall for 31-byte HMAC-SHA256 buffer, got {:?}",
        result
    );

    let mut tag_buf = [0u8; 32];
    let tag_len = HsmSigner::sign(&mut HsmHmacAlgo::new(), &key_a, data, Some(&mut tag_buf))
        .expect("HMAC signing should succeed with a 32-byte buffer");

    assert_eq!(tag_len, 32, "HMAC-SHA256 tag length should be 32 bytes");

    let is_valid = HsmVerifier::verify(&mut HsmHmacAlgo::new(), &key_b, data, &tag_buf[..tag_len])
        .expect("HMAC verify failed");

    assert!(
        is_valid,
        "Tag produced after BufferTooSmall path should verify"
    );
}
