// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

use crate::algo::ecc::*;

/// Helper function to derive an ECDH shared secret for testing.
fn derive_shared_secret_for_unmask_test(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> HsmGenericSecretKey {
    let (_priv_key_a, pub_key_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party A");

    let (priv_key_b, _pub_key_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party B");

    // Derive shared secret using party B's private key and party A's public key
    let pub_key_der = pub_key_a
        .pub_key_der_vec()
        .expect("Failed to get public key DER");

    let mut ecdh_algo = EcdhAlgo::new(&pub_key_der);

    let bits = curve.key_size_bits() as u32;
    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build derived key props");

    HsmKeyManager::derive_key(session, &mut ecdh_algo, &priv_key_b, derived_key_props)
        .expect("Failed to derive shared secret")
}

/// Compares key properties between original and unmasked keys.
fn compare_shared_secret_properties(
    original: &HsmGenericSecretKey,
    unmasked: &HsmGenericSecretKey,
) {
    assert_eq!(original.class(), unmasked.class());
    assert_eq!(original.kind(), unmasked.kind());
    assert_eq!(original.bits(), unmasked.bits());
    assert_eq!(original.can_derive(), unmasked.can_derive());
}

/// Test unmask of a shared secret key derived via ECDH.
///
/// This test:
/// 1. Derives a shared secret key using ECDH
/// 2. Gets the masked key blob
/// 3. Unmasks it using HsmGenericSecretKeyUnmaskAlgo
/// 4. Verifies the properties match
fn test_shared_secret_unmask_common(session: &HsmSession, curve: HsmEccCurve) {
    // Derive a shared secret key
    let original_key = derive_shared_secret_for_unmask_test(session, curve);

    // Get the masked key blob
    let masked_key = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    // Unmask the key
    let mut unmask_algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(session, &mut unmask_algo, &masked_key)
        .expect("Failed to unmask shared secret key");

    // Verify properties match
    compare_shared_secret_properties(&original_key, &unmasked_key);

    // Clean up
    HsmKeyManager::delete_key(unmasked_key).expect("Failed to delete unmasked key");
    HsmKeyManager::delete_key(original_key).expect("Failed to delete original key");
}

/// Test unmask of a P-256 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p256(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P256);
}

/// Test unmask of a P-384 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p384(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P384);
}

/// Test unmask of a P-521 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p521(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P521);
}
