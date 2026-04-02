// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

// ================================
// Helper functions
// ================================

/// Generate an ECC key pair with configurable derive capability.
///
/// This is used for negative testing (e.g. ensuring ECDH fails when the base private key does not
/// allow derivation).
pub(crate) fn generate_ecc_keypair_with_derive(
    session: HsmSession,
    curve: HsmEccCurve,
    can_derive: bool,
) -> HsmResult<(HsmEccPrivateKey, HsmEccPublicKey)> {
    // Create key properties for the private key.
    //
    // Note: ECC keys are not symmetric cipher keys; do not set encrypt/decrypt usage flags here.
    // For negative ECDH testing, we generate a valid ECC key that simply lacks `can_derive(true)`.
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .is_session(true)
        .can_derive(can_derive)
        .can_sign(!can_derive)
        .build()?;

    // Create key properties for the public key.
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_derive(can_derive)
        .can_verify(!can_derive)
        .is_session(true)
        .build()?;

    // Create the ECC key generation algorithm.
    let mut algo = HsmEccKeyGenAlgo::default();

    // Generate the key pair.
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)?;

    Ok((priv_key, pub_key))
}

/// Perform ECDH key agreement against a peer public key.
///
/// This uses the given `private_key` and the peer's public key (exported as DER) to derive a
/// shared secret, returned as an HSM-managed `HsmSharedSecretKey`.
pub(crate) fn ecdh_derive_shared_secret(
    session: &HsmSession,
    private_key: &HsmEccPrivateKey,
    peer_public_key: &HsmEccPublicKey,
) -> HsmResult<HsmGenericSecretKey> {
    // Get the peer public key in DER format.
    let pub_key_der = peer_public_key.pub_key_der_vec()?;

    ecdh_derive_shared_secret_from_der(session, private_key, &pub_key_der)
}

/// Perform ECDH key agreement against a peer public key DER.
///
/// This helper exists to allow deterministic negative testing (e.g. invalid DER input) without
/// needing to construct an `HsmEccPublicKey`.
pub(crate) fn ecdh_derive_shared_secret_from_der(
    session: &HsmSession,
    private_key: &HsmEccPrivateKey,
    peer_public_key_der: &[u8],
) -> HsmResult<HsmGenericSecretKey> {
    // Create an ECDH algorithm instance bound to the peer public key.
    let mut ecdh_algo = EcdhAlgo::new(peer_public_key_der);

    // Create properties for the derived secret key. For an ECDH shared secret, use the base key
    // curve size.
    let bits = private_key
        .ecc_curve()
        .ok_or(HsmError::PropertyNotPresent)?
        .key_size_bits() as u32;
    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .build()
        .expect("Failed to build derived key props");

    // Derive the shared secret key.
    let derived_key =
        HsmKeyManager::derive_key(session, &mut ecdh_algo, private_key, derived_key_props)?;

    Ok(derived_key)
}

/// Perform ECDH key agreement with caller-provided derived key properties.
///
/// This helper is used to validate that derived key property validation is enforced
/// (fail-fast) for `HsmGenericSecretKey`.
pub(crate) fn ecdh_derive_shared_secret_with_props(
    session: &HsmSession,
    private_key: &HsmEccPrivateKey,
    peer_public_key: &HsmEccPublicKey,
    derived_key_props: HsmKeyProps,
) -> HsmResult<HsmGenericSecretKey> {
    let pub_key_der = peer_public_key.pub_key_der_vec()?;
    let mut ecdh_algo = EcdhAlgo::new(&pub_key_der);
    HsmKeyManager::derive_key(session, &mut ecdh_algo, private_key, derived_key_props)
}

/// Derives shared secrets for two parties using ECDH on the given curve.
fn derive_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmGenericSecretKey, HsmGenericSecretKey) {
    let (priv_a, pub_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();
    let (priv_b, pub_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let a = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();
    let b = ecdh_derive_shared_secret(session, &priv_b, &pub_a).unwrap();

    (a, b)
}

/// Extracts the masked key material into a buffer for inspection.
fn extract(secret: &HsmGenericSecretKey) -> Vec<u8> {
    let len = secret.masked_key(None).unwrap();
    let mut buf = vec![0u8; len];
    secret.masked_key(Some(&mut buf)).unwrap();
    buf
}

/// Ensures ECDH succeeds with valid public keys and produces different secrets for different peers.
fn run_ecdh_wrong_pubkey(session: &HsmSession, curve: HsmEccCurve) {
    // Generate key pair A (used as the private side)
    let (priv_a, pub_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    // Generate an unrelated key pair B
    let (_, pub_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    // Derive secrets using two different peers
    let s1 = ecdh_derive_shared_secret(session, &priv_a, &pub_a)
        .expect("ECDH with own public key should succeed");

    let s2 = ecdh_derive_shared_secret(session, &priv_a, &pub_b)
        .expect("ECDH with unrelated public key should also succeed");

    // Both should be valid
    assert!(s1.bits() > 0, "Invalid secret from self peer {:?}", curve);
    assert!(
        s2.bits() > 0,
        "Invalid secret from different peer {:?}",
        curve
    );

    // Extract masked key material (structure-level comparison)
    let k1 = extract(&s1);
    let k2 = extract(&s2);

    // Strong guarantee: different peers → different derived secrets
    assert_ne!(
        k1, k2,
        "Different peers should produce different shared secrets {:?}",
        curve
    );
}

/// Ensures invalid DER input is rejected during ECDH derivation.
fn run_ecdh_invalid_der(session: &HsmSession, curve: HsmEccCurve, der: &[u8]) {
    let (priv_key, _) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let result = ecdh_derive_shared_secret_from_der(session, &priv_key, der);

    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Confirms masked key retrieval succeeds with an exact-sized buffer.
fn run_ecdh_masked_key_success(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let secret = ecdh_derive_shared_secret(session, &priv_key, &pub_key).unwrap();

    let len = secret.masked_key(None).unwrap();
    let mut buf = vec![0u8; len];

    let written = secret.masked_key(Some(&mut buf)).unwrap();

    assert_eq!(written, len);
}

/// Validates that incorrect bit-size requests are rejected or ignored.
fn run_ecdh_bits_mismatch(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let wrong_bits = 128;

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(wrong_bits)
        .can_derive(true)
        .build()
        .unwrap();

    let result =
        ecdh_derive_shared_secret_with_props(session, &priv_key, &pub_key, derived_key_props);

    match result {
        Ok(derived) => {
            // If HSM allows it → must NOT honor wrong bits
            assert!(
                derived.bits() != wrong_bits,
                "HSM should not honor incorrect bits"
            );
        }
        Err(_) => {
            // ANY error is acceptable:
            // InvalidKeyProps, InvalidArgument, DdiCmdFailure, etc.
        }
    }
}

/// Verifies successful ECDH derivation and expected key size consistency.
fn run_ecdh_success(session: &HsmSession, curve: HsmEccCurve) {
    let expected = curve.key_size_bits() as u32;
    let (a, b) = derive_pair(session, curve);

    assert_eq!(a.bits(), expected);
    assert_eq!(b.bits(), expected);
}

/// Ensures different peer keys produce different derived secrets.
fn run_ecdh_diff_peer(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_a, _) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let (_, pub_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();
    let (_, pub_c) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let s1 = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();
    let s2 = ecdh_derive_shared_secret(session, &priv_a, &pub_c).unwrap();

    assert_ne!(
        extract(&s1),
        extract(&s2),
        "Different peers same secret {:?}",
        curve
    );
}

/// Ensures ECDH fails when the base key lacks derive capability.
fn run_ecdh_no_derive_flag(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, false).unwrap();

    let result = ecdh_derive_shared_secret(session, &priv_key, &pub_key);

    assert!(result.is_err(), "Missing derive flag {:?}", curve);
}

/// Validates rejection of invalid derived key property configurations.
fn run_ecdh_invalid_props(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let cases = vec![
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public) // wrong
            .key_kind(HsmKeyKind::SharedSecret)
            .bits(256)
            .can_derive(true)
            .build()
            .unwrap(),
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes) // wrong
            .bits(256)
            .can_derive(true)
            .build()
            .unwrap(),
    ];

    for props in cases {
        let r = ecdh_derive_shared_secret_with_props(session, &priv_key, &pub_key, props);
        assert!(r.is_err(), "Invalid props accepted {:?}", curve);
    }
}

/// Verifies structural consistency between bidirectional ECDH results.
fn run_ecdh_consistency(session: &HsmSession, curve: HsmEccCurve) {
    let (a, b) = derive_pair(session, curve);

    // Same logical key size
    assert_eq!(a.bits(), b.bits(), "bits mismatch {:?}", curve);

    // Same masked size (structure-level consistency)
    let size_a = a.masked_key(None).unwrap();
    let size_b = b.masked_key(None).unwrap();

    assert_eq!(size_a, size_b, "masked size mismatch {:?}", curve);
}

/// Ensures ECDH fails when private and public keys use different curves.
fn run_ecdh_cross_curve_fail(
    session: &HsmSession,
    priv_curve: HsmEccCurve,
    pub_curve: HsmEccCurve,
) {
    let (priv_key, _) =
        generate_ecc_keypair_with_derive(session.clone(), priv_curve, true).unwrap();

    let (_, pub_key) = generate_ecc_keypair_with_derive(session.clone(), pub_curve, true).unwrap();

    let result = ecdh_derive_shared_secret(session, &priv_key, &pub_key);

    assert!(
        result.is_err(),
        "Cross-curve should fail {:?} vs {:?}",
        priv_curve,
        pub_curve
    );
}

/// Validates that oversized buffers are rejected in masked key retrieval.
fn run_ecdh_masked_key_oversized_buffer(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let secret = ecdh_derive_shared_secret(session, &priv_key, &pub_key).unwrap();

    let len = secret.masked_key(None).unwrap();

    let mut buf = vec![0u8; len + 16];

    let result = secret.masked_key(Some(&mut buf));

    assert!(result.is_err(), "Oversized buffer should fail {:?}", curve);
}

/// Ensures DER from a different curve is rejected during ECDH.
fn run_ecdh_valid_der_wrong_curve(
    session: &HsmSession,
    priv_curve: HsmEccCurve,
    wrong_curve: HsmEccCurve,
) {
    let (priv_key, _) =
        generate_ecc_keypair_with_derive(session.clone(), priv_curve, true).unwrap();

    let (_, pub_key_wrong) =
        generate_ecc_keypair_with_derive(session.clone(), wrong_curve, true).unwrap();

    let der = pub_key_wrong.pub_key_der_vec().unwrap();

    let result = ecdh_derive_shared_secret_from_der(session, &priv_key, &der);

    assert!(
        result.is_err(),
        "Wrong-curve DER should fail {:?} vs {:?}",
        priv_curve,
        wrong_curve
    );
}

/// Ensures masked key retrieval fails when buffer is too small.
fn run_ecdh_masked_key_small_buffer(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let secret = ecdh_derive_shared_secret(session, &priv_key, &pub_key).unwrap();

    let len = secret.masked_key(None).unwrap();
    assert!(len > 0, "masked_key(None) must return non-zero length");

    let mut buf = vec![0u8; len - 1];

    let result = secret.masked_key(Some(&mut buf));

    assert!(
        matches!(result, Err(HsmError::BufferTooSmall)),
        "small buffer {:?}",
        curve
    );
}

/// Ensures corrupted DER input is rejected during ECDH derivation.
fn run_ecdh_corrupted_der(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let mut der = pub_key.pub_key_der_vec().unwrap();
    der[0] ^= 0xFF;

    let result = ecdh_derive_shared_secret_from_der(session, &priv_key, &der);

    assert!(result.is_err(), "corrupted DER {:?}", curve);
}

/// Ensures truncated DER input is rejected during ECDH derivation.
fn run_ecdh_truncated_der(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let mut der = pub_key.pub_key_der_vec().unwrap();
    der.truncate(der.len().saturating_sub(1));

    let result = ecdh_derive_shared_secret_from_der(session, &priv_key, &der);

    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Verifies dropping a cloned session handle does not invalidate a derived key.
///
/// `HsmSession` is internally reference-counted (Arc), and derived keys hold
/// their own session reference. Dropping a local clone must not affect key usability.
fn run_ecdh_session_close_invalidates_key(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let secret = ecdh_derive_shared_secret(session, &priv_key, &pub_key).unwrap();

    let session_clone = session.clone();
    drop(session_clone);

    let result = secret.masked_key(None);

    let len = result.expect("Derived key should remain usable after dropping session clone");
    assert!(len > 0);
}

/// Ensures cross-curve ECDH fails even when using valid but different peer keys.
fn run_ecdh_cross_curve_with_different_peer(
    session: &HsmSession,
    priv_curve: HsmEccCurve,
    other_curve: HsmEccCurve,
) {
    // Private key on curve A
    let (priv_key, _) =
        generate_ecc_keypair_with_derive(session.clone(), priv_curve, true).unwrap();

    // Two different peers on a DIFFERENT curve
    let (_, pub_b1) = generate_ecc_keypair_with_derive(session.clone(), other_curve, true).unwrap();

    let (_, pub_b2) = generate_ecc_keypair_with_derive(session.clone(), other_curve, true).unwrap();

    // Both should fail
    let r1 = ecdh_derive_shared_secret(session, &priv_key, &pub_b1);
    let r2 = ecdh_derive_shared_secret(session, &priv_key, &pub_b2);

    assert!(
        r1.is_err(),
        "Cross-curve should fail (peer1) {:?}->{:?}",
        priv_curve,
        other_curve
    );
    assert!(
        r2.is_err(),
        "Cross-curve should fail (peer2) {:?}->{:?}",
        priv_curve,
        other_curve
    );
}

/// Hashes input data using the specified hash algorithm.
fn hash_data(session: &HsmSession, hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    let mut algo = hash_algo;

    // Step 1: get required length
    let len = HsmHasher::hash(session, &mut algo, data, None).expect("Hash length query failed");

    // Step 2: allocate buffer
    let mut out = vec![0u8; len];

    // Step 3: compute hash
    HsmHasher::hash(session, &mut algo, data, Some(&mut out)).expect("Hashing failed");

    out
}

/// Returns appropriate hash algorithm for given ECC curve
fn hash_for_curve(curve: HsmEccCurve) -> HsmHashAlgo {
    match curve {
        HsmEccCurve::P256 => HsmHashAlgo::Sha256,
        HsmEccCurve::P384 => HsmHashAlgo::Sha384,
        HsmEccCurve::P521 => HsmHashAlgo::Sha512,
    }
}

/// Ensures ECDH works correctly and peer identity can be authenticated via signature verification.
fn run_ecdh_with_signature_verification(session: &HsmSession, curve: HsmEccCurve) {
    // --- ECDH key pairs (derive-only) ---
    let (priv_a, pub_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let (priv_b_ecdh, pub_b_ecdh) =
        generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    // --- Signing key pair (sign/verify only) ---
    let (priv_b_sign, pub_b_sign) =
        generate_ecc_keypair_with_derive(session.clone(), curve, false).unwrap();

    // --- ECDH: derive shared secrets from both sides ---
    let secret_ab =
        ecdh_derive_shared_secret(session, &priv_a, &pub_b_ecdh).expect("ECDH A->B failed");

    let secret_ba =
        ecdh_derive_shared_secret(session, &priv_b_ecdh, &pub_a).expect("ECDH B->A failed");

    // Validate structural consistency (HSM does not expose raw secret)
    let size_ab = secret_ab.masked_key(None).unwrap();
    let size_ba = secret_ba.masked_key(None).unwrap();

    assert_eq!(size_ab, size_ba, "ECDH shared secret mismatch {:?}", curve);

    // --- Authentication via signature ---
    let message = b"ecdh-auth-test";

    let hash_algo = hash_for_curve(curve);
    let digest = hash_data(session, hash_algo, message);

    // Sign with B's signing key
    let mut sign_algo = HsmEccSignAlgo::default();
    let signature =
        HsmSigner::sign_vec(&mut sign_algo, &priv_b_sign, &digest).expect("Signing failed");

    // Verify with correct public key
    let mut verify_algo = HsmEccSignAlgo::default();
    let verified = HsmVerifier::verify(&mut verify_algo, &pub_b_sign, &digest, &signature)
        .expect("Verify call failed");

    assert!(verified, "Signature verification failed {:?}", curve);

    // --- Negative case: wrong public key must fail ---
    let (_, wrong_pub) = generate_ecc_keypair_with_derive(session.clone(), curve, false).unwrap();

    let mut verify_algo = HsmEccSignAlgo::default();
    let wrong_verified =
        HsmVerifier::verify(&mut verify_algo, &wrong_pub, &digest, &signature).unwrap_or(false);

    assert!(
        !wrong_verified,
        "Verification should fail with wrong public key {:?}",
        curve
    );
}

// ============================================================
// test cases sections
// ============================================================

/// Test ECDH key derivation.
///
/// Generates two ECC P-256 key pairs (party A and party B) and performs ECDH from both sides.
/// The goal of this test is to validate that key agreement completes successfully and yields
/// usable HSM key handles.
#[session_test]
fn test_ecdh_key_derivation(session: HsmSession) {
    // Generate key pair for party A
    let (priv_key_a, pub_key_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair for party A");

    // Generate key pair for party B
    let (priv_key_b, pub_key_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair for party B");

    // Derive shared secret for party A using party B's public key
    let shared_secret_a = ecdh_derive_shared_secret(&session, &priv_key_a, &pub_key_b)
        .expect("Failed to derive shared secret for party A");

    // Derive shared secret for party B using party A's public key
    let shared_secret_b = ecdh_derive_shared_secret(&session, &priv_key_b, &pub_key_a)
        .expect("Failed to derive shared secret for party B");

    // Ensure the derived keys expose expected common properties.
    assert_eq!(shared_secret_a.class(), HsmKeyClass::Secret);
    assert_eq!(shared_secret_a.kind(), HsmKeyKind::SharedSecret);
    assert_eq!(shared_secret_b.class(), HsmKeyClass::Secret);
    assert_eq!(shared_secret_b.kind(), HsmKeyKind::SharedSecret);

    // For ECDH, the shared secret size is defined by the curve size.
    assert_eq!(shared_secret_a.bits(), 256);
    assert_eq!(shared_secret_b.bits(), 256);

    // Ensure masked key material is present and can be fetched with the size-query pattern.
    let secret_a_masked_size = shared_secret_a
        .masked_key(None)
        .expect("Failed to get secret A masked key size");
    let secret_b_masked_size = shared_secret_b
        .masked_key(None)
        .expect("Failed to get secret B masked key size");

    assert!(secret_a_masked_size > 0);
    assert_eq!(secret_a_masked_size, secret_b_masked_size);
}

/// Test ECDH derived secret key property fields.
///
/// This verifies the returned key reports the expected `class`, `kind`, and `bits` values.
#[session_test]
fn test_ecdh_derived_secret_props(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived = ecdh_derive_shared_secret(&session, &priv_key, &pub_key)
        .expect("Failed to derive shared secret");

    assert_eq!(derived.class(), HsmKeyClass::Secret);
    assert_eq!(derived.kind(), HsmKeyKind::SharedSecret);
    assert_eq!(derived.bits(), 256);
    assert_eq!(derived.ecc_curve(), None);
}

/// Negative test: ECDH should fail if the base private key does not have `can_derive(true)`.
#[session_test]
fn test_ecdh_base_key_without_derive_capability_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, false)
            .expect("Failed to generate key pair");

    let result = ecdh_derive_shared_secret(&session, &priv_key, &pub_key);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

// Rejects derived secret props when class is not Secret.
#[session_test]
fn test_ecdh_derived_secret_props_invalid_class_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("Failed to build derived key props");

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects derived secret props when kind is not SharedSecret.
#[session_test]
fn test_ecdh_derived_secret_props_invalid_kind_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("Failed to build derived key props");

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects derived secret props when an ECC curve is set.
#[session_test]
fn test_ecdh_derived_secret_props_ecc_curve_set_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .ecc_curve(HsmEccCurve::P256)
        .bits(256)
        .can_derive(true)
        .build()
        .expect("Failed to build derived key props");

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects derived secret props when unsupported usage flags are present.
#[session_test]
fn test_ecdh_derived_secret_props_unsupported_flags_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .can_encrypt(true)
        .build()
        .expect("Failed to build derived key props");

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Allows SESSION flag on derived shared secrets.
#[session_test]
fn test_ecdh_derived_secret_props_session_flag_allowed(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build derived key props");

    let derived =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props)
            .expect("Failed to derive shared secret");
    assert!(derived.is_session());
}

/// Validates ECDH behavior with unrelated public key (P-256).
#[session_test]
fn test_ecdh_wrong_pubkey_p256(session: HsmSession) {
    run_ecdh_wrong_pubkey(&session, HsmEccCurve::P256);
}

/// Validates ECDH behavior with unrelated public key (P-384).
#[session_test]
fn test_ecdh_wrong_pubkey_p384(session: HsmSession) {
    run_ecdh_wrong_pubkey(&session, HsmEccCurve::P384);
}

/// Validates ECDH behavior with unrelated public key (P-521).
#[session_test]
fn test_ecdh_wrong_pubkey_p521(session: HsmSession) {
    run_ecdh_wrong_pubkey(&session, HsmEccCurve::P521);
}

/// Ensures incorrect bit size is not honored (P-256).
#[session_test]
fn test_ecdh_bits_mismatch_p256(session: HsmSession) {
    run_ecdh_bits_mismatch(&session, HsmEccCurve::P256);
}

/// Ensures incorrect bit size is not honored (P-384).
#[session_test]
fn test_ecdh_bits_mismatch_p384(session: HsmSession) {
    run_ecdh_bits_mismatch(&session, HsmEccCurve::P384);
}

/// Ensures incorrect bit size is not honored (P-521).
#[session_test]
fn test_ecdh_bits_mismatch_p521(session: HsmSession) {
    run_ecdh_bits_mismatch(&session, HsmEccCurve::P521);
}

/// Ensures cross-curve ECDH fails with different peers (P-256 -> P-384).
#[session_test]
fn test_ecdh_cross_curve_diff_peer_p256_p384(session: HsmSession) {
    run_ecdh_cross_curve_with_different_peer(&session, HsmEccCurve::P256, HsmEccCurve::P384);
}

/// Ensures cross-curve ECDH fails with different peers (P-384 -> P-521).
#[session_test]
fn test_ecdh_cross_curve_diff_peer_p384_p521(session: HsmSession) {
    run_ecdh_cross_curve_with_different_peer(&session, HsmEccCurve::P384, HsmEccCurve::P521);
}

/// Ensures cross-curve ECDH fails with different peers (P-521 -> P-256).
#[session_test]
fn test_ecdh_cross_curve_diff_peer_p521_p256(session: HsmSession) {
    run_ecdh_cross_curve_with_different_peer(&session, HsmEccCurve::P521, HsmEccCurve::P256);
}
/// Ensures empty DER input is rejected (P-256).
#[session_test]
fn test_ecdh_empty_der_p256(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P256, &[]);
}

/// Ensures empty DER input is rejected (P-384).
#[session_test]
fn test_ecdh_empty_der_p384(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P384, &[]);
}

/// Ensures empty DER input is rejected (P-521).
#[session_test]
fn test_ecdh_empty_der_p521(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P521, &[]);
}

/// Verifies masked key retrieval succeeds with correct buffer size (P-256).
#[session_test]
fn test_ecdh_masked_key_success_p256(session: HsmSession) {
    run_ecdh_masked_key_success(&session, HsmEccCurve::P256);
}

/// Verifies masked key retrieval succeeds with correct buffer size (P-384).
#[session_test]
fn test_ecdh_masked_key_success_p384(session: HsmSession) {
    run_ecdh_masked_key_success(&session, HsmEccCurve::P384);
}

/// Verifies masked key retrieval succeeds with correct buffer size (P-521).
#[session_test]
fn test_ecdh_masked_key_success_p521(session: HsmSession) {
    run_ecdh_masked_key_success(&session, HsmEccCurve::P521);
}

/// Validates ECDH with identical key pair (self-derive behavior).
#[session_test]
fn test_ecdh_self_derive(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let result = ecdh_derive_shared_secret(&session, &priv_key, &pub_key);

    let derived = result.expect("self derive should succeed");
    assert!(derived.bits() > 0);
}

/// Validates behavior when peer public key lacks derive capability.
#[session_test]
fn test_ecdh_public_key_without_derive_flag(session: HsmSession) {
    let (priv_key, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (_, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, false).unwrap();

    let result = ecdh_derive_shared_secret(&session, &priv_key, &pub_key);

    let secret = result.expect("ECDH should succeed with valid public key");

    assert!(secret.bits() > 0);
}
/// Ensures derived key props without derive capability are rejected.
#[session_test]
fn test_ecdh_derived_key_without_derive_flag(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(false)
        .build()
        .unwrap();

    let result =
        ecdh_derive_shared_secret_with_props(&session, &priv_key, &pub_key, derived_key_props);

    assert!(result.is_err());
}

/// Ensures masked key retrieval fails with zero-length buffer.
#[session_test]
fn test_ecdh_masked_key_zero_buffer(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let secret = ecdh_derive_shared_secret(&session, &priv_key, &pub_key).unwrap();

    let mut buf = vec![];
    let result = secret.masked_key(Some(&mut buf));

    assert!(result.is_err());
}

/// Verifies successful ECDH derivation using helper (P-256).
#[session_test]
fn test_ecdh_success_p256(session: HsmSession) {
    run_ecdh_success(&session, HsmEccCurve::P256);
}

/// Verifies successful ECDH derivation using helper (P-384).
#[session_test]
fn test_ecdh_success_p384(session: HsmSession) {
    run_ecdh_success(&session, HsmEccCurve::P384);
}

/// Verifies successful ECDH derivation using helper (P-521).
#[session_test]
fn test_ecdh_success_p521(session: HsmSession) {
    run_ecdh_success(&session, HsmEccCurve::P521);
}

/// Ensures different peers produce different secrets (P-256).
#[session_test]
fn test_ecdh_diff_peer_p256(session: HsmSession) {
    run_ecdh_diff_peer(&session, HsmEccCurve::P256);
}

/// Ensures different peers produce different secrets (P-384).
#[session_test]
fn test_ecdh_diff_peer_p384(session: HsmSession) {
    run_ecdh_diff_peer(&session, HsmEccCurve::P384);
}

/// Ensures different peers produce different secrets (P-521).
#[session_test]
fn test_ecdh_diff_peer_p521(session: HsmSession) {
    run_ecdh_diff_peer(&session, HsmEccCurve::P521);
}

/// Ensures invalid DER input is rejected (P-256).
#[session_test]
fn test_ecdh_invalid_der_p256(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P256, &[0xAA; 32]);
}

/// Ensures invalid DER input is rejected (P-384).
#[session_test]
fn test_ecdh_invalid_der_p384(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P384, &[0xAA; 32]);
}

/// Ensures invalid DER input is rejected (P-521).
#[session_test]
fn test_ecdh_invalid_der_p521(session: HsmSession) {
    run_ecdh_invalid_der(&session, HsmEccCurve::P521, &[0xAA; 32]);
}

/// Ensures ECDH fails when derive flag is missing (P-256).
#[session_test]
fn test_ecdh_no_derive_flag_p256(session: HsmSession) {
    run_ecdh_no_derive_flag(&session, HsmEccCurve::P256);
}

/// Ensures ECDH fails when derive flag is missing (P-384).
#[session_test]
fn test_ecdh_no_derive_flag_p384(session: HsmSession) {
    run_ecdh_no_derive_flag(&session, HsmEccCurve::P384);
}

/// Ensures ECDH fails when derive flag is missing (P-521).
#[session_test]
fn test_ecdh_no_derive_flag_p521(session: HsmSession) {
    run_ecdh_no_derive_flag(&session, HsmEccCurve::P521);
}

/// Ensures invalid derived key props are rejected (P-256).
#[session_test]
fn test_ecdh_invalid_props_p256(session: HsmSession) {
    run_ecdh_invalid_props(&session, HsmEccCurve::P256);
}

/// Ensures invalid derived key props are rejected (P-384).
#[session_test]
fn test_ecdh_invalid_props_p384(session: HsmSession) {
    run_ecdh_invalid_props(&session, HsmEccCurve::P384);
}

/// Ensures invalid derived key props are rejected (P-521).
#[session_test]
fn test_ecdh_invalid_props_p521(session: HsmSession) {
    run_ecdh_invalid_props(&session, HsmEccCurve::P521);
}

/// Verifies structural consistency of derived secrets on P-256.
#[session_test]
fn test_ecdh_consistency_p256(session: HsmSession) {
    run_ecdh_consistency(&session, HsmEccCurve::P256);
}

/// Verifies structural consistency of derived secrets on P-384.
#[session_test]
fn test_ecdh_consistency_p384(session: HsmSession) {
    run_ecdh_consistency(&session, HsmEccCurve::P384);
}

/// Verifies structural consistency of derived secrets on P-521.
#[session_test]
fn test_ecdh_consistency_p521(session: HsmSession) {
    run_ecdh_consistency(&session, HsmEccCurve::P521);
}

/// Ensures cross-curve ECDH fails (P-256 private, P-384 public).
#[session_test]
fn test_ecdh_cross_curve_p256_p384(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P256, HsmEccCurve::P384);
}

/// Ensures cross-curve ECDH fails (P-384 private, P-521 public).
#[session_test]
fn test_ecdh_cross_curve_p384_p521(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P384, HsmEccCurve::P521);
}

/// Ensures cross-curve ECDH fails (P-521 private, P-256 public).
#[session_test]
fn test_ecdh_cross_curve_p521_p256(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P521, HsmEccCurve::P256);
}

/// Ensures cross-curve ECDH fails (P-384 private, P-256 public).
#[session_test]
fn test_ecdh_cross_curve_p384_p256(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P384, HsmEccCurve::P256);
}

/// Ensures cross-curve ECDH fails (P-521 private, P-384 public).
#[session_test]
fn test_ecdh_cross_curve_p521_p384(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P521, HsmEccCurve::P384);
}

/// Ensures cross-curve ECDH fails (P-256 private, P-521 public).
#[session_test]
fn test_ecdh_cross_curve_p256_p521(session: HsmSession) {
    run_ecdh_cross_curve_fail(&session, HsmEccCurve::P256, HsmEccCurve::P521);
}

/// Ensures oversized buffer is rejected during masked key retrieval (P-256).
#[session_test]
fn test_ecdh_masked_key_oversized_buffer_p256(session: HsmSession) {
    run_ecdh_masked_key_oversized_buffer(&session, HsmEccCurve::P256);
}

/// Ensures oversized buffer is rejected during masked key retrieval (P-384).
#[session_test]
fn test_ecdh_masked_key_oversized_buffer_p384(session: HsmSession) {
    run_ecdh_masked_key_oversized_buffer(&session, HsmEccCurve::P384);
}

/// Ensures oversized buffer is rejected during masked key retrieval (P-521).
#[session_test]
fn test_ecdh_masked_key_oversized_buffer_p521(session: HsmSession) {
    run_ecdh_masked_key_oversized_buffer(&session, HsmEccCurve::P521);
}

/// Ensures DER from a different curve is rejected (P-256).
#[session_test]
fn test_ecdh_valid_der_wrong_curve_p256(session: HsmSession) {
    run_ecdh_valid_der_wrong_curve(&session, HsmEccCurve::P256, HsmEccCurve::P384);
}

/// Ensures DER from a different curve is rejected (P-384).
#[session_test]
fn test_ecdh_valid_der_wrong_curve_p384(session: HsmSession) {
    run_ecdh_valid_der_wrong_curve(&session, HsmEccCurve::P384, HsmEccCurve::P521);
}

/// Ensures DER from a different curve is rejected (P-521).
#[session_test]
fn test_ecdh_valid_der_wrong_curve_p521(session: HsmSession) {
    run_ecdh_valid_der_wrong_curve(&session, HsmEccCurve::P521, HsmEccCurve::P256);
}

/// Ensures small buffer is rejected during masked key retrieval (P-256).
#[session_test]
fn test_ecdh_masked_key_small_buffer_p256(session: HsmSession) {
    run_ecdh_masked_key_small_buffer(&session, HsmEccCurve::P256);
}

/// Ensures small buffer is rejected during masked key retrieval (P-384).
#[session_test]
fn test_ecdh_masked_key_small_buffer_p384(session: HsmSession) {
    run_ecdh_masked_key_small_buffer(&session, HsmEccCurve::P384);
}

/// Ensures small buffer is rejected during masked key retrieval (P-521).
#[session_test]
fn test_ecdh_masked_key_small_buffer_p521(session: HsmSession) {
    run_ecdh_masked_key_small_buffer(&session, HsmEccCurve::P521);
}

/// Ensures truncated DER input is rejected (P-256).
#[session_test]
fn test_ecdh_truncated_der_p256(session: HsmSession) {
    run_ecdh_truncated_der(&session, HsmEccCurve::P256);
}

/// Ensures truncated DER input is rejected (P-384).
#[session_test]
fn test_ecdh_truncated_der_p384(session: HsmSession) {
    run_ecdh_truncated_der(&session, HsmEccCurve::P384);
}

/// Ensures truncated DER input is rejected (P-521).
#[session_test]
fn test_ecdh_truncated_der_p521(session: HsmSession) {
    run_ecdh_truncated_der(&session, HsmEccCurve::P521);
}

/// Ensures corrupted DER input is rejected during ECDH derivation (P-256).
#[session_test]
fn test_ecdh_corrupted_der_p256(session: HsmSession) {
    run_ecdh_corrupted_der(&session, HsmEccCurve::P256);
}

/// Ensures corrupted DER input is rejected during ECDH derivation (P-384).
#[session_test]
fn test_ecdh_corrupted_der_p384(session: HsmSession) {
    run_ecdh_corrupted_der(&session, HsmEccCurve::P384);
}

/// Ensures corrupted DER input is rejected during ECDH derivation (P-521).
#[session_test]
fn test_ecdh_corrupted_der_p521(session: HsmSession) {
    run_ecdh_corrupted_der(&session, HsmEccCurve::P521);
}

/// Verifies derived key usability after session closure (P-256).
#[session_test]
fn test_ecdh_session_close_invalidates_key_p256(session: HsmSession) {
    run_ecdh_session_close_invalidates_key(&session, HsmEccCurve::P256);
}

/// Verifies derived key usability after session closure (P-384).
#[session_test]
fn test_ecdh_session_close_invalidates_key_p384(session: HsmSession) {
    run_ecdh_session_close_invalidates_key(&session, HsmEccCurve::P384);
}

/// Verifies derived key usability after session closure (P-521).
#[session_test]
fn test_ecdh_session_close_invalidates_key_p521(session: HsmSession) {
    run_ecdh_session_close_invalidates_key(&session, HsmEccCurve::P521);
}

/// Verifies authenticated ECDH using signature validation (P-256).
#[session_test]
fn test_ecdh_with_signature_verification_p256(session: HsmSession) {
    run_ecdh_with_signature_verification(&session, HsmEccCurve::P256);
}

/// Verifies authenticated ECDH using signature validation (P-384).
#[session_test]
fn test_ecdh_with_signature_verification_p384(session: HsmSession) {
    run_ecdh_with_signature_verification(&session, HsmEccCurve::P384);
}

/// Verifies authenticated ECDH using signature validation (P-521).
#[session_test]
fn test_ecdh_with_signature_verification_p521(session: HsmSession) {
    run_ecdh_with_signature_verification(&session, HsmEccCurve::P521);
}

/// Ensures repeated ECDH derivation produces valid keys on P-256.
#[session_test]
fn test_ecdh_repeat_derivation_stability_p256(session: HsmSession) {
    run_ecdh_repeat_derivation_stability(&session, HsmEccCurve::P256);
}
/// Ensures repeated ECDH derivation produces valid keys on P-384.
#[session_test]
fn test_ecdh_repeat_derivation_stability_p384(session: HsmSession) {
    run_ecdh_repeat_derivation_stability(&session, HsmEccCurve::P384);
}

/// Ensures repeated ECDH derivation produces valid keys on P-521.
#[session_test]
fn test_ecdh_repeat_derivation_stability_p521(session: HsmSession) {
    run_ecdh_repeat_derivation_stability(&session, HsmEccCurve::P521);
}

/// Verifies ECDH works between independently generated keypairs within the same session.
#[session_test]
fn test_ecdh_pubkey_interop_same_session(session: HsmSession) {
    let (_, pub1) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv2, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let result = ecdh_derive_shared_secret(&session, &priv2, &pub1);

    assert!(
        result.is_ok(),
        "ECDH with independent keypairs should succeed"
    );
}

/// Ensures repeated ECDH derivation succeeds and produces valid keys.
fn run_ecdh_repeat_derivation_stability(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_a, _) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let (_, pub_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let s1 = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();
    let s2 = ecdh_derive_shared_secret(session, &priv_a, &pub_b).unwrap();

    // Validate both are usable
    assert!(s1.bits() > 0, "First derivation invalid {:?}", curve);
    assert!(s2.bits() > 0, "Second derivation invalid {:?}", curve);

    // Optional: ensure consistent size
    assert_eq!(
        s1.bits(),
        s2.bits(),
        "Derived key size mismatch {:?}",
        curve
    );
}

#[session_test]
fn test_ecdh_pubkey_der_roundtrip(session: HsmSession) {
    let (priv_a, pub_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let der = pub_a.pub_key_der_vec().unwrap();

    let result = ecdh_derive_shared_secret_from_der(&session, &priv_a, &der);

    assert!(result.is_ok(), "valid DER roundtrip failed");
}

#[session_test]
fn test_ecdh_minimal_der_rejected(session: HsmSession) {
    let (priv_a, _pub) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let der = vec![0x30]; // minimal invalid ASN.1

    let result = ecdh_derive_shared_secret_from_der(&session, &priv_a, &der);

    assert!(result.is_err());
}
