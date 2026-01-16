// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

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
        .can_verify(!can_derive)
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
        .ok_or(HsmError::KeyPropertyNotPresent)?
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

/// Negative test: invalid peer public key DER should be rejected.
///
/// This is expected to fail before calling into the DDI layer.
#[session_test]
fn test_ecdh_invalid_peer_public_key_der_fails(session: HsmSession) {
    let (priv_key, pub_key) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let mut pub_key_der = pub_key
        .pub_key_der_vec()
        .expect("Failed to export public key DER");

    // Corrupt the DER in a deterministic way.
    pub_key_der.truncate(pub_key_der.len().saturating_sub(1));

    let result = ecdh_derive_shared_secret_from_der(&session, &priv_key, &pub_key_der);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
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

/// Negative test: `masked_key` should reject a buffer of the wrong size.
#[session_test]
fn test_ecdh_masked_key_buffer_size_mismatch_fails(session: HsmSession) {
    let (priv_key_a, pub_key_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true)
            .expect("Failed to generate key pair");

    let shared_secret = ecdh_derive_shared_secret(&session, &priv_key_a, &pub_key_b)
        .expect("Failed to derive shared secret");

    let len = shared_secret
        .masked_key(None)
        .expect("Failed to get masked key size");
    assert!(len > 0);

    let mut too_small = vec![0u8; len - 1];
    let result = shared_secret.masked_key(Some(&mut too_small));
    assert!(matches!(result, Err(HsmError::BufferTooSmall)));
}

#[session_test]
// Rejects derived secret props when class is not Secret.
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

#[session_test]
// Rejects derived secret props when kind is not SharedSecret.
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

#[session_test]
// Rejects derived secret props when an ECC curve is set.
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

#[session_test]
// Rejects derived secret props when unsupported usage flags are present.
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

#[session_test]
// Allows SESSION flag on derived shared secrets.
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
