// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto::DerEccSignature;
use azihsm_crypto::DeriveOp;
use azihsm_crypto::EccAlgo as CryptoEccAlgo;
use azihsm_crypto::EccCurve as CryptoEccCurve;
use azihsm_crypto::EccPrivateKey as CryptoEccPrivateKey;
use azihsm_crypto::EccPublicKey as CryptoEccPublicKey;
use azihsm_crypto::EcdhAlgo as CryptoEcdhAlgo;
use azihsm_crypto::EcdsaAlgo as CryptoEcdsaAlgo;
use azihsm_crypto::ExportableKey as CryptoExportableKey;
use azihsm_crypto::HashAlgo as CryptoHashAlgo;
use azihsm_crypto::ImportableKey as CryptoImportableKey;
use azihsm_crypto::Verifier as CryptoVerifier;
use azihsm_crypto::testvectors::ecc::ECC_P256_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::ECC_P384_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::ECC_P521_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::ECDH_P256_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::ECDH_P384_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::ECDH_P521_TEST_VECTORS;
use azihsm_crypto::testvectors::ecc::EccNistTestVector;

use super::*;

// =======================================================
// API-level common helpers
// =======================================================

/// Hashes input data using the API-level HSM hash operation.
fn api_hash_data(session: &HsmSession, mut hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

/// Signs a precomputed digest using an HSM ECC private key.
fn api_sign_hash(priv_key: &HsmEccPrivateKey, hash: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmEccSignAlgo::default();

    HsmSigner::sign_vec(&mut sign_algo, priv_key, hash)
        .expect("API ECDSA signature generation failed")
}

/// Verifies an ECDSA signature against a precomputed digest using an HSM ECC public key.
fn api_verify_hash_signature(
    pub_key: &HsmEccPublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, HsmError> {
    let mut verify_algo = HsmEccSignAlgo::default();

    HsmVerifier::verify(&mut verify_algo, pub_key, hash, signature)
}

/// Returns the expected digest length for the given HSM ECC curve.
fn api_expected_digest_len(curve: HsmEccCurve) -> usize {
    match curve {
        HsmEccCurve::P256 => 32,
        HsmEccCurve::P384 => 48,
        HsmEccCurve::P521 => 64,
    }
}

// =======================================================
// API-level RSA-AES unwrap helpers for ECC key-pair import
// =======================================================

/// Generates an RSA key pair for RSA-AES wrapping and unwrapping tests.
fn generate_rsa_keypair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build RSA private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build RSA public key props");

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
        .expect("RSA key generation failed")
}

/// Wraps ECC private-key DER bytes using the RSA-AES wrapping algorithm.
fn wrap_ecc_key_pair_rsa(rsa_pub: &HsmRsaPublicKey, ecc_private_key_der: &[u8]) -> Vec<u8> {
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);

    let size = wrap_algo
        .encrypt(rsa_pub, ecc_private_key_der, None)
        .expect("ECC key-pair wrap size query failed");

    let mut wrapped_key_pair = vec![0u8; size];

    wrap_algo
        .encrypt(rsa_pub, ecc_private_key_der, Some(&mut wrapped_key_pair))
        .expect("ECC key-pair wrap failed");

    wrapped_key_pair
}

/// Unwraps RSA-AES-wrapped ECC private-key DER into HSM ECC private/public key handles.
fn unwrap_ecc_key_pair_from_der(
    rsa_priv: &HsmRsaPrivateKey,
    rsa_pub: &HsmRsaPublicKey,
    ecc_private_key_der: &[u8],
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let wrapped_key_pair = wrap_ecc_key_pair_rsa(rsa_pub, ecc_private_key_der);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build ECC public key props");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        rsa_priv,
        &wrapped_key_pair,
        priv_props,
        pub_props,
    )
    .expect("Failed to unwrap ECC key pair")
}

// =======================================================
// API-level generated-key ECDSA helpers
// =======================================================

/// Runs API-level generated-key sign/verify using NIST vector messages.
/// It uses the NIST message input, but signs with a freshly generated HSM key pair.
fn run_api_ecdsa_sign_verify_nist_messages(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
    vectors: &[EccNistTestVector],
    label: &str,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    for (i, vector) in vectors.iter().enumerate() {
        let digest = api_hash_data(session, hash_algo, vector.msg);

        assert_eq!(
            digest.len(),
            api_expected_digest_len(curve),
            "[{label}] API digest length mismatch at vector {i}"
        );

        let signature = api_sign_hash(&priv_key, &digest);

        assert_eq!(
            signature.len(),
            curve.signature_size(),
            "[{label}] API signature length mismatch at vector {i}"
        );

        let result = api_verify_hash_signature(&pub_key, &digest, &signature);

        assert!(
            matches!(result, Ok(true)),
            "[{label}] API ECDSA sign/verify failed for NIST message vector {i}: {:?}",
            result
        );
    }
}

/// Verifies that API ECDSA verification fails when the digest is modified.
fn run_api_ecdsa_modified_digest_fails(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
    vectors: &[EccNistTestVector],
    label: &str,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    for (i, vector) in vectors.iter().enumerate() {
        let digest = api_hash_data(session, hash_algo, vector.msg);
        let signature = api_sign_hash(&priv_key, &digest);

        let mut modified_digest = digest.clone();
        modified_digest[0] ^= 0x01;

        let result = api_verify_hash_signature(&pub_key, &modified_digest, &signature);

        assert!(
            matches!(
                result,
                Ok(false) | Err(HsmError::DdiCmdFailure) | Err(HsmError::InternalError)
            ),
            "[{label}] API ECDSA verification should fail for modified digest at vector {i}, got {:?}",
            result
        );
    }
}

fn run_api_ecdsa_tampered_signature_fails(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
    vectors: &[EccNistTestVector],
    label: &str,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    for (i, vector) in vectors.iter().enumerate() {
        let digest = api_hash_data(session, hash_algo, vector.msg);
        let mut signature = api_sign_hash(&priv_key, &digest);

        signature[0] ^= 0xFF;

        let result = api_verify_hash_signature(&pub_key, &digest, &signature);

        assert!(
            matches!(
                result,
                Ok(false) | Err(HsmError::DdiCmdFailure) | Err(HsmError::InternalError)
            ),
            "[{label}] API ECDSA verification should fail for tampered signature at vector {i}, got {:?}",
            result
        );
    }
}

// =======================================================
// API-level unwrapped-key ECDSA helpers
// =======================================================

/// Imports ECC private-key DER through RSA-AES unwrap, then signs/verifies with HSM ECC key handles.
fn run_api_ecc_unwrap_key_pair_sign_verify<T>(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
    vectors: &[T],
    get_private_key_der: fn(&T) -> &[u8],
    label: &str,
) {
    let (rsa_priv, rsa_pub) = generate_rsa_keypair(session);

    for (i, vector) in vectors.iter().enumerate() {
        let private_key_der = get_private_key_der(vector);

        let (ecc_priv, ecc_pub) =
            unwrap_ecc_key_pair_from_der(&rsa_priv, &rsa_pub, private_key_der, curve);

        let msg = b"API ECC unwrap sign/verify using NIST ECC key material";
        let digest = api_hash_data(session, hash_algo, msg);

        assert_eq!(
            digest.len(),
            api_expected_digest_len(curve),
            "[{label}] API digest length mismatch at vector {i}"
        );

        let signature = api_sign_hash(&ecc_priv, &digest);

        assert_eq!(
            signature.len(),
            curve.signature_size(),
            "[{label}] API signature length mismatch at vector {i}"
        );

        let result = api_verify_hash_signature(&ecc_pub, &digest, &signature);

        assert!(
            matches!(result, Ok(true)),
            "[{label}] API ECC unwrap + sign/verify failed at vector {i}: {:?}",
            result
        );

        HsmKeyManager::delete_key(ecc_priv).expect("Failed to delete ECC private key");
        HsmKeyManager::delete_key(ecc_pub).expect("Failed to delete ECC public key");
    }
}

// =======================================================
// Crypto-level NIST helpers
// =======================================================

/// Returns the NIST ECC curve size in bits.
fn curve_bits(curve: CryptoEccCurve) -> u32 {
    match curve {
        CryptoEccCurve::P256 => 256,
        CryptoEccCurve::P384 => 384,
        CryptoEccCurve::P521 => 521,
    }
}

/// Returns the raw ECDSA signature length for the given curve.
fn signature_len(curve: CryptoEccCurve) -> usize {
    match curve {
        CryptoEccCurve::P256 => 64,
        CryptoEccCurve::P384 => 96,
        CryptoEccCurve::P521 => 132,
    }
}

/// Converts a DER-encoded ECDSA signature into raw r||s format.
fn sig_der_to_raw(curve: CryptoEccCurve, sig_der: &[u8]) -> Vec<u8> {
    let sig =
        DerEccSignature::from_der(curve, sig_der).expect("Failed to parse DER ECDSA signature");

    let point_size = curve.point_size();
    let mut raw = vec![0u8; point_size * 2];

    raw[..point_size].copy_from_slice(sig.r());
    raw[point_size..].copy_from_slice(sig.s());

    raw
}

/// Verifies NIST ECDSA signatures using precomputed digests and CryptoEccAlgo.
fn run_ecc_digest_nist_vectors(vectors: &[EccNistTestVector], curve: CryptoEccCurve, label: &str) {
    let mut algo = CryptoEccAlgo {};

    for (i, vector) in vectors.iter().enumerate() {
        assert_eq!(
            vector.curve_bits as u32,
            curve_bits(curve),
            "[{label}] curve_bits mismatch at vector {i}"
        );

        let pub_key = CryptoEccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");

        let sig = sig_der_to_raw(curve, vector.sig_der);

        assert_eq!(
            sig.len(),
            signature_len(curve),
            "[{label}] signature size mismatch at vector {i}"
        );

        let is_valid = CryptoVerifier::verify(&mut algo, &pub_key, vector.digest, &sig)
            .expect("Failed to verify NIST digest signature");

        assert!(
            is_valid,
            "[{label}] NIST digest signature failed at vector {i}"
        );
    }
}

/// Verifies NIST ECDSA signatures using messages and CryptoEcdsaAlgo.
fn run_ecdsa_msg_nist_vectors(
    curve: CryptoEccCurve,
    vectors: &[EccNistTestVector],
    hash_algo: CryptoHashAlgo,
    expected_digest_len: usize,
    label: &str,
) {
    let mut algo = CryptoEcdsaAlgo::new(hash_algo);

    for (i, vector) in vectors.iter().enumerate() {
        assert_eq!(
            vector.curve_bits as u32,
            curve_bits(curve),
            "[{label}] curve_bits mismatch at vector {i}"
        );

        assert_eq!(
            vector.digest.len(),
            expected_digest_len,
            "[{label}] digest length mismatch at vector {i}"
        );

        let pub_key = CryptoEccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");

        let sig = sig_der_to_raw(curve, vector.sig_der);

        assert_eq!(
            sig.len(),
            signature_len(curve),
            "[{label}] signature size mismatch at vector {i}"
        );

        let is_valid = CryptoVerifier::verify(&mut algo, &pub_key, vector.msg, &sig)
            .expect("Failed to verify NIST message signature");

        assert!(
            is_valid,
            "[{label}] NIST message signature failed at vector {i}"
        );
    }
}

/// Verifies ECDH NIST shared secret vectors using crypto-level ECDH.
fn run_ecdh_nist<T>(
    vectors: &[T],
    out_len: usize,
    get_peer_pub: fn(&T) -> &[u8],
    get_priv: fn(&T) -> &[u8],
    get_expected: fn(&T) -> &[u8],
    label: &str,
) {
    for (i, vector) in vectors.iter().enumerate() {
        let peer_pub = CryptoEccPublicKey::from_bytes(get_peer_pub(vector))
            .expect("Failed to parse ECDH peer public key DER");

        let priv_key = CryptoEccPrivateKey::from_bytes(get_priv(vector))
            .expect("Failed to parse ECDH private key DER");

        let secret = CryptoEcdhAlgo::new(&peer_pub)
            .derive(&priv_key, out_len)
            .expect("ECDH derive failed");

        let mut secret_bytes = vec![0u8; out_len];

        secret
            .to_bytes(Some(&mut secret_bytes))
            .expect("Failed to export ECDH secret");

        assert_eq!(
            secret_bytes,
            get_expected(vector),
            "ECDH {label} derived secret mismatch at vector {i}"
        );
    }
}

// =======================================================
// True ECDSA digest-level NIST verification tests.
// Crypto layer: NIST public key + NIST signature + NIST digest.
// =======================================================

/// Verifies P-256 NIST ECDSA signatures using precomputed digests.
#[test]
fn ecc_p256_nist_digest_verify() {
    run_ecc_digest_nist_vectors(ECC_P256_TEST_VECTORS, CryptoEccCurve::P256, "ECC_P256");
}

/// Verifies P-384 NIST ECDSA signatures using precomputed digests.
#[test]
fn ecc_p384_nist_digest_verify() {
    run_ecc_digest_nist_vectors(ECC_P384_TEST_VECTORS, CryptoEccCurve::P384, "ECC_P384");
}

/// Verifies P-521 NIST ECDSA signatures using precomputed digests.
#[test]
fn ecc_p521_nist_digest_verify() {
    run_ecc_digest_nist_vectors(ECC_P521_TEST_VECTORS, CryptoEccCurve::P521, "ECC_P521");
}

// =======================================================
// True ECDSA message-level NIST verification tests.
// Crypto layer: NIST public key + NIST signature + NIST message.
// =======================================================

/// Verifies P-256 NIST ECDSA signatures using full messages.
#[test]
fn ecdsa_p256_nist_message_verify() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P256,
        ECC_P256_TEST_VECTORS,
        CryptoHashAlgo::sha256(),
        32,
        "ECDSA_P256",
    );
}

/// Verifies P-384 NIST ECDSA signatures using full messages.
#[test]
fn ecdsa_p384_nist_message_verify() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P384,
        ECC_P384_TEST_VECTORS,
        CryptoHashAlgo::sha384(),
        48,
        "ECDSA_P384",
    );
}

/// Verifies P-521 NIST ECDSA signatures using full messages.
#[test]
fn ecdsa_p521_nist_message_verify() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P521,
        ECC_P521_TEST_VECTORS,
        CryptoHashAlgo::sha512(),
        64,
        "ECDSA_P521",
    );
}

// =======================================================
// API-level generated-key ECDSA sign/verify tests.
// API layer: HSM-generated key + NIST message + HsmSigner/HsmVerifier.
// =======================================================

/// Verifies API-level P-256 ECDSA sign/verify using NIST vector messages.
#[session_test]
fn api_ecdsa_p256_sign_verify_nist_messages(session: HsmSession) {
    run_api_ecdsa_sign_verify_nist_messages(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        ECC_P256_TEST_VECTORS,
        "API_ECDSA_P256",
    );
}

/// Verifies API-level P-384 ECDSA sign/verify using NIST vector messages.
#[session_test]
fn api_ecdsa_p384_sign_verify_nist_messages(session: HsmSession) {
    run_api_ecdsa_sign_verify_nist_messages(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        ECC_P384_TEST_VECTORS,
        "API_ECDSA_P384",
    );
}

/// Verifies API-level P-521 ECDSA sign/verify using NIST vector messages.
#[session_test]
fn api_ecdsa_p521_sign_verify_nist_messages(session: HsmSession) {
    run_api_ecdsa_sign_verify_nist_messages(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        ECC_P521_TEST_VECTORS,
        "API_ECDSA_P521",
    );
}

// =======================================================
// API-level generated-key negative checks using NIST messages.
// =======================================================

/// Verifies API-level P-256 ECDSA verification fails for a modified digest.
#[session_test]
fn api_ecdsa_p256_modified_digest_fails(session: HsmSession) {
    run_api_ecdsa_modified_digest_fails(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        ECC_P256_TEST_VECTORS,
        "API_ECDSA_P256",
    );
}

/// Verifies API-level P-384 ECDSA verification fails for a modified digest.
#[session_test]
fn api_ecdsa_p384_modified_digest_fails(session: HsmSession) {
    run_api_ecdsa_modified_digest_fails(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        ECC_P384_TEST_VECTORS,
        "API_ECDSA_P384",
    );
}

/// Verifies API-level P-521 ECDSA verification fails for a modified digest.
#[session_test]
fn api_ecdsa_p521_modified_digest_fails(session: HsmSession) {
    run_api_ecdsa_modified_digest_fails(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        ECC_P521_TEST_VECTORS,
        "API_ECDSA_P521",
    );
}

/// Verifies API-level P-256 ECDSA verification fails for a tampered signature.
#[session_test]
fn api_ecdsa_p256_tampered_signature_fails(session: HsmSession) {
    run_api_ecdsa_tampered_signature_fails(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        ECC_P256_TEST_VECTORS,
        "API_ECDSA_P256",
    );
}

/// Verifies API-level P-384 ECDSA verification fails for a tampered signature.
#[session_test]
fn api_ecdsa_p384_tampered_signature_fails(session: HsmSession) {
    run_api_ecdsa_tampered_signature_fails(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        ECC_P384_TEST_VECTORS,
        "API_ECDSA_P384",
    );
}

/// Verifies API-level P-521 ECDSA verification fails for a tampered signature.
#[session_test]
fn api_ecdsa_p521_tampered_signature_fails(session: HsmSession) {
    run_api_ecdsa_tampered_signature_fails(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        ECC_P521_TEST_VECTORS,
        "API_ECDSA_P521",
    );
}

// =======================================================
// API-level ECC key-pair unwrap + sign/verify tests.
// API layer: NIST ECC private-key DER -> RSA-AES wrap -> ECC unwrap.
// =======================================================

/// Verifies P-256 ECC key-pair unwrap using ECDH NIST private-key material.
#[session_test]
fn api_ecc_p256_unwrap_ecdh_nist_key_sign_verify(session: HsmSession) {
    run_api_ecc_unwrap_key_pair_sign_verify(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        ECDH_P256_TEST_VECTORS,
        |v| v.diut_privkey_der,
        "API_ECC_P256_UNWRAP_ECDH_KEY",
    );
}

/// Verifies P-384 ECC key-pair unwrap using ECDH NIST private-key material.
#[session_test]
fn api_ecc_p384_unwrap_ecdh_nist_key_sign_verify(session: HsmSession) {
    run_api_ecc_unwrap_key_pair_sign_verify(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        ECDH_P384_TEST_VECTORS,
        |v| v.diut_privkey_der,
        "API_ECC_P384_UNWRAP_ECDH_KEY",
    );
}

/// Verifies P-521 ECC key-pair unwrap using ECDH NIST private-key material.
#[session_test]
fn api_ecc_p521_unwrap_ecdh_nist_key_sign_verify(session: HsmSession) {
    run_api_ecc_unwrap_key_pair_sign_verify(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        ECDH_P521_TEST_VECTORS,
        |v| v.diut_privkey_der,
        "API_ECC_P521_UNWRAP_ECDH_KEY",
    );
}

// =======================================================
// ECDH NIST tests.
// Crypto layer: NIST private key + peer public key + expected shared secret.
// =======================================================

/// Verifies P-256 ECDH NIST shared-secret derivation.
#[test]
fn ecc_ecdh_p256_nist() {
    run_ecdh_nist(
        ECDH_P256_TEST_VECTORS,
        32,
        |v| v.qcavs_pubkey_der,
        |v| v.diut_privkey_der,
        |v| v.ziut,
        "P256",
    );
}

/// Verifies P-384 ECDH NIST shared-secret derivation.
#[test]
fn ecc_ecdh_p384_nist() {
    run_ecdh_nist(
        ECDH_P384_TEST_VECTORS,
        48,
        |v| v.qcavs_pubkey_der,
        |v| v.diut_privkey_der,
        |v| v.ziut,
        "P384",
    );
}

/// Verifies P-521 ECDH NIST shared-secret derivation.
#[test]
fn ecc_ecdh_p521_nist() {
    run_ecdh_nist(
        ECDH_P521_TEST_VECTORS,
        66,
        |v| v.qcavs_pubkey_der,
        |v| v.diut_privkey_der,
        |v| v.ziut,
        "P521",
    );
}
