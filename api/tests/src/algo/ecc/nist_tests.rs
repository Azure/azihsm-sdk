// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

use azihsm_api::*;
use azihsm_api_tests_macro::*;

// =======================================================
// API-level helpers
// =======================================================

/// Generates an API-level ECC key pair with sign/verify permissions.
fn generate_ecc_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmEccKeyGenAlgo::default();

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}

/// Hashes message data through the API-level hash path.
fn hsm_hash_vec(session: &HsmSession, mut hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash message")
}

/// Runs API-level generated key sign/verify against NIST vector messages.
fn run_api_ecdsa_sign_verify_msg(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
    vectors: &[EccNistTestVector],
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    for vector in vectors.iter() {
        let digest = hsm_hash_vec(session, hash_algo, vector.msg);

        let mut sign_algo = HsmEccSignAlgo::default();
        let signature =
            HsmSigner::sign_vec(&mut sign_algo, &priv_key, &digest).expect("Failed to sign digest");

        let mut verify_algo = HsmEccSignAlgo::default();
        let ok = HsmVerifier::verify(&mut verify_algo, &pub_key, &digest, &signature)
            .expect("Failed to verify signature");

        assert!(ok, "API-level ECDSA sign/verify failed for {:?}", curve);
    }
}

// =======================================================
// Crypto-level NIST helpers
// =======================================================

fn curve_bits(curve: CryptoEccCurve) -> u32 {
    match curve {
        CryptoEccCurve::P256 => 256,
        CryptoEccCurve::P384 => 384,
        CryptoEccCurve::P521 => 521,
    }
}

fn signature_len(curve: CryptoEccCurve) -> usize {
    match curve {
        CryptoEccCurve::P256 => 64,
        CryptoEccCurve::P384 => 96,
        CryptoEccCurve::P521 => 132,
    }
}

fn sig_der_to_raw(curve: CryptoEccCurve, der: &[u8]) -> Vec<u8> {
    fn read_len(input: &[u8], offset: &mut usize) -> usize {
        let first = input[*offset];
        *offset += 1;

        if first & 0x80 == 0 {
            first as usize
        } else {
            let num_bytes = (first & 0x7F) as usize;
            let mut len = 0usize;

            for _ in 0..num_bytes {
                len = (len << 8) | input[*offset] as usize;
                *offset += 1;
            }

            len
        }
    }

    fn parse_int(input: &[u8], offset: &mut usize) -> Vec<u8> {
        assert_eq!(input[*offset], 0x02, "Expected INTEGER");
        *offset += 1;

        let len = read_len(input, offset);
        assert!(*offset + len <= input.len(), "DER length out of bounds");

        let val = &input[*offset..*offset + len];
        *offset += len;

        if val.len() > 1 && val[0] == 0 {
            val[1..].to_vec()
        } else {
            val.to_vec()
        }
    }

    let mut offset = 0;

    assert_eq!(der[offset], 0x30, "Expected SEQUENCE");
    offset += 1;

    let _seq_len = read_len(der, &mut offset);

    let r = parse_int(der, &mut offset);
    let s = parse_int(der, &mut offset);

    let size = match curve {
        CryptoEccCurve::P256 => 32,
        CryptoEccCurve::P384 => 48,
        CryptoEccCurve::P521 => 66,
    };

    assert!(r.len() <= size, "r too large for curve");
    assert!(s.len() <= size, "s too large for curve");

    let mut r_pad = vec![0u8; size];
    let mut s_pad = vec![0u8; size];

    r_pad[size - r.len()..].copy_from_slice(&r);
    s_pad[size - s.len()..].copy_from_slice(&s);

    [r_pad, s_pad].concat()
}

/// Verifies NIST ECDSA signatures using precomputed digests and `CryptoEccAlgo`.
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

/// Verifies NIST ECDSA signatures using messages and `CryptoEcdsaAlgo`.
fn run_ecdsa_msg_nist_vectors(
    curve: CryptoEccCurve,
    vectors: &[EccNistTestVector],
    hash_algo: CryptoHashAlgo,
    expected_digest_len: usize,
) {
    let mut algo = CryptoEcdsaAlgo::new(hash_algo);

    for vector in vectors.iter() {
        assert_eq!(vector.curve_bits as u32, curve_bits(curve));

        assert_eq!(
            vector.digest.len(),
            expected_digest_len,
            "Digest length mismatch for {:?}",
            curve
        );

        let pub_key = CryptoEccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");

        let sig = sig_der_to_raw(curve, vector.sig_der);

        let is_valid = CryptoVerifier::verify(&mut algo, &pub_key, vector.msg, &sig)
            .expect("Failed to verify NIST message signature");

        assert!(is_valid, "ECDSA NIST message verify failed for {:?}", curve);
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
    for vector in vectors.iter() {
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
            "ECDH {label} derived secret mismatch"
        );
    }
}

// =======================================================
// ECDSA digest-level NIST tests.
// =======================================================

#[test]
fn ecc_p256_nist() {
    run_ecc_digest_nist_vectors(ECC_P256_TEST_VECTORS, CryptoEccCurve::P256, "ECC_P256");
}

#[test]
fn ecc_p384_nist() {
    run_ecc_digest_nist_vectors(ECC_P384_TEST_VECTORS, CryptoEccCurve::P384, "ECC_P384");
}

#[test]
fn ecc_p521_nist() {
    run_ecc_digest_nist_vectors(ECC_P521_TEST_VECTORS, CryptoEccCurve::P521, "ECC_P521");
}

// =======================================================
// ECDSA message-level NIST tests.
// =======================================================

#[test]
fn ecdsa_p256_nist_verify_msg() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P256,
        ECC_P256_TEST_VECTORS,
        CryptoHashAlgo::sha256(),
        32,
    );
}

#[test]
fn ecdsa_p384_nist_verify_msg() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P384,
        ECC_P384_TEST_VECTORS,
        CryptoHashAlgo::sha384(),
        48,
    );
}

#[test]
fn ecdsa_p521_nist_verify_msg() {
    run_ecdsa_msg_nist_vectors(
        CryptoEccCurve::P521,
        ECC_P521_TEST_VECTORS,
        CryptoHashAlgo::sha512(),
        64,
    );
}

// =======================================================
// API-level generated-key ECDSA sign/verify tests.
// =======================================================

#[session_test]
fn api_ecdsa_p256_sign_verify_msg(session: HsmSession) {
    run_api_ecdsa_sign_verify_msg(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        ECC_P256_TEST_VECTORS,
    );
}

#[session_test]
fn api_ecdsa_p384_sign_verify_msg(session: HsmSession) {
    run_api_ecdsa_sign_verify_msg(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        ECC_P384_TEST_VECTORS,
    );
}

#[session_test]
fn api_ecdsa_p521_sign_verify_msg(session: HsmSession) {
    run_api_ecdsa_sign_verify_msg(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        ECC_P521_TEST_VECTORS,
    );
}

// =======================================================
// ECDH NIST tests.
// =======================================================

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
