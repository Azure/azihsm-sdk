// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//implement ECDSA P-256 signature test using sha256
use super::*;

#[test]
fn test_ecdsa_p256_sign_verify() {
    let priv_key = EccPrivateKey::from_curve(EccCurve::P256).expect("Failed to create private key");
    let pub_key = priv_key.public_key().expect("Failed to derive public key");

    let hash_algo = HashAlgo::sha256();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);

    let msg = b"test message";
    let sig_len =
        Signer::sign(&mut ecdsa_algo, &priv_key, msg, None).expect("Failed to sign message");
    let mut signature = vec![0u8; sig_len];
    Signer::sign(&mut ecdsa_algo, &priv_key, msg, Some(&mut signature))
        .expect("Failed to sign message");

    let is_valid = Verifier::verify(&mut ecdsa_algo, &pub_key, msg, &signature)
        .expect("Failed to verify signature");
    assert!(is_valid, "Signature verification failed");
}

fn assert_sha256_matches_digest(msg: &[u8], expected_digest: &[u8]) {
    assert_eq!(
        expected_digest.len(),
        32,
        "P-256 vectors are expected to use SHA-256 digests"
    );

    let mut hash_algo = HashAlgo::sha256();
    let len = Hasher::hash(&mut hash_algo, msg, None).expect("Failed to query digest length");
    assert_eq!(len, 32, "SHA-256 digest length mismatch");

    let mut actual = [0u8; 32];
    Hasher::hash(&mut hash_algo, msg, Some(&mut actual)).expect("Failed to hash message");
    assert_eq!(actual.as_slice(), expected_digest, "hash(msg) mismatch");
}

#[test]
fn test_ecdsa_p256_nist_vector_verify_signature() {
    let hash_algo = HashAlgo::sha256();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);

    for vector in ECC_P256_TEST_VECTORS.iter() {
        assert_eq!(
            vector.curve_bits, 256,
            "P-256 testvectors must have curve_bits=256"
        );
        assert_sha256_matches_digest(vector.msg, vector.digest);

        let pub_key = EccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");
        let sig_raw = sig_der_to_raw(EccCurve::P256, vector.sig_der);

        let is_valid = Verifier::verify(&mut ecdsa_algo, &pub_key, vector.msg, &sig_raw)
            .expect("ECDSA verify failed");
        assert!(
            is_valid,
            "NIST P-256 ECDSA vector signature verification failed"
        );
    }
}

#[test]
fn test_ecdsa_p256_nist_vector_sign_verify_msg() {
    let hash_algo = HashAlgo::sha256();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);

    for vector in ECC_P256_TEST_VECTORS.iter() {
        let pri_key = EccPrivateKey::from_bytes(vector.private_key_der)
            .expect("Failed to parse private key DER");
        let pub_key = pri_key.public_key().expect("Failed to derive public key");

        let expected_sig_len = expected_sig_len_from_curve_bits(vector.curve_bits);
        let sig_len =
            Signer::sign(&mut ecdsa_algo, &pri_key, vector.msg, None).expect("Signing failed");
        assert_eq!(sig_len, expected_sig_len, "Unexpected signature length");

        let mut signature = vec![0u8; sig_len];
        Signer::sign(&mut ecdsa_algo, &pri_key, vector.msg, Some(&mut signature))
            .expect("Signing failed");

        let ok = Verifier::verify(&mut ecdsa_algo, &pub_key, vector.msg, &signature)
            .expect("Verification failed");
        assert!(ok, "P-256 ECDSA sign/verify failed on msg");
    }
}

#[test]
fn test_ecdsa_p256_import_priv_sign_import_pub_verify_msg() {
    let hash_algo = HashAlgo::sha256();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);

    for vector in ECC_P256_TEST_VECTORS.iter() {
        let pri_key = EccPrivateKey::from_bytes(vector.private_key_der)
            .expect("Failed to parse private key DER");
        let pub_key = EccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");

        let sig_len =
            Signer::sign(&mut ecdsa_algo, &pri_key, vector.msg, None).expect("Signing failed");
        let mut signature = vec![0u8; sig_len];
        Signer::sign(&mut ecdsa_algo, &pri_key, vector.msg, Some(&mut signature))
            .expect("Signing failed");

        let ok = Verifier::verify(&mut ecdsa_algo, &pub_key, vector.msg, &signature)
            .expect("Verification failed");
        assert!(ok, "P-256 ECDSA import/sign/import/verify failed");
    }
}
