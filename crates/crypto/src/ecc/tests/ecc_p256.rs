// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_ecc_sign_verify_p256() {
    // Test code for ECC sign and verify on P-256 curve
    let msg = b"Another test message for ECC signing";

    // Get SHA-384 digest length
    let mut algo = HashAlgo::sha256();
    let result = Hasher::hash(&mut algo, msg, None);

    assert_eq!(result, Ok(32)); // Expects 32 bytes for SHA-256 digest
    let mut digest = [0u8; 32];
    // Get hash value
    assert_eq!(Hasher::hash(&mut algo, msg, Some(&mut digest)), Ok(32));

    // Generate ECC key pair
    let pri_key = EccPrivateKey::from_curve(EccCurve::P256).expect("Key generation failed");
    let pub_key = pri_key.public_key().expect("Failed to get public key");

    let mut algo = EccAlgo {};

    // get signature size
    let sig_size = Signer::sign(&mut algo, &pri_key, &digest, None).expect("Signing failed");
    let mut signature = vec![0u8; sig_size];
    // Sign the digest
    assert_eq!(
        Signer::sign(&mut algo, &pri_key, &digest, Some(&mut signature)),
        Ok(sig_size)
    );

    // Verify the signature
    let is_valid =
        Verifier::verify(&mut algo, &pub_key, &digest, &signature).expect("Verification failed");
    assert!(is_valid);
}

// Test NIST Vectors
#[test]
fn test_ecc_p256_sign_verify_nist_vectors() {
    let mut algo = EccAlgo {};
    for vector in ECC_P256_TEST_VECTORS.iter() {
        assert_eq!(
            vector.curve_bits, 256,
            "P-256 testvectors must have curve_bits=256"
        );

        let pri_key = EccPrivateKey::from_bytes(vector.private_key_der)
            .expect("Failed to parse private key DER");
        let pub_key = pri_key.public_key().expect("Failed to get public key");

        // Validate curve_bits via signature size for portability.
        let expected_sig_len = expected_sig_len_from_curve_bits(vector.curve_bits);
        let sig_size =
            Signer::sign(&mut algo, &pri_key, vector.digest, None).expect("Signing failed");
        assert_eq!(
            sig_size, expected_sig_len,
            "Signature size does not match vector curve_bits"
        );

        // Sign the digest
        let mut signature = vec![0u8; sig_size];
        assert_eq!(
            Signer::sign(&mut algo, &pri_key, vector.digest, Some(&mut signature)),
            Ok(sig_size)
        );

        // Verify the signature
        let is_valid = Verifier::verify(&mut algo, &pub_key, vector.digest, &signature)
            .expect("Verification failed");
        assert!(is_valid, "NIST P-256 vector verification failed");
    }
}

#[test]
fn test_ecc_p256_verify_nist_vector_signatures() {
    let mut algo = EccAlgo {};
    for vector in ECC_P256_TEST_VECTORS.iter() {
        let pub_key = EccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");
        let signature = sig_der_to_raw(EccCurve::P256, vector.sig_der);
        let is_valid = Verifier::verify(&mut algo, &pub_key, vector.digest, &signature)
            .expect("Verification failed");
        assert!(is_valid, "NIST P-256 vector signature verification failed");
    }
}

#[test]
fn test_ecc_p256_import_priv_sign_import_pub_verify() {
    let mut algo = EccAlgo {};
    for vector in ECC_P256_TEST_VECTORS.iter() {
        let pri_key = EccPrivateKey::from_bytes(vector.private_key_der)
            .expect("Failed to parse private key DER");
        let pub_key = EccPublicKey::from_bytes(vector.public_key_der)
            .expect("Failed to parse public key DER");

        let sig_size =
            Signer::sign(&mut algo, &pri_key, vector.digest, None).expect("Signing failed");
        let mut signature = vec![0u8; sig_size];
        assert_eq!(
            Signer::sign(&mut algo, &pri_key, vector.digest, Some(&mut signature)),
            Ok(sig_size)
        );

        let is_valid = Verifier::verify(&mut algo, &pub_key, vector.digest, &signature)
            .expect("Verification failed");
        assert!(is_valid, "NIST P-256 import/sign/import/verify failed");
    }
}
