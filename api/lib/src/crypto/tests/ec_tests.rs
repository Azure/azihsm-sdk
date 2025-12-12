// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(test)]
mod tests {
    use crate::crypto::ec::EcdsaAlgo;
    use crate::crypto::ec::EcdsaKeyPair;
    use crate::crypto::SignOp;
    use crate::crypto::StreamingSignOp;
    use crate::crypto::StreamingVerifyOp;
    use crate::session::test_helpers::create_test_session;
    use crate::types::AlgoId;
    use crate::types::EcCurve;
    use crate::types::KeyProps;
    use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
    use crate::AZIHSM_KEY_ALREADY_EXISTS;
    use crate::AZIHSM_KEY_NOT_INITIALIZED;
    use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;
    use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

    #[test]
    fn test_ecdsa_key_gen_p256() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve properties
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Verify initial state
        assert!(
            keypair.priv_key_id().is_none(),
            "Private key ID should be None before generation"
        );
        assert!(
            keypair.pub_key().is_none(),
            "Public key should be None before generation"
        );

        // Generate the key pair using session
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-256 key pair");

        // Verify key pair was generated successfully
        assert!(
            keypair.priv_key_id().is_some(),
            "PRivate key id should be set after generation"
        );
        assert!(
            keypair.pub_key().is_some(),
            "Public key should be set after generation"
        );

        // Verify public key is not empty
        let pub_key = keypair.pub_key().unwrap();
        assert!(!pub_key.is_empty(), "Public key should not be empty");

        // Delete the key pair
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete ECDSA key pair");

        // Check key ID and public key are cleared
        assert!(
            keypair.priv_key_id().is_none(),
            "Private key id should be None after deletion"
        );
        assert!(
            keypair.pub_key().is_none(),
            "Public key should be None after deletion"
        );

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_p384() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-384 curve properties
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-384 key pair");

        // Verify key pair was generated successfully
        assert!(
            keypair.priv_key_id().is_some(),
            "PRivate key id should be set after generation"
        );
        assert!(
            keypair.pub_key().is_some(),
            "Public key should be set after generation"
        );

        // Verify public key is not empty
        let pub_key = keypair.pub_key().unwrap();
        assert!(!pub_key.is_empty(), "Public key should not be empty");

        // Delete the key pair
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete ECDSA key pair");

        // Check key ID and public key are cleared
        assert!(
            keypair.priv_key_id().is_none(),
            "Private key id should be None after deletion"
        );
        assert!(
            keypair.pub_key().is_none(),
            "Public key should be None after deletion"
        );

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_p521() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-521 curve properties
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .sign(true)
            .verify(true)
            .build();

        let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut ecdsa_key)
            .expect("Failed to generate ECDSA P-521 key pair");

        // Verify key pair was generated successfully
        assert!(
            ecdsa_key.priv_key_id().is_some(),
            "Private key id should be set after generation"
        );
        assert!(
            ecdsa_key.pub_key().is_some(),
            "Public key should be set after generation"
        );

        // Verify public key is not empty
        let pub_key = ecdsa_key.pub_key().unwrap();
        assert!(!pub_key.is_empty(), "Public key should not be empty");

        // Delete the key pair
        session
            .delete_key(&mut ecdsa_key)
            .expect("Failed to delete ECDSA key pair");

        // Check key ID and public key are cleared
        assert!(
            ecdsa_key.priv_key_id().is_none(),
            "Private key id should be None after deletion"
        );
        assert!(
            ecdsa_key.pub_key().is_none(),
            "Public key should be None after deletion"
        );

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_already_exists() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve properties
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair first time - should succeed
        session
            .generate_key_pair(&mut ecdsa_key)
            .expect("Failed to generate ECDSA key pair first time");

        // Try to generate again - should fail
        let result = session.generate_key_pair(&mut ecdsa_key);
        assert!(result.is_err(), "Second key pair generation should fail");
        assert_eq!(result.unwrap_err(), AZIHSM_KEY_ALREADY_EXISTS);

        // Delete the key pair
        session
            .delete_key(&mut ecdsa_key)
            .expect("Failed to delete ECDSA key pair");

        // Check key ID and public key are cleared
        assert!(
            ecdsa_key.priv_key_id().is_none(),
            "Private key id should be None after deletion"
        );
        assert!(
            ecdsa_key.pub_key().is_none(),
            "Public key should be None after deletion"
        );

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_single_key_not_supported() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve properties
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .build();

        let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Try to generate single key - should fail for ECDSA
        let result = session.generate_key(&mut ecdsa_key);
        assert!(
            result.is_err(),
            "Single key generation should not be supported for ECDSA"
        );
        assert_eq!(result.unwrap_err(), AZIHSM_OPERATION_NOT_SUPPORTED);

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_missing_curve() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key without specifying curve
        let key_props = KeyProps::builder().sign(true).verify(true).build();

        let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Try to generate key pair - should fail without curve
        let result = session.generate_key_pair(&mut ecdsa_key);
        assert!(
            result.is_err(),
            "Key pair generation should fail without curve specification"
        );
        assert_eq!(result.unwrap_err(), AZIHSM_KEY_PROPERTY_NOT_PRESENT);

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_gen_with_different_properties() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        // Test different property combinations
        let test_cases = vec![
            // Sign only
            KeyProps::builder()
                .ecc_curve(EcCurve::P256)
                .sign(true)
                .build(),
            // Verify only
            KeyProps::builder()
                .ecc_curve(EcCurve::P256)
                .verify(true)
                .build(),
            // Both sign and verify
            KeyProps::builder()
                .ecc_curve(EcCurve::P256)
                .sign(true)
                .verify(true)
                .build(),
            // With session key
            KeyProps::builder()
                .ecc_curve(EcCurve::P256)
                .sign(true)
                .verify(true)
                .session(true)
                .build(),
            // With label
            KeyProps::builder()
                .ecc_curve(EcCurve::P256)
                .sign(true)
                .verify(true)
                .label("Test ECDSA Key".to_string())
                .build(),
        ];

        for (i, key_props) in test_cases.into_iter().enumerate() {
            let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

            // Generate the key pair
            session
                .generate_key_pair(&mut ecdsa_key)
                .unwrap_or_else(|_| {
                    panic!("Failed to generate ECDSA key pair for test case {}", i)
                });

            // Verify key pair was generated successfully
            assert!(
                ecdsa_key.priv_key_id().is_some(),
                "Private key ID should be set for test case {}",
                i
            );
            assert!(
                ecdsa_key.pub_key().is_some(),
                "Public key should be set for test case {}",
                i
            );

            // Delete the key pair
            session
                .delete_key(&mut ecdsa_key)
                .unwrap_or_else(|_| panic!("Failed to delete ECDSA key pair for test case {}", i));
        }

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_key_clone() {
        // Test that EcdsaKey can be cloned properly
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);
        let cloned_key = ecdsa_key.clone();

        // Both should have the same initial state
        assert_eq!(ecdsa_key.priv_key_id(), cloned_key.priv_key_id());
        assert_eq!(ecdsa_key.pub_key(), cloned_key.pub_key());
    }

    #[test]
    fn test_ecdsa_key_public_key_sizes() {
        // Create test session using helper
        let (_partition, mut session) = create_test_session();

        let test_cases = vec![
            (EcCurve::P256, "P-256"),
            (EcCurve::P384, "P-384"),
            (EcCurve::P521, "P-521"),
        ];

        for (curve, curve_name) in test_cases {
            let key_props = KeyProps::builder()
                .ecc_curve(curve)
                .sign(true)
                .verify(true)
                .build();

            let mut ecdsa_key = EcdsaKeyPair::new(key_props.clone(), key_props);

            // Generate the key pair
            session
                .generate_key_pair(&mut ecdsa_key)
                .unwrap_or_else(|_| panic!("Failed to generate ECDSA {} key pair", curve_name));

            // Verify public key exists and has reasonable size
            let pub_key = ecdsa_key.pub_key().unwrap();
            assert!(
                !pub_key.is_empty(),
                "Public key should not be empty for {}",
                curve_name
            );

            // DER-encoded public keys should have reasonable minimum sizes
            // This is a basic sanity check - actual sizes depend on DER encoding
            assert!(
                pub_key.len() > 32,
                "Public key should be larger than 32 bytes for {} (got {} bytes)",
                curve_name,
                pub_key.len()
            );

            println!(
                "Generated {} public key with {} bytes",
                curve_name,
                pub_key.len()
            );

            // Delete the key pair
            session
                .delete_key(&mut ecdsa_key)
                .unwrap_or_else(|_| panic!("Failed to delete ECDSA {} key pair", curve_name));
        }

        // Clean up
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_p256_sha256() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-256 key pair");

        // Create ECDSA algorithm with SHA-256
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Test message
        let message = b"Hello, ECDSA signing and verification!";

        // Get signature length
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the message
        session
            .sign(&algo, &keypair, message, &mut signature)
            .expect("Failed to sign message");

        // Verify the signature should succeed
        session
            .verify(&algo, &keypair, message, &signature)
            .expect("Failed to verify valid signature");

        // Verify with tampered message should fail
        let tampered_message = b"Hello, ECDSA signing and verification modified!";
        let verify_result = session.verify(&algo, &keypair, tampered_message, &signature);
        assert!(
            verify_result.is_err(),
            "Verification should fail with tampered message"
        );

        // Verify with tampered signature should fail
        let mut tampered_signature = signature.clone();
        tampered_signature[0] ^= 0xFF; // Flip bits in first byte
        let verify_result = session.verify(&algo, &keypair, message, &tampered_signature);
        assert!(
            verify_result.is_err(),
            "Verification should fail with tampered signature"
        );

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_p384_sha384() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-384 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-384 key pair");

        // Create ECDSA algorithm with SHA-384
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha384);

        // Test message
        let message = b"Testing P-384 curve with SHA-384 hash algorithm for ECDSA operations";

        // Get signature length
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the message
        session
            .sign(&algo, &keypair, message, &mut signature)
            .expect("Failed to sign message with P-384");

        // Verify the signature
        session
            .verify(&algo, &keypair, message, &signature)
            .expect("Failed to verify P-384 signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_p521_sha512() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-521 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-521 key pair");

        // Create ECDSA algorithm with SHA-512
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha512);

        // Test message
        let message = b"Testing the strongest curve P-521 with SHA-512 for maximum security in ECDSA operations";

        // Get signature length
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the message
        session
            .sign(&algo, &keypair, message, &mut signature)
            .expect("Failed to sign message with P-521");

        // Verify the signature
        session
            .verify(&algo, &keypair, message, &signature)
            .expect("Failed to verify P-521 signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_digest_direct() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA key pair");

        // Create ECDSA algorithm
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        let msg = [
            0x3b, 0xa8, 0xc2, 0x0c, 0x54, 0x8c, 0xf7, 0x9b, 0x94, 0x4b, 0x8a, 0xb4, 0x9c, 0x8a,
            0x8e, 0x6b, 0x2e, 0x1b, 0x3c, 0x7f, 0x9f, 0x8c, 0x0f, 0x2a, 0x8b, 0x4c, 0x9e, 0x7d,
            0x8a, 0x9b, 0xc5, 0xd1,
        ];

        // Get signature length and create signature buffer
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the digest directly
        session
            .sign(&algo, &keypair, &msg, &mut signature)
            .expect("Failed to sign digest");

        // Verify the signature using digest
        session
            .verify(&algo, &keypair, &msg, &signature)
            .expect("Failed to verify digest signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_signature_lengths() {
        let (_partition, mut session) = create_test_session();

        let test_cases = vec![
            (EcCurve::P256, AlgoId::EcdsaSha256, 64u32),
            (EcCurve::P384, AlgoId::EcdsaSha384, 96u32),
            (EcCurve::P521, AlgoId::EcdsaSha512, 132u32),
        ];

        for (curve, algo_id, expected_len) in test_cases {
            let key_props = KeyProps::builder()
                .ecc_curve(curve)
                .sign(true)
                .verify(true)
                .build();

            let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

            // Generate the key pair
            session
                .generate_key_pair(&mut keypair)
                .expect("Failed to generate key pair");

            let algo = EcdsaAlgo::new(algo_id);

            // Test signature length
            let sig_len = algo.signature_len(&keypair).unwrap();
            assert_eq!(
                sig_len, expected_len,
                "Signature length for {:?} should be {} bytes",
                curve, expected_len
            );

            // Clean up
            session
                .delete_key(&mut keypair)
                .expect("Failed to delete key pair");
        }

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_empty_message() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA key pair");

        // Create ECDSA algorithm
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Test with empty message
        let message = b"";

        // Get signature length
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the empty message
        session
            .sign(&algo, &keypair, message, &mut signature)
            .expect("Failed to sign empty message");

        // Verify the signature
        session
            .verify(&algo, &keypair, message, &signature)
            .expect("Failed to verify empty message signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_large_message() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA key pair");

        // Create ECDSA algorithm
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Create a large message (1MB)
        let large_message = vec![0xAB; 1024 * 1024];

        // Get signature length
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        // Sign the large message
        session
            .sign(&algo, &keypair, &large_message, &mut signature)
            .expect("Failed to sign large message");

        // Verify the signature
        session
            .verify(&algo, &keypair, &large_message, &signature)
            .expect("Failed to verify large message signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_sign_verify_insufficient_buffer() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA key pair");

        // Create ECDSA algorithm
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Test message
        let message = b"Test message for insufficient buffer";

        // Create insufficient signature buffer (too small)
        let mut small_signature = vec![0u8; 32]; // P-256 needs 64 bytes

        // Sign should fail with insufficient buffer
        let sign_result = session.sign(&algo, &keypair, message, &mut small_signature);
        assert!(
            sign_result.is_err(),
            "Sign should fail with insufficient buffer"
        );

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_verify_without_public_key() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key pair but don't generate it
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Create ECDSA algorithm
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Test message and dummy signature
        let message = b"Test message";
        let signature = vec![0u8; 64];

        // Verify should fail because key pair is not generated
        let verify_result = session.verify(&algo, &keypair, message, &signature);
        assert!(
            verify_result.is_err(),
            "Verify should fail without generated key pair"
        );
        assert_eq!(verify_result.unwrap_err(), AZIHSM_KEY_NOT_INITIALIZED);

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_verify_p256_sha256() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-256 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        // Generate the key pair
        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-256 key pair");

        // Create ECDSA algorithm with SHA-256
        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Initialize streaming sign operation
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");

        // Update with data in chunks
        let chunk1 = b"Hello, ";
        let chunk2 = b"ECDSA ";
        let chunk3 = b"streaming!";

        sign_stream
            .update(chunk1)
            .expect("Failed to update sign stream with chunk 1");
        sign_stream
            .update(chunk2)
            .expect("Failed to update sign stream with chunk 2");
        sign_stream
            .update(chunk3)
            .expect("Failed to update sign stream with chunk 3");

        // Get signature length and finalize
        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];

        let bytes_written = sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize sign stream");

        assert_eq!(bytes_written, sig_len, "Signature length mismatch");

        // Verify with streaming verify
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");

        verify_stream
            .update(chunk1)
            .expect("Failed to update verify stream with chunk 1");
        verify_stream
            .update(chunk2)
            .expect("Failed to update verify stream with chunk 2");
        verify_stream
            .update(chunk3)
            .expect("Failed to update verify stream with chunk 3");

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify streaming signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_verify_p384_sha384() {
        let (_partition, mut session) = create_test_session();

        // Create ECDSA key with P-384 curve
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P384)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-384 key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha384);

        // Initialize streaming sign
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");

        // Update with multiple chunks
        let data = b"Testing P-384 curve with streaming operations";
        for chunk in data.chunks(10) {
            sign_stream
                .update(chunk)
                .expect("Failed to update sign stream");
        }

        // Finalize signature
        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize sign stream");

        // Verify with streaming
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");

        for chunk in data.chunks(10) {
            verify_stream
                .update(chunk)
                .expect("Failed to update verify stream");
        }

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify streaming signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_verify_p521_sha512() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P521)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate ECDSA P-521 key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha512);

        // Initialize and update streaming sign
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");
        let message = b"Testing the strongest curve P-521 with streaming SHA-512";
        sign_stream
            .update(message)
            .expect("Failed to update sign stream");

        // Finalize signature
        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize sign stream");

        // Verify with streaming
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");
        verify_stream
            .update(message)
            .expect("Failed to update verify stream");
        verify_stream
            .finalize(&signature)
            .expect("Failed to verify streaming signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_empty_message() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Initialize sign stream
        let sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");

        // Don't call update - finalize with empty buffer
        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize with empty message");

        // Verify empty message
        let verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");
        verify_stream
            .finalize(&signature)
            .expect("Failed to verify empty message signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_large_message() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Initialize sign stream
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");

        // Create and update with large message in chunks
        let chunk_size = 1024;
        let num_chunks = 1024; // 1MB total
        for i in 0..num_chunks {
            let chunk = vec![(i % 256) as u8; chunk_size];
            sign_stream
                .update(&chunk)
                .expect("Failed to update with large chunk");
        }

        // Finalize
        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize large message signature");

        // Verify with same chunking pattern
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");

        for i in 0..num_chunks {
            let chunk = vec![(i % 256) as u8; chunk_size];
            verify_stream
                .update(&chunk)
                .expect("Failed to update verify with large chunk");
        }

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify large message signature");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_verify_tampered_message() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Sign original message
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");
        let chunk1 = b"Original ";
        let chunk2 = b"message";
        sign_stream.update(chunk1).expect("Update failed");
        sign_stream.update(chunk2).expect("Update failed");

        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize");

        // Verify with tampered message
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");
        let tampered_chunk1 = b"Tampered ";
        verify_stream
            .update(tampered_chunk1)
            .expect("Update failed");
        verify_stream.update(chunk2).expect("Update failed");

        let result = verify_stream.finalize(&signature);
        assert!(
            result.is_err(),
            "Verification should fail with tampered message"
        );

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_verify_tampered_signature() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Sign message
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");
        let message = b"Test message for signature tampering";
        sign_stream.update(message).expect("Update failed");

        let sig_len = sign_stream.signature_len().unwrap() as usize;
        let mut signature = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize");

        // Tamper with signature
        signature[0] ^= 0xFF;

        // Verify with tampered signature
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");
        verify_stream.update(message).expect("Update failed");

        let result = verify_stream.finalize(&signature);
        assert!(
            result.is_err(),
            "Verification should fail with tampered signature"
        );

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_without_private_key() {
        let (_partition, mut session) = create_test_session();

        // Create key pair without generating it
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Try to initialize sign stream without generated key
        let result = session.sign_init(&algo, &keypair);
        assert!(
            result.is_err(),
            "Sign init should fail without generated key"
        );
        assert!(matches!(result, Err(AZIHSM_KEY_NOT_INITIALIZED)));

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_verify_without_public_key() {
        let (_partition, mut session) = create_test_session();

        // Create key pair without generating it
        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Try to initialize verify stream without generated key
        let result = session.verify_init(&algo, &keypair);
        assert!(
            result.is_err(),
            "Verify init should fail without generated key"
        );
        assert!(matches!(result, Err(AZIHSM_KEY_NOT_INITIALIZED)));

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_signature_lengths() {
        let (_partition, mut session) = create_test_session();

        let test_cases = vec![
            (EcCurve::P256, AlgoId::EcdsaSha256, 64usize),
            (EcCurve::P384, AlgoId::EcdsaSha384, 96usize),
            (EcCurve::P521, AlgoId::EcdsaSha512, 132usize),
        ];

        for (curve, algo_id, expected_len) in test_cases {
            let key_props = KeyProps::builder()
                .ecc_curve(curve)
                .sign(true)
                .verify(true)
                .build();

            let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

            session
                .generate_key_pair(&mut keypair)
                .expect("Failed to generate key pair");

            let algo = EcdsaAlgo::new(algo_id);
            let sign_stream = session
                .sign_init(&algo, &keypair)
                .expect("Failed to init sign stream");

            // Check signature length
            let sig_len = sign_stream.signature_len().unwrap() as usize;
            assert_eq!(
                sig_len, expected_len,
                "Signature length for {:?} should be {} bytes",
                curve, expected_len
            );

            // Clean up
            session
                .delete_key(&mut keypair)
                .expect("Failed to delete key pair");
        }

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_vs_non_streaming_consistency() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        let message = b"Test message for comparing streaming vs non-streaming operations";

        // Non-streaming sign
        let sig_len = algo.signature_len(&keypair).unwrap() as usize;
        let mut non_streaming_sig = vec![0u8; sig_len];
        session
            .sign(&algo, &keypair, message, &mut non_streaming_sig)
            .expect("Failed to sign non-streaming");

        // Streaming sign
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");
        sign_stream
            .update(message)
            .expect("Failed to update sign stream");
        let mut streaming_sig = vec![0u8; sig_len];
        sign_stream
            .finalize(&mut streaming_sig)
            .expect("Failed to finalize sign stream");

        // Verify non-streaming signature with streaming verify
        let mut verify_stream = session
            .verify_init(&algo, &keypair)
            .expect("Failed to init verify stream");
        verify_stream
            .update(message)
            .expect("Failed to update verify stream");
        verify_stream
            .finalize(&non_streaming_sig)
            .expect("Failed to verify non-streaming signature with streaming verify");

        // Verify streaming signature with non-streaming verify
        session
            .verify(&algo, &keypair, message, &streaming_sig)
            .expect("Failed to verify streaming signature with non-streaming verify");

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_ecdsa_streaming_sign_insufficient_buffer() {
        let (_partition, mut session) = create_test_session();

        let key_props = KeyProps::builder()
            .ecc_curve(EcCurve::P256)
            .sign(true)
            .verify(true)
            .build();

        let mut keypair = EcdsaKeyPair::new(key_props.clone(), key_props);

        session
            .generate_key_pair(&mut keypair)
            .expect("Failed to generate key pair");

        let algo = EcdsaAlgo::new(AlgoId::EcdsaSha256);

        // Initialize and update sign stream
        let mut sign_stream = session
            .sign_init(&algo, &keypair)
            .expect("Failed to init sign stream");
        sign_stream
            .update(b"Test message")
            .expect("Failed to update");

        // Try to finalize with insufficient buffer
        let mut small_signature = vec![0u8; sign_stream.signature_len().unwrap() as usize - 1];

        let result = sign_stream.finalize(&mut small_signature);
        assert!(
            result.is_err(),
            "Finalize should fail with insufficient buffer"
        );
        assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

        // Clean up
        session
            .delete_key(&mut keypair)
            .expect("Failed to delete key pair");
        session.close().expect("Failed to close session");
    }
}
