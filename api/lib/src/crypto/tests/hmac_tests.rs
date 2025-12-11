// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

#[cfg(test)]
mod tests {
    use crate::crypto::ecdh::SecretKey;
    use crate::crypto::hkdf::HkdfAlgo;
    use crate::crypto::hkdf::HkdfAlgoParams;
    use crate::crypto::hmac::HmacAlgo;
    use crate::crypto::hmac::HmacKey;
    use crate::crypto::SignOp;
    use crate::crypto::StreamingSignOp;
    use crate::crypto::StreamingVerifyOp;
    use crate::crypto::VerifyOp;
    use crate::session::test_helpers::create_test_session;
    use crate::types::AlgoId;
    use crate::types::AzihsmKeyClass;
    use crate::types::KeyKind;
    use crate::types::KeyProps;

    /// Helper function to derive an HMAC key for testing using ECDH + HKDF
    fn create_hmac_key(
        session: &crate::session::Session,
        key_kind: KeyKind,
        bit_len: u32,
        hmac_algo_id: AlgoId,
    ) -> HmacKey {
        // Generate two ECDH key pairs
        let server_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            server_key_props.clone(),
            server_key_props.clone(),
        );
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        let client_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            client_key_props.clone(),
            client_key_props.clone(),
        );
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm to derive the base secret
        let ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: ecdh_params,
        };

        let mut base_key_props_for_derive = KeyProps::builder().derive(true).build();
        base_key_props_for_derive.set_kind(KeyKind::HmacSha256);
        base_key_props_for_derive.set_class(AzihsmKeyClass::Secret);

        let base_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &base_key_props_for_derive)
            .expect("ECDH key derivation should succeed for base key");

        // Create SecretKey with the derived key ID for HKDF
        let base_secret_key = SecretKey::new_with_id(base_key_props_for_derive, base_key_id);

        // Use HKDF to derive HMAC key from secret
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id,
            salt: Some(b"test-salt-hmac".to_vec()),
            info: Some(b"test-info-hmac-key".to_vec()),
        };
        let hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Define derived HMAC key properties
        let mut hmac_key_props = KeyProps::builder()
            .bit_len(bit_len)
            .sign(true)
            .verify(true)
            .build();
        hmac_key_props.set_kind(key_kind);
        hmac_key_props.set_class(AzihsmKeyClass::Secret);

        // Derive HMAC key using HKDF
        let hmac_key_id = session
            .key_derive(&hkdf_algo, &base_secret_key, &hmac_key_props)
            .expect("HKDF key derivation should succeed for HMAC key");

        // Create HMAC key from derived key ID
        HmacKey::new_with_id(hmac_key_props, hmac_key_id)
    }

    #[test]
    fn test_hmac_sha256_basic_sign_verify() {
        let (_partition, session) = create_test_session();

        // Generate a base secret key for HMAC using ECDH
        let server_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            server_key_props.clone(),
            server_key_props.clone(),
        );
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        let client_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair =
            crate::crypto::ec::EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        // Get client's public key for ECDH
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        // Create ECDH algorithm to derive the base secret
        let ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: ecdh_params,
        };

        let mut base_key_props_for_derive = KeyProps::builder().derive(true).build();
        base_key_props_for_derive.set_kind(KeyKind::HmacSha256);
        base_key_props_for_derive.set_class(AzihsmKeyClass::Secret);

        let base_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &base_key_props_for_derive)
            .expect("ECDH key derivation should succeed for base key");

        // Create HKDF algorithm to derive HMAC key
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: Some(b"test-salt-hmac".to_vec()),
            info: Some(b"test-info-hmac-key".to_vec()),
        };
        let hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Define derived HMAC key properties
        let mut hmac_key_props = KeyProps::builder()
            .bit_len(256)
            .sign(true)
            .verify(true)
            .build();
        hmac_key_props.set_kind(KeyKind::HmacSha256);
        hmac_key_props.set_class(AzihsmKeyClass::Secret);

        // Create SecretKey with the derived key ID for HKDF
        let base_secret_key = SecretKey::new_with_id(base_key_props_for_derive, base_key_id);

        // Derive HMAC key using HKDF
        let hmac_key_id = session
            .key_derive(&hkdf_algo, &base_secret_key, &hmac_key_props)
            .expect("HKDF key derivation should succeed for HMAC key");

        // Create HMAC key from derived key ID
        let hmac_key = HmacKey::new_with_id(hmac_key_props, hmac_key_id);

        // Test HMAC sign and verify
        let hmac_algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let message = b"Hello, HMAC world!";
        let signature_len = hmac_algo
            .signature_len(&hmac_key)
            .expect("Should be able to get signature length");
        let mut signature = vec![0u8; signature_len as usize];

        // Sign the message
        hmac_algo
            .sign(&session, &hmac_key, message, &mut signature)
            .expect("HMAC signing should succeed");

        // Verify the signature
        hmac_algo
            .verify(&session, &hmac_key, message, &signature)
            .expect("HMAC verification should succeed");

        // Test with wrong message (should fail)
        let wrong_message = b"Wrong message!";
        let verify_result = hmac_algo.verify(&session, &hmac_key, wrong_message, &signature);
        assert!(
            verify_result.is_err(),
            "HMAC verification should fail with wrong message"
        );

        // Test with corrupted signature (should fail)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 0xFF; // Flip bits in first byte
        let verify_result = hmac_algo.verify(&session, &hmac_key, message, &corrupted_signature);
        assert!(
            verify_result.is_err(),
            "HMAC verification should fail with corrupted signature"
        );
    }

    #[test]
    fn test_cross_party_hmac_sign_verify() {
        let (_partition, session) = create_test_session();

        // Test real-world scenario: Two parties (Client and Server) perform ECDH key exchange,
        // then derive HMAC keys using HKDF, and use them for cross-party authentication

        // Generate Server's key pair
        let server_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            server_key_props.clone(),
            server_key_props.clone(),
        );
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate Server's key pair");

        // Generate Client's key pair
        let client_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            client_key_props.clone(),
            client_key_props.clone(),
        );
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate Client's key pair");

        // Server derives shared secret using its private key + Client's public key
        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get Client's public key");

        let server_ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: client_public_key,
        };
        let server_ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: server_ecdh_params,
        };

        let mut server_base_key_props = KeyProps::builder().derive(true).build();
        server_base_key_props.set_kind(KeyKind::HmacSha256);
        server_base_key_props.set_class(AzihsmKeyClass::Secret);

        let server_shared_secret_id = session
            .key_derive(&server_ecdh_algo, &server_keypair, &server_base_key_props)
            .expect("Server's ECDH key derivation should succeed");

        let server_shared_secret =
            SecretKey::new_with_id(server_base_key_props, server_shared_secret_id);

        // Client derives shared secret using its private key + Server's public key
        let server_public_key = server_keypair
            .pub_key()
            .expect("Failed to get Server's public key");

        let client_ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: server_public_key,
        };
        let client_ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: client_ecdh_params,
        };

        let mut client_base_key_props = KeyProps::builder().derive(true).build();
        client_base_key_props.set_kind(KeyKind::HmacSha256);
        client_base_key_props.set_class(AzihsmKeyClass::Secret);

        let client_shared_secret_id = session
            .key_derive(&client_ecdh_algo, &client_keypair, &client_base_key_props)
            .expect("Client's ECDH key derivation should succeed");

        let client_shared_secret =
            SecretKey::new_with_id(client_base_key_props, client_shared_secret_id);

        // Create HKDF algorithm for HMAC key derivation (same parameters for both parties)
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: Some(b"hmac-salt-256".to_vec()),
            info: Some(b"hmac-auth-key".to_vec()),
        };
        let server_hkdf_algo = HkdfAlgo {
            params: hkdf_params.clone(),
        };
        let client_hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Define derived HMAC key properties (same for both parties)
        let mut server_hmac_key_props = KeyProps::builder()
            .bit_len(256)
            .sign(true)
            .verify(true)
            .build();
        server_hmac_key_props.set_kind(KeyKind::HmacSha256);
        server_hmac_key_props.set_class(AzihsmKeyClass::Secret);

        let mut client_hmac_key_props = KeyProps::builder()
            .bit_len(256)
            .sign(true)
            .verify(true)
            .build();
        client_hmac_key_props.set_kind(KeyKind::HmacSha256);
        client_hmac_key_props.set_class(AzihsmKeyClass::Secret);

        // Server derives HMAC key using HKDF
        let server_hmac_key_id = session
            .key_derive(
                &server_hkdf_algo,
                &server_shared_secret,
                &server_hmac_key_props,
            )
            .expect("Server's HKDF key derivation should succeed");

        // Client derives HMAC key using HKDF
        let client_hmac_key_id = session
            .key_derive(
                &client_hkdf_algo,
                &client_shared_secret,
                &client_hmac_key_props,
            )
            .expect("Client's HKDF key derivation should succeed");

        // Create HMAC keys from derived key IDs
        let server_hmac_key = HmacKey::new_with_id(server_hmac_key_props, server_hmac_key_id);
        let client_hmac_key = HmacKey::new_with_id(client_hmac_key_props, client_hmac_key_id);

        // Test cross-party HMAC authentication (real-world scenario)
        let hmac_algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        // Server signs a message to Client
        let server_message = b"Server authentication token";
        let signature_len = hmac_algo
            .signature_len(&server_hmac_key)
            .expect("Should be able to get signature length");
        let mut server_signature = vec![0u8; signature_len as usize];

        hmac_algo
            .sign(
                &session,
                &server_hmac_key,
                server_message,
                &mut server_signature,
            )
            .expect("Server's HMAC signing should succeed");

        // Client verifies Server's message using Client's copy of the same derived key
        hmac_algo
            .verify(
                &session,
                &client_hmac_key,
                server_message,
                &server_signature,
            )
            .expect("Client should be able to verify Server's HMAC");

        // Client signs a response to Server
        let client_message = b"Client response token";
        let mut client_signature = vec![0u8; signature_len as usize];

        hmac_algo
            .sign(
                &session,
                &client_hmac_key,
                client_message,
                &mut client_signature,
            )
            .expect("Client's HMAC signing should succeed");

        // Server verifies Client's response using Server's copy of the same derived key
        hmac_algo
            .verify(
                &session,
                &server_hmac_key,
                client_message,
                &client_signature,
            )
            .expect("Server should be able to verify Client's HMAC");

        // Test that different messages fail verification
        let wrong_message = b"Attacker's message";
        let verify_result =
            hmac_algo.verify(&session, &client_hmac_key, wrong_message, &server_signature);
        assert!(
            verify_result.is_err(),
            "HMAC verification should fail with wrong message"
        );
    }

    #[test]
    fn test_hmac_different_hash_algorithms() {
        let (_partition, session) = create_test_session();

        // Create base secret key using ECDH
        let server_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            server_key_props.clone(),
            server_key_props.clone(),
        );
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        let client_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair =
            crate::crypto::ec::EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        let ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: ecdh_params,
        };

        let mut base_key_props_for_derive = KeyProps::builder().derive(true).build();
        base_key_props_for_derive.set_kind(KeyKind::HmacSha256);
        base_key_props_for_derive.set_class(AzihsmKeyClass::Secret);

        let base_key_id = session
            .key_derive(&ecdh_algo, &server_keypair, &base_key_props_for_derive)
            .expect("ECDH key derivation should succeed");

        let base_secret_key = SecretKey::new_with_id(base_key_props_for_derive, base_key_id);

        // Test different HMAC hash algorithms (all use 256-bit key length for derivation)
        // Note: HmacSha1 is not included as DDI doesn't support DdiKeyType::HmacSha1
        let test_cases: Vec<(AlgoId, KeyKind, u32)> = vec![
            (AlgoId::HmacSha256, KeyKind::HmacSha256, 256),
            (AlgoId::HmacSha384, KeyKind::HmacSha384, 256),
            (AlgoId::HmacSha512, KeyKind::HmacSha512, 256),
        ];

        for (hmac_algo_id, key_kind, bit_len) in test_cases {
            // Create HKDF algorithm
            let hkdf_params = HkdfAlgoParams {
                hmac_algo_id,
                salt: Some(format!("salt-{:?}", hmac_algo_id).into_bytes()),
                info: Some(format!("info-{:?}", hmac_algo_id).into_bytes()),
            };
            let hkdf_algo = HkdfAlgo {
                params: hkdf_params,
            };

            // Define derived HMAC key properties
            let mut hmac_key_props = KeyProps::builder()
                .bit_len(bit_len)
                .sign(true)
                .verify(true)
                .build();
            hmac_key_props.set_kind(key_kind);
            hmac_key_props.set_class(AzihsmKeyClass::Secret);

            // Derive first HMAC key for signing
            let signing_key_props = hmac_key_props.clone();
            let signing_key_id = session
                .key_derive(&hkdf_algo, &base_secret_key, &signing_key_props)
                .unwrap_or_else(|_| {
                    panic!(
                        "HKDF key derivation should succeed for signing key {:?}",
                        hmac_algo_id
                    )
                });

            // Derive second HMAC key for verification (same parameters, separate key object)
            let verification_key_props = hmac_key_props.clone();
            let verification_key_id = session
                .key_derive(&hkdf_algo, &base_secret_key, &verification_key_props)
                .unwrap_or_else(|_| {
                    panic!(
                        "HKDF key derivation should succeed for verification key {:?}",
                        hmac_algo_id
                    )
                });

            // Create separate HMAC keys for signing and verification
            let signing_key = HmacKey::new_with_id(signing_key_props, signing_key_id);
            let verification_key =
                HmacKey::new_with_id(verification_key_props, verification_key_id);
            let hmac_algo = HmacAlgo { id: hmac_algo_id };

            let message = format!("Test message for {:?}", hmac_algo_id);
            let signature_len = hmac_algo.signature_len(&signing_key).unwrap_or_else(|_| {
                panic!(
                    "Should be able to get signature length for {:?}",
                    hmac_algo_id
                )
            });
            let mut signature = vec![0u8; signature_len as usize];

            // Sign with signing key and verify with verification key (separate keys, same derivation)
            hmac_algo
                .sign(&session, &signing_key, message.as_bytes(), &mut signature)
                .unwrap_or_else(|_| panic!("HMAC signing should succeed for {:?}", hmac_algo_id));

            hmac_algo
                .verify(&session, &verification_key, message.as_bytes(), &signature)
                .unwrap_or_else(|_| {
                    panic!("HMAC verification should succeed for {:?}", hmac_algo_id)
                });
        }
    }

    #[test]
    fn test_hmac_signature_lengths() {
        let (_partition, session) = create_test_session();

        // Create a simple HMAC key for testing signature lengths
        let server_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut server_keypair = crate::crypto::ec::EcdsaKeyPair::new(
            server_key_props.clone(),
            server_key_props.clone(),
        );
        session
            .generate_key_pair(&mut server_keypair)
            .expect("Failed to generate server's key pair");

        let client_key_props = KeyProps::builder()
            .ecc_curve(crate::types::EcCurve::P256)
            .derive(true)
            .build();

        let mut client_keypair =
            crate::crypto::ec::EcdsaKeyPair::new(client_key_props.clone(), client_key_props);
        session
            .generate_key_pair(&mut client_keypair)
            .expect("Failed to generate client's key pair");

        let client_public_key = client_keypair
            .pub_key()
            .expect("Failed to get client's public key");

        let ecdh_params = crate::crypto::ecdh::EcdhParams {
            pub_key: client_public_key,
        };
        let ecdh_algo = crate::crypto::ecdh::EcdhAlgo {
            params: ecdh_params,
        };

        // Test signature lengths for different HMAC algorithms (all use 256-bit for key derivation)
        // Note: HmacSha1 is not included as DDI doesn't support DdiKeyType::HmacSha1
        let test_cases = vec![
            (AlgoId::HmacSha256, KeyKind::HmacSha256, 256, 32),
            (AlgoId::HmacSha384, KeyKind::HmacSha384, 256, 48),
            (AlgoId::HmacSha512, KeyKind::HmacSha512, 256, 64),
        ];

        for (hmac_algo_id, key_kind, bit_len, expected_sig_len) in test_cases {
            let mut base_key_props_for_derive = KeyProps::builder().derive(true).build();
            base_key_props_for_derive.set_kind(KeyKind::HmacSha256); // Always use HmacSha256 for ECDH base secret
            base_key_props_for_derive.set_class(AzihsmKeyClass::Secret);

            let base_key_id = session
                .key_derive(&ecdh_algo, &server_keypair, &base_key_props_for_derive)
                .expect("ECDH key derivation should succeed");

            let base_secret_key = SecretKey::new_with_id(base_key_props_for_derive, base_key_id);

            // Create HKDF algorithm
            let hkdf_params = HkdfAlgoParams {
                hmac_algo_id,
                salt: Some(b"test-salt".to_vec()),
                info: Some(b"test-info".to_vec()),
            };
            let hkdf_algo = HkdfAlgo {
                params: hkdf_params,
            };

            // Define derived HMAC key properties
            let mut hmac_key_props = KeyProps::builder()
                .bit_len(bit_len)
                .sign(true)
                .verify(true)
                .build();
            hmac_key_props.set_kind(key_kind);
            hmac_key_props.set_class(AzihsmKeyClass::Secret);

            // Derive HMAC key using HKDF
            let hmac_key_id = session
                .key_derive(&hkdf_algo, &base_secret_key, &hmac_key_props)
                .expect("HKDF key derivation should succeed");

            // Create HMAC key and test signature length
            let hmac_key = HmacKey::new_with_id(hmac_key_props, hmac_key_id);
            let hmac_algo = HmacAlgo { id: hmac_algo_id };

            let signature_len = hmac_algo
                .signature_len(&hmac_key)
                .expect("Should be able to get signature length");

            assert_eq!(
                signature_len as usize, expected_sig_len,
                "Signature length for {:?} should be {} bytes",
                hmac_algo_id, expected_sig_len
            );
        }
    }

    #[test]
    fn test_hmac_streaming_sign_verify_sha256() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        // Initialize streaming sign operation
        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        // Update with data in chunks
        let chunk1 = b"Hello, ";
        let chunk2 = b"HMAC ";
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
        let sig_len = sign_stream.signature_len().unwrap();
        assert_eq!(sig_len, 32, "HMAC-SHA256 should produce 32-byte tag");

        let mut signature = vec![0u8; sig_len as usize];

        let bytes_written = sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream");

        assert_eq!(bytes_written, sig_len as usize, "Signature length mismatch");

        // Verify with streaming verify
        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

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
            .expect("Failed to verify HMAC streaming signature");

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_sign_verify_sha512() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha512,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha512, 256, algo.id);

        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        let message = b"Test message for HMAC-SHA512 streaming";
        sign_stream
            .update(message)
            .expect("Failed to update sign stream");

        let sig_len = sign_stream.signature_len().unwrap();
        assert_eq!(sig_len, 64, "HMAC-SHA512 should produce 64-byte tag");

        let mut signature = vec![0u8; sig_len as usize];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream");

        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        verify_stream
            .update(message)
            .expect("Failed to update verify stream");

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify HMAC streaming signature");

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_empty_message() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        let sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        let sig_len = sign_stream.signature_len().unwrap();
        let mut signature = vec![0u8; sig_len as usize];

        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream with empty message");

        let verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify HMAC signature for empty message");

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_large_message() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        // Create message exactly at max size (1024 bytes)
        let large_message = vec![0x42u8; 1024];

        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        // Send in 256-byte chunks (4 chunks total = 1024 bytes)
        for chunk in large_message.chunks(256) {
            sign_stream
                .update(chunk)
                .expect("Failed to update sign stream");
        }

        let sig_len = sign_stream.signature_len().unwrap();
        let mut signature = vec![0u8; sig_len as usize];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream");

        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        for chunk in large_message.chunks(256) {
            verify_stream
                .update(chunk)
                .expect("Failed to update verify stream");
        }

        verify_stream
            .finalize(&signature)
            .expect("Failed to verify HMAC signature for large message");

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_exceed_max_message_size() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        // Test exceeding max size in single update
        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        let too_large_message = vec![0x42u8; 1025]; // 1 byte over limit
        let result = sign_stream.update(&too_large_message);
        assert!(
            result.is_err(),
            "Should fail when message exceeds max size in single update"
        );

        // Test exceeding max size across multiple updates
        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        let chunk1 = vec![0x42u8; 512];
        sign_stream
            .update(&chunk1)
            .expect("First 512-byte update should succeed");

        let chunk2 = vec![0x42u8; 512];
        sign_stream
            .update(&chunk2)
            .expect("Second 512-byte update should succeed (total 1024)");

        let chunk3 = vec![0x42u8; 1]; // This pushes over the limit
        let result = sign_stream.update(&chunk3);
        assert!(
            result.is_err(),
            "Should fail when accumulated message exceeds max size"
        );

        // Test same for verify stream
        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        let too_large_message = vec![0x42u8; 1025];
        let result = verify_stream.update(&too_large_message);
        assert!(
            result.is_err(),
            "Verify should fail when message exceeds max size"
        );

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_verify_tampered_message() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        let original_message = b"Original message";
        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        sign_stream
            .update(original_message)
            .expect("Failed to update sign stream");

        let sig_len = sign_stream.signature_len().unwrap();
        let mut signature = vec![0u8; sig_len as usize];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream");

        let tampered_message = b"Tampered message";
        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        verify_stream
            .update(tampered_message)
            .expect("Failed to update verify stream");

        let result = verify_stream.finalize(&signature);
        assert!(
            result.is_err(),
            "Verification should fail for tampered message"
        );

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_verify_tampered_signature() {
        let (_partition, mut session) = create_test_session();

        let algo = HmacAlgo {
            id: AlgoId::HmacSha256,
        };

        let mut hmac_key = create_hmac_key(&session, KeyKind::HmacSha256, 256, algo.id);

        let message = b"Test message";
        let mut sign_stream = session
            .sign_init(&algo, &hmac_key)
            .expect("Failed to init HMAC sign stream");

        sign_stream
            .update(message)
            .expect("Failed to update sign stream");

        let sig_len = sign_stream.signature_len().unwrap();
        let mut signature = vec![0u8; sig_len as usize];
        sign_stream
            .finalize(&mut signature)
            .expect("Failed to finalize HMAC sign stream");

        signature[0] ^= 0xFF;

        let mut verify_stream = session
            .verify_init(&algo, &hmac_key)
            .expect("Failed to init HMAC verify stream");

        verify_stream
            .update(message)
            .expect("Failed to update verify stream");

        let result = verify_stream.finalize(&signature);
        assert!(
            result.is_err(),
            "Verification should fail for tampered signature"
        );

        session
            .delete_key(&mut hmac_key)
            .expect("Failed to delete HMAC key");

        session.close().expect("Failed to close session");
    }

    #[test]
    fn test_hmac_streaming_all_algorithms() {
        let (_partition, mut session) = create_test_session();

        let test_cases = vec![
            (AlgoId::HmacSha256, KeyKind::HmacSha256, 256, 32),
            (AlgoId::HmacSha384, KeyKind::HmacSha384, 256, 48),
            (AlgoId::HmacSha512, KeyKind::HmacSha512, 256, 64),
        ];

        for (algo_id, key_kind, bit_len, expected_sig_len) in test_cases {
            let algo = HmacAlgo { id: algo_id };
            let mut hmac_key = create_hmac_key(&session, key_kind, bit_len, algo_id);

            let mut sign_stream = session
                .sign_init(&algo, &hmac_key)
                .unwrap_or_else(|_| panic!("Failed to init sign stream for {:?}", algo_id));

            let message = b"Test message for all HMAC algorithms";
            sign_stream
                .update(message)
                .unwrap_or_else(|_| panic!("Failed to update sign stream for {:?}", algo_id));

            let sig_len = sign_stream.signature_len().unwrap();
            assert_eq!(
                sig_len, expected_sig_len,
                "{:?} should produce {}-byte tag",
                algo_id, expected_sig_len
            );

            let mut signature = vec![0u8; sig_len as usize];
            sign_stream
                .finalize(&mut signature)
                .unwrap_or_else(|_| panic!("Failed to finalize sign stream for {:?}", algo_id));

            let mut verify_stream = session
                .verify_init(&algo, &hmac_key)
                .unwrap_or_else(|_| panic!("Failed to init verify stream for {:?}", algo_id));
            verify_stream
                .update(message)
                .unwrap_or_else(|_| panic!("Failed to update verify stream for {:?}", algo_id));

            verify_stream
                .finalize(&signature)
                .unwrap_or_else(|_| panic!("Failed to verify signature for {:?}", algo_id));

            session
                .delete_key(&mut hmac_key)
                .expect("Failed to delete HMAC key");
        }

        session.close().expect("Failed to close session");
    }
}
