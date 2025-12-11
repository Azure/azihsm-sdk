// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

#[cfg(test)]
mod tests {
    use crate::crypto::aes::AesCbcAlgo;
    use crate::crypto::aes::AesCbcKey;
    use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
    use crate::crypto::ecdh::SecretKey;
    use crate::crypto::hkdf::HkdfAlgo;
    use crate::crypto::hkdf::HkdfAlgoParams;
    use crate::crypto::EncryptOp;
    use crate::session::test_helpers::create_test_session;
    use crate::types::AlgoId;
    use crate::types::AzihsmKeyClass;
    use crate::types::KeyKind;
    use crate::types::KeyProps;

    #[test]
    fn test_hkdf_derive_aes128_basic() {
        let (_partition, session) = create_test_session();

        // Generate a base secret key for HKDF using ECDH
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

        // Create SecretKey with the derived key ID
        let base_secret_key = SecretKey::new_with_id(base_key_props_for_derive, base_key_id);

        // Create HKDF algorithm
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: Some(b"test-salt".to_vec()),
            info: Some(b"test-info".to_vec()),
        };
        let hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Define derived key properties for AES-128
        let mut derived_key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();
        derived_key_props.set_kind(KeyKind::Aes);
        derived_key_props.set_class(AzihsmKeyClass::Secret);

        // Perform HKDF key derivation

        let result = session.key_derive(&hkdf_algo, &base_secret_key, &derived_key_props);

        assert!(result.is_ok(), "HKDF derivation should succeed");
        assert_ne!(result.unwrap().0, 0, "Derived key ID should not be zero");
    }

    #[test]
    fn test_hkdf_derive_aes256_with_encryption() {
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

        // server derives shared secret using her private key + client's public key
        let mut server_base_key_props = KeyProps::builder().derive(true).build();
        server_base_key_props.set_kind(KeyKind::HmacSha256);
        server_base_key_props.set_class(AzihsmKeyClass::Secret);

        let server_shared_secret_id = session
            .key_derive(&ecdh_algo, &server_keypair, &server_base_key_props)
            .expect("server's ECDH key derivation should succeed");

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

        // Create HKDF algorithm for AES-256 (same parameters for both parties)
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: Some(b"test-salt-256".to_vec()),
            info: Some(b"test-info-aes256".to_vec()),
        };
        let client_hkdf_algo = HkdfAlgo {
            params: hkdf_params.clone(),
        };
        let server_hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Define derived key properties for AES-256 (same for both parties)
        let mut client_aes_key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();
        client_aes_key_props.set_kind(KeyKind::Aes);
        client_aes_key_props.set_class(AzihsmKeyClass::Secret);

        let mut server_aes_key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .build();
        server_aes_key_props.set_kind(KeyKind::Aes);
        server_aes_key_props.set_class(AzihsmKeyClass::Secret);

        // Client derives AES key using HKDF
        let client_aes_key_id = session
            .key_derive(
                &client_hkdf_algo,
                &client_shared_secret,
                &client_aes_key_props,
            )
            .expect("Client's HKDF key derivation should succeed");

        // Server derives AES key using HKDF
        let server_aes_key_id = session
            .key_derive(
                &server_hkdf_algo,
                &server_shared_secret,
                &server_aes_key_props,
            )
            .expect("Server's HKDF key derivation should succeed");

        // Create AES keys from derived key IDs
        let client_aes_key = AesCbcKey::new_with_id(client_aes_key_props, client_aes_key_id);
        let server_aes_key = AesCbcKey::new_with_id(server_aes_key_props, server_aes_key_id);

        // Test cross-party encryption/decryption (real-world scenario)
        let plaintext = b"Hello, HKDF-derived AES key!";
        let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH]; // Use zero IV for testing
        let mut client_encrypt_algo = AesCbcAlgo::new(iv, true); // Enable PKCS7 padding

        // Calculate output buffer sizes
        let encrypt_len = client_encrypt_algo.ciphertext_len(plaintext.len());
        let mut ciphertext = vec![0u8; encrypt_len];

        // Client encrypts with its derived AES key
        let encrypt_result = session.encrypt(
            &mut client_encrypt_algo,
            &client_aes_key,
            plaintext,
            &mut ciphertext,
        );
        assert!(encrypt_result.is_ok(), "Client's encryption should succeed");

        let encrypted_bytes = encrypt_result.unwrap();
        assert!(encrypted_bytes > 0, "Should have encrypted some bytes");

        // Server decrypts with its derived AES key (which should be identical to Client's)
        let mut server_decrypt_algo = AesCbcAlgo::new(iv, true);
        let mut decrypted = vec![0u8; plaintext.len() + 16]; // Extra space for padding
        let decrypt_result = session.decrypt(
            &mut server_decrypt_algo,
            &server_aes_key,
            &ciphertext[..encrypted_bytes],
            &mut decrypted,
        );
        assert!(decrypt_result.is_ok(), "Server's decryption should succeed");

        let decrypted_bytes = decrypt_result.unwrap();
        assert_eq!(
            decrypted_bytes,
            plaintext.len(),
            "Decrypted length should match original"
        );
        assert_eq!(
            &decrypted[..decrypted_bytes],
            plaintext,
            "Decrypted data should match original plaintext"
        );

        // Additional verification: Both derived AES keys should be functionally equivalent
        // Test Server encrypting and Client decrypting
        let plaintext2 = b"Server's response to Client!";
        let mut server_encrypt_algo = AesCbcAlgo::new(iv, true);
        let encrypt_len2 = server_encrypt_algo.ciphertext_len(plaintext2.len());
        let mut ciphertext2 = vec![0u8; encrypt_len2];

        // Server encrypts
        let encrypt_result2 = session.encrypt(
            &mut server_encrypt_algo,
            &server_aes_key,
            plaintext2,
            &mut ciphertext2,
        );
        assert!(
            encrypt_result2.is_ok(),
            "Server's encryption should succeed"
        );

        let encrypted_bytes2 = encrypt_result2.unwrap();

        // Client decrypts
        let mut client_decrypt_algo = AesCbcAlgo::new(iv, true);
        let mut decrypted2 = vec![0u8; plaintext2.len() + 16];
        let decrypt_result2 = session.decrypt(
            &mut client_decrypt_algo,
            &client_aes_key,
            &ciphertext2[..encrypted_bytes2],
            &mut decrypted2,
        );
        assert!(
            decrypt_result2.is_ok(),
            "Client's decryption should succeed"
        );

        let decrypted_bytes2 = decrypt_result2.unwrap();
        assert_eq!(
            &decrypted2[..decrypted_bytes2],
            plaintext2,
            "Client should be able to decrypt Server's message"
        );
    }

    #[test]
    fn test_hkdf_derive_different_salt_info() {
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

        // Test derivation with different salt/info combinations
        let test_cases = vec![
            (Some(b"salt1".to_vec()), Some(b"info1".to_vec())),
            (Some(b"salt2".to_vec()), Some(b"info2".to_vec())),
            (Some(b"salt1".to_vec()), Some(b"info2".to_vec())),
            (Some(b"salt2".to_vec()), Some(b"info1".to_vec())),
        ];

        let mut derived_key_ids = Vec::new();

        for (salt, info) in test_cases {
            let hkdf_params = HkdfAlgoParams {
                hmac_algo_id: AlgoId::HmacSha256,
                salt,
                info,
            };
            let hkdf_algo = HkdfAlgo {
                params: hkdf_params,
            };

            let mut derived_key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();
            derived_key_props.set_kind(KeyKind::Aes);
            derived_key_props.set_class(AzihsmKeyClass::Secret);

            let derived_key_id = session
                .key_derive(&hkdf_algo, &base_secret_key, &derived_key_props)
                .expect("HKDF key derivation should succeed");

            assert_ne!(derived_key_id.0, 0, "Derived key ID should not be zero");
            derived_key_ids.push(derived_key_id);
        }

        // All derived keys should be different (different salt/info should produce different keys)
        for i in 0..derived_key_ids.len() {
            for j in (i + 1)..derived_key_ids.len() {
                assert_ne!(
                    derived_key_ids[i].0, derived_key_ids[j].0,
                    "Different salt/info combinations should produce different keys"
                );
            }
        }
    }

    #[test]
    fn test_hkdf_derive_conflicting_key_properties_should_fail() {
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

        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: Some(b"test-salt".to_vec()),
            info: Some(b"test-info".to_vec()),
        };
        let hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        // Test conflicting key properties: encrypt/decrypt + derive
        let mut conflicting_key_props = KeyProps::builder()
            .bit_len(256)
            .encrypt(true)
            .decrypt(true)
            .derive(true) // This conflicts with encrypt/decrypt
            .build();
        conflicting_key_props.set_kind(KeyKind::Aes);
        conflicting_key_props.set_class(AzihsmKeyClass::Secret);

        let result = session.key_derive(&hkdf_algo, &base_secret_key, &conflicting_key_props);

        // Should fail due to conflicting key properties validation
        assert!(
            result.is_err(),
            "HKDF derivation should fail with conflicting key properties"
        );
    }

    #[test]
    fn test_hkdf_derive_no_salt_no_info() {
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

        // Test HKDF with no salt and no info (both None)
        let hkdf_params = HkdfAlgoParams {
            hmac_algo_id: AlgoId::HmacSha256,
            salt: None,
            info: None,
        };
        let hkdf_algo = HkdfAlgo {
            params: hkdf_params,
        };

        let mut derived_key_props = KeyProps::builder()
            .bit_len(128)
            .encrypt(true)
            .decrypt(true)
            .build();
        derived_key_props.set_kind(KeyKind::Aes);
        derived_key_props.set_class(AzihsmKeyClass::Secret);

        let result = session.key_derive(&hkdf_algo, &base_secret_key, &derived_key_props);

        assert!(
            result.is_ok(),
            "HKDF derivation should succeed even without salt/info"
        );
        assert_ne!(result.unwrap().0, 0, "Derived key ID should not be zero");
    }

    #[test]
    fn test_hkdf_derive_different_hash_algorithms() {
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

        // Test different HMAC hash algorithms (HKDF uses HMAC, not raw hash)
        let hash_algorithms = vec![
            AlgoId::HmacSha1,
            AlgoId::HmacSha256,
            AlgoId::HmacSha384,
            AlgoId::HmacSha512,
        ];

        let mut derived_key_ids = Vec::new();

        for hash_algo in hash_algorithms {
            let hkdf_params = HkdfAlgoParams {
                hmac_algo_id: hash_algo,
                salt: Some(b"test-salt".to_vec()),
                info: Some(b"test-info".to_vec()),
            };
            let hkdf_algo = HkdfAlgo {
                params: hkdf_params,
            };

            let mut derived_key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();
            derived_key_props.set_kind(KeyKind::Aes);
            derived_key_props.set_class(AzihsmKeyClass::Secret);

            let result = session.key_derive(&hkdf_algo, &base_secret_key, &derived_key_props);

            assert!(
                result.is_ok(),
                "HKDF derivation should succeed with {:?}",
                hash_algo
            );
            assert_ne!(
                result.unwrap().0,
                0,
                "Derived key ID should not be zero for {:?}",
                hash_algo
            );
            derived_key_ids.push(result.unwrap());
        }

        // All derived keys should be different (different hash algorithms should produce different keys)
        for i in 0..derived_key_ids.len() {
            for j in (i + 1)..derived_key_ids.len() {
                assert_ne!(
                    derived_key_ids[i].0, derived_key_ids[j].0,
                    "Different hash algorithms should produce different keys"
                );
            }
        }
    }
}
