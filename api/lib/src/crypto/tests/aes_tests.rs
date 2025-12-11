// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(test)]
mod tests {
    // ================================================================================
    // AES CBC (Unpadded) Tests
    // ================================================================================
    mod cbc_unpadded {
        use crate::crypto::aes::AesCbcAlgo;
        use crate::crypto::aes::AesCbcKey;
        use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
        use crate::crypto::DecryptOp;
        use crate::crypto::EncryptOp;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;
        use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
        use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
        use crate::AZIHSM_KEY_ALREADY_EXISTS;
        use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

        #[test]
        fn test_key_gen_128_bit() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties using builder
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);

            // Verify initial state
            assert!(
                aes_key.id().is_none(),
                "Key ID should be None before generation"
            );

            // Generate the key using session
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES 128-bit key");

            // Verify key was generated successfully
            assert!(
                aes_key.id().is_some(),
                "Key ID should be set after generation"
            );

            // Delete the key.
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete AES key");

            // Clean up
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_gen_already_exists() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties using builder
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);

            // Generate the key first time - should succeed
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key first time");

            // Try to generate again - should fail
            let result = session.generate_key(&mut aes_key);
            assert!(result.is_err(), "Second key generation should fail");
            assert_eq!(result.unwrap_err(), AZIHSM_KEY_ALREADY_EXISTS);

            // Clean up
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_gen_pair_not_supported() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties using builder
            let key_props = KeyProps::builder().bit_len(128).build();

            let mut aes_key = AesCbcKey::new(key_props);

            // Try to generate key pair - should fail for AES
            let result = session.generate_key_pair(&mut aes_key);
            assert!(
                result.is_err(),
                "Key pair generation should not be supported for AES"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_OPERATION_NOT_SUPPORTED);

            // Clean up
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);

            // Generate the key
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - must be 16 bytes (AES block size) for CBC mode
            let plaintext = b"1234567890123456"; // 16 bytes
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Initialize IV (16 bytes for AES)
            let iv = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ];

            // Create AES CBC algorithm instance
            let mut aes_cbc = AesCbcAlgo::new(iv, false);

            // Encrypt the plaintext
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt data");

            // Verify that ciphertext is different from plaintext
            assert_ne!(
                &ciphertext[..],
                &plaintext[..],
                "Ciphertext should be different from plaintext"
            );

            // Reset IV for decryption (CBC mode modifies the IV)
            aes_cbc.iv = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ];

            // Decrypt the ciphertext
            aes_cbc
                .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt data");

            // Verify that decrypted data matches original plaintext
            assert_eq!(
                &decrypted[..],
                &plaintext[..],
                "Decrypted data should match original plaintext"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete AES key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_different_lengths() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create and generate AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data for unpadded mode (must be block-aligned)
            let plaintext = b"1234567890123456"; // 16 bytes - exactly one block
            let iv = [0u8; 16];

            // Test Case 1: Insufficient buffer should fail (unpadded mode)
            let mut small_ciphertext = vec![0u8; 8]; // 8 bytes - too small for 16 byte plaintext
            let mut aes_cbc_encrypt1 = AesCbcAlgo::new(iv, false);

            let result =
                aes_cbc_encrypt1.encrypt(&session, &aes_key, plaintext, &mut small_ciphertext);
            assert!(
                result.is_err(),
                "Encrypt should fail with insufficient buffer"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Test Case 2: Exact size buffer should succeed (unpadded mode)
            let mut exact_ciphertext = vec![0u8; 16]; // 16 bytes - exact match
            let mut aes_cbc_encrypt2 = AesCbcAlgo::new(iv, false);

            let result =
                aes_cbc_encrypt2.encrypt(&session, &aes_key, plaintext, &mut exact_ciphertext);
            assert!(
                result.is_ok(),
                "Encrypt should succeed with exact buffer size"
            );

            // Verify the ciphertext is different from plaintext
            assert_ne!(&exact_ciphertext[..], plaintext);

            // Test Case 3: Larger buffer should succeed (unpadded mode)
            let mut large_ciphertext = vec![0u8; 32]; // 32 bytes - larger than needed
            let mut aes_cbc_encrypt3 = AesCbcAlgo::new(iv, false);

            let encrypted_len = aes_cbc_encrypt3
                .encrypt(&session, &aes_key, plaintext, &mut large_ciphertext)
                .expect("Encrypt should succeed with larger buffer");

            // Verify that only the first 16 bytes contain the encrypted data
            assert_eq!(encrypted_len, 16, "Encrypted length should be 16 bytes");
            assert_ne!(&large_ciphertext[..encrypted_len], plaintext);

            // Verify that unused buffer space remains unchanged (zeros in this case)
            assert_eq!(
                &large_ciphertext[encrypted_len..],
                &vec![0u8; large_ciphertext.len() - encrypted_len][..],
                "Unused buffer space should remain unchanged"
            );

            // Test Case 4: Non-block-aligned plaintext should fail (unpadded mode)
            let unaligned_plaintext = b"12345"; // 5 bytes - not block-aligned
            let mut unaligned_ciphertext = vec![0u8; 16];
            let mut aes_cbc_encrypt4 = AesCbcAlgo::new(iv, false);

            let result = aes_cbc_encrypt4.encrypt(
                &session,
                &aes_key,
                unaligned_plaintext,
                &mut unaligned_ciphertext,
            );
            assert!(
                result.is_err(),
                "Encrypt should fail with non-block-aligned input in unpadded mode"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_different_lengths() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create and generate AES key
            let key_props = KeyProps::builder()
                .bit_len(192)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // First, create valid ciphertext by encrypting known plaintext
            let original_plaintext = b"1234567890123456"; // 16 bytes
            let mut valid_ciphertext = vec![0u8; 16];

            let iv = [0u8; 16];
            let mut aes_cbc_encrypt = AesCbcAlgo::new(iv, false);

            aes_cbc_encrypt
                .encrypt(
                    &session,
                    &aes_key,
                    original_plaintext,
                    &mut valid_ciphertext,
                )
                .expect("Failed to create test ciphertext");

            // Test Case 1: Insufficient buffer should fail (unpadded mode)
            let mut small_plaintext = vec![0u8; 8]; // 8 bytes - too small for 16 byte ciphertext
            let mut aes_cbc_decrypt1 = AesCbcAlgo::new(iv, false);

            let result = aes_cbc_decrypt1.decrypt(
                &session,
                &aes_key,
                &valid_ciphertext,
                &mut small_plaintext,
            );
            assert!(
                result.is_err(),
                "Decrypt should fail with insufficient buffer"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Test Case 2: Exact size buffer should succeed (unpadded mode)
            let mut exact_plaintext = vec![0u8; 16]; // 16 bytes - exact match
            let mut aes_cbc_decrypt2 = AesCbcAlgo::new(iv, false);

            let result = aes_cbc_decrypt2.decrypt(
                &session,
                &aes_key,
                &valid_ciphertext,
                &mut exact_plaintext,
            );
            assert!(
                result.is_ok(),
                "Decrypt should succeed with exact buffer size"
            );
            assert_eq!(&exact_plaintext[..], original_plaintext);

            // Test Case 3: Larger buffer should succeed (unpadded mode)
            let mut large_plaintext = vec![0u8; 32]; // 32 bytes - larger than needed
            let mut aes_cbc_decrypt3 = AesCbcAlgo::new(iv, false);

            let decrypted_len = aes_cbc_decrypt3
                .decrypt(&session, &aes_key, &valid_ciphertext, &mut large_plaintext)
                .expect("Decrypt should succeed with larger buffer");

            // Verify that only the first 16 bytes contain the decrypted data
            assert_eq!(decrypted_len, 16, "Decrypted length should be 16 bytes");
            assert_eq!(&large_plaintext[..decrypted_len], original_plaintext);

            // Verify that unused buffer space remains unchanged (zeros in this case)
            assert_eq!(
                &large_plaintext[decrypted_len..],
                &vec![0u8; large_plaintext.len() - decrypted_len][..],
                "Unused buffer space should remain unchanged"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_multiple_blocks() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create and generate AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data with multiple blocks (32 bytes = 2 AES blocks)
            let plaintext = b"12345678901234561234567890123456"; // 32 bytes
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            let iv = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ];

            let mut aes_cbc = AesCbcAlgo::new(iv, false);

            // Encrypt multiple blocks
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt multiple blocks");

            // Verify encryption changed the data
            assert_ne!(&ciphertext[..], &plaintext[..]);

            // Reset IV for decryption
            aes_cbc.iv = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00,
            ];

            // Decrypt multiple blocks
            aes_cbc
                .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt multiple blocks");

            // Verify round-trip success
            assert_eq!(&decrypted[..], &plaintext[..]);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_block_alignment_requirement() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data that is NOT block-aligned
            let plaintext = b"12345"; // 5 bytes - not a multiple of 16
            let mut ciphertext = vec![0u8; 16];

            let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
            let mut aes_cbc = AesCbcAlgo::new(iv, false); // No padding

            // Should fail because input is not block-aligned
            let result = aes_cbc.encrypt(&session, &aes_key, plaintext, &mut ciphertext);
            assert!(
                result.is_err(),
                "Should fail with non-block-aligned input in unpadded mode"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INVALID_ARGUMENT);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }
    }

    // ================================================================================
    // AES CBC Streaming (Unpadded) Tests
    // ================================================================================
    mod cbc_streaming_unpadded {
        use crate::crypto::aes::AesCbcAlgo;
        use crate::crypto::aes::AesCbcKey;
        use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
        use crate::crypto::EncryptOp;
        use crate::crypto::StreamingDecryptOp;
        use crate::crypto::StreamingEncryptOp;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;

        #[test]
        fn test_encrypt_basic() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - 48 bytes (3 blocks)
            let plaintext = b"123456789012345612345678901234561234567890123456";
            let iv = [0x01; AES_CBC_BLOCK_IV_LENGTH];

            // Create streaming algorithm
            let aes_cbc = AesCbcAlgo::new(iv, false);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = vec![0u8; 48];
            let mut total_written = 0;

            // Process data in 16-byte chunks using update()
            for chunk_start in (0..plaintext.len()).step_by(AES_CBC_BLOCK_IV_LENGTH) {
                let chunk_end =
                    std::cmp::min(chunk_start + AES_CBC_BLOCK_IV_LENGTH, plaintext.len());
                let bytes_written = encrypt_stream
                    .update(
                        &plaintext[chunk_start..chunk_end],
                        &mut ciphertext[total_written..],
                    )
                    .expect("Failed to update streaming encryption");

                total_written += bytes_written;

                // Each complete block should produce exactly 16 bytes of output
                if chunk_end - chunk_start == AES_CBC_BLOCK_IV_LENGTH {
                    assert_eq!(
                        bytes_written, AES_CBC_BLOCK_IV_LENGTH,
                        "Should write {} bytes for complete block",
                        AES_CBC_BLOCK_IV_LENGTH
                    );
                }
            }

            // Finalize should return 0 bytes in unpadded mode when all data is block-aligned
            let bytes_written_final = encrypt_stream
                .finalize(&mut [])
                .expect("Failed to finalize streaming encryption");

            assert_eq!(
                bytes_written_final, 0,
                "Should write 0 bytes in finalize for unpadded mode"
            );
            assert_eq!(total_written, 48, "Should have written all 48 bytes");

            // Verify total output matches non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, false);
            let mut expected_ct = vec![0u8; 48];
            aes_cbc_compare
                .encrypt(&session, &aes_key, plaintext, &mut expected_ct)
                .expect("Failed non-streaming encryption");

            assert_eq!(
                ciphertext, expected_ct,
                "Streaming and non-streaming should match"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_basic() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Create test data and encrypt it first
            let plaintext = b"12345678901234561234567890123456"; // 32 bytes (2 blocks)
            let iv: [u8; 16] = [0x55; AES_CBC_BLOCK_IV_LENGTH];

            let mut aes_cbc = AesCbcAlgo::new(iv, false);
            let mut ciphertext = vec![0u8; 32];
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt test data");

            // Now test streaming decryption
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, false);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            // Decrypt first block (16 bytes)
            let mut decrypted = [0u8; 32];
            let bytes_written1 = decrypt_stream
                .update(&ciphertext[..16], &mut decrypted[..])
                .expect("Failed to update streaming decryption");

            assert_eq!(bytes_written1, 16, "Should write 16 bytes for first block");

            // Decrypt second block (16 bytes)
            let bytes_written2 = decrypt_stream
                .update(&ciphertext[16..], &mut decrypted[bytes_written1..])
                .expect("Failed to update streaming decryption");

            assert_eq!(bytes_written2, 16, "Should write 16 bytes for second block");

            // Finalize with no remaining data
            let bytes_written3 = decrypt_stream
                .finalize(&mut decrypted[bytes_written1 + bytes_written2..])
                .expect("Failed to finalize streaming decryption");

            assert_eq!(
                bytes_written3, 0,
                "Finalize should return 0 bytes when no data remains"
            );

            // Verify decrypted data matches original
            assert_eq!(
                &decrypted[..32],
                &plaintext[..],
                "Decrypted data should match original"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_partial_blocks() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - 50 bytes
            let plaintext = [0xAA; 50];
            let iv = [0x11; AES_CBC_BLOCK_IV_LENGTH];

            // Create streaming algorithm without padding
            let aes_cbc = AesCbcAlgo::new(iv, false);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = [0u8; 48]; // Only complete blocks (48 bytes = 3 blocks)
            let mut total_written = 0;

            // Feed data in small chunks to test partial block handling
            let chunks = [7, 5, 12, 8, 10, 8]; // Total: 50 bytes
            let mut offset = 0;

            for chunk_size in chunks {
                let end = std::cmp::min(offset + chunk_size, plaintext.len());
                let bytes_written = encrypt_stream
                    .update(&plaintext[offset..end], &mut ciphertext[total_written..])
                    .expect("Failed to update streaming encryption");

                total_written += bytes_written;
                offset = end;

                // Only complete blocks should be output
                assert_eq!(
                    total_written % AES_CBC_BLOCK_IV_LENGTH,
                    0,
                    "Should only output complete blocks"
                );
            }

            // Should have processed 48 bytes (3 complete blocks), 2 bytes remain in buffer
            assert_eq!(
                total_written, 48,
                "Should have written 48 bytes for 3 complete blocks"
            );

            // Finalize should fail because we have partial data and no padding
            let result = encrypt_stream.finalize(&mut [0u8; 16]);
            assert!(
                result.is_err(),
                "Should fail with partial data and no padding"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_partial_blocks() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Create ciphertext (3 blocks = 48 bytes)
            let plaintext = [0xBB; 48];
            let iv = [0x22; AES_CBC_BLOCK_IV_LENGTH];

            let mut aes_cbc = AesCbcAlgo::new(iv, false);
            let mut ciphertext = vec![0u8; 48];
            aes_cbc
                .encrypt(&session, &aes_key, &plaintext, &mut ciphertext)
                .expect("Failed to encrypt test data");

            // Now test streaming decryption with partial chunks
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, false);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            let mut decrypted = [0u8; 48];
            let mut total_written = 0;

            // Feed ciphertext in irregular chunks - use update() for ALL chunks
            let chunks = [10, 6, 20, 12]; // Total: 48 bytes
            let mut offset = 0;

            for chunk_size in chunks {
                let end = offset + chunk_size;
                let bytes_written = decrypt_stream
                    .update(&ciphertext[offset..end], &mut decrypted[total_written..])
                    .expect("Failed to update streaming decryption");

                total_written += bytes_written;
                offset = end;
            }

            // Finalize with no remaining data (should return 0 bytes in unpadded mode)
            let final_bytes = decrypt_stream
                .finalize(&mut decrypted[total_written..])
                .expect("Failed to finalize streaming decryption");

            total_written += final_bytes;

            assert_eq!(
                final_bytes, 0,
                "Finalize should return 0 bytes in unpadded mode"
            );
            assert_eq!(total_written, 48, "Should have decrypted all 48 bytes");
            assert_eq!(
                &decrypted[..],
                &plaintext[..],
                "Decrypted data should match original"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_empty_updates() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(192)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            let iv = [0x33; AES_CBC_BLOCK_IV_LENGTH];

            // Test encryption with empty updates
            let aes_cbc = AesCbcAlgo::new(iv, false);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = vec![0u8; 32];

            // Multiple empty updates should not fail
            let bytes1 = encrypt_stream.update(&[], &mut ciphertext).unwrap();
            assert_eq!(bytes1, 0, "Empty update should return 0 bytes");

            let bytes2 = encrypt_stream.update(&[], &mut ciphertext).unwrap();
            assert_eq!(bytes2, 0, "Empty update should return 0 bytes");

            // Add real data
            let plaintext = b"1234567890123456"; // 16 bytes
            let bytes3 = encrypt_stream.update(plaintext, &mut ciphertext).unwrap();
            assert_eq!(bytes3, 16, "Should return 16 bytes for complete block");

            // Empty finalize
            let bytes4 = encrypt_stream.finalize(&mut ciphertext[16..]).unwrap();
            assert_eq!(bytes4, 0, "Empty finalize should return 0 bytes");

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_single_byte_chunks() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - exactly 2 blocks
            let plaintext = b"12345678901234561234567890123456"; // 32 bytes
            let iv = [0x44; AES_CBC_BLOCK_IV_LENGTH];

            // Test encryption with single-byte chunks
            let aes_cbc = AesCbcAlgo::new(iv, false);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = vec![0u8; 32];
            let mut total_written = 0;

            // Feed data byte by byte
            for (i, &byte) in plaintext.iter().enumerate() {
                let bytes_written = encrypt_stream
                    .update(&[byte], &mut ciphertext[total_written..])
                    .expect("Failed single-byte update");

                total_written += bytes_written;

                // Should only output complete blocks
                if (i + 1) % AES_CBC_BLOCK_IV_LENGTH == 0 {
                    assert_eq!(
                        bytes_written, AES_CBC_BLOCK_IV_LENGTH,
                        "Should output complete block"
                    );
                } else {
                    assert_eq!(bytes_written, 0, "Should not output partial blocks");
                }
            }

            assert_eq!(total_written, 32, "Should have written all 32 bytes");

            // Finalize with no remaining data
            let bytes_written = encrypt_stream.finalize(&mut []).unwrap();
            assert_eq!(bytes_written, 0, "No remaining data to finalize");

            // Verify against normal encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, false);
            let mut expected_ct = vec![0u8; 32];
            aes_cbc_compare
                .encrypt(&session, &aes_key, plaintext, &mut expected_ct)
                .expect("Failed comparison encryption");

            assert_eq!(
                ciphertext, expected_ct,
                "Single-byte streaming should match normal encryption"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_large_data() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Large test data - 1024 bytes (64 blocks)
            let plaintext = vec![0xCC; 1024];
            let iv = [0x55; AES_CBC_BLOCK_IV_LENGTH];

            // Test streaming encryption
            let aes_cbc = AesCbcAlgo::new(iv, false);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = vec![0u8; 1024];
            let mut total_written = 0;

            // Process in chunks of 100 bytes
            for chunk_start in (0..1024).step_by(100) {
                let chunk_end = std::cmp::min(chunk_start + 100, 1024);
                let bytes_written = encrypt_stream
                    .update(
                        &plaintext[chunk_start..chunk_end],
                        &mut ciphertext[total_written..],
                    )
                    .expect("Failed to process large chunk");

                total_written += bytes_written;
            }

            // Finalize should return 0 bytes in unpadded mode
            let final_bytes = encrypt_stream
                .finalize(&mut ciphertext[total_written..])
                .expect("Failed to finalize encryption");
            total_written += final_bytes;

            assert_eq!(
                final_bytes, 0,
                "Finalize should return 0 bytes in unpadded mode"
            );
            assert_eq!(total_written, 1024, "Should process all 1024 bytes");

            // Verify with non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, false);
            let mut expected_ct = vec![0u8; 1024];
            aes_cbc_compare
                .encrypt(&session, &aes_key, &plaintext, &mut expected_ct)
                .expect("Failed comparison encryption");

            assert_eq!(
                ciphertext, expected_ct,
                "Large data streaming should match normal encryption"
            );

            // Test streaming decryption - use update() for ALL chunks
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, false);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            let mut decrypted = vec![0u8; 1024];
            let mut total_decrypted = 0;

            // Decrypt in chunks of 80 bytes using update() for all chunks
            for chunk_start in (0..1024).step_by(80) {
                let chunk_end = std::cmp::min(chunk_start + 80, 1024);
                let bytes_written = decrypt_stream
                    .update(
                        &ciphertext[chunk_start..chunk_end],
                        &mut decrypted[total_decrypted..],
                    )
                    .expect("Failed to decrypt chunk");

                total_decrypted += bytes_written;
            }

            // Finalize with no remaining data
            let final_bytes = decrypt_stream
                .finalize(&mut decrypted[total_decrypted..])
                .expect("Failed to finalize decryption");
            total_decrypted += final_bytes;

            assert_eq!(
                final_bytes, 0,
                "Finalize should return 0 bytes in unpadded mode"
            );
            assert_eq!(total_decrypted, 1024, "Should decrypt all 1024 bytes");
            assert_eq!(decrypted, plaintext, "Decrypted data should match original");

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_error_conditions() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            let iv = [0xEE; AES_CBC_BLOCK_IV_LENGTH];

            // Test 1: Finalize without padding when partial data remains
            let aes_cbc = AesCbcAlgo::new(iv, false); // No padding
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            // Add partial block data
            let partial_data = b"12345"; // 5 bytes - not a complete block
            let mut ciphertext = vec![0u8; 16];

            encrypt_stream
                .update(partial_data, &mut ciphertext)
                .expect("Update should succeed"); // No output expected

            // Finalize should fail because we have partial data and no padding
            let result = encrypt_stream.finalize(&mut ciphertext);
            assert!(
                result.is_err(),
                "Finalize should fail with partial data and no padding"
            );

            // Test 2: Decryption with wrong ciphertext length for unpadded mode
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, false); // No padding
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            // Provide non-block-aligned ciphertext (invalid for any mode)
            let bad_ciphertext = vec![0u8; 10]; // 10 bytes - not block-aligned
            let mut plaintext = vec![0u8; 16];

            let result = decrypt_stream.update(&bad_ciphertext, &mut plaintext);
            // This should work in update (it gets buffered), but fail in finalize
            assert!(result.is_ok(), "Update might buffer partial data");

            // Try to add more data to make 1.5 blocks (24 bytes) - should fail in finalize
            let more_bad_data = vec![0u8; 14];
            decrypt_stream
                .update(&more_bad_data, &mut plaintext)
                .expect("Update should buffer data");

            let result = decrypt_stream.finalize(&mut plaintext);
            assert!(
                result.is_err(),
                "Finalize should fail with non-block-aligned data"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }
    }

    // ================================================================================
    // AES CBC PKCS#7 Padded Tests
    // ================================================================================
    mod cbc_pkcs7_padded {
        use crate::crypto::aes::AesCbcAlgo;
        use crate::crypto::aes::AesCbcKey;
        use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
        use crate::crypto::DecryptOp;
        use crate::crypto::EncryptOp;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;
        use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;

        #[test]
        fn test_encrypt_decrypt() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);

            // Generate the key
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - 15 bytes (not block-aligned, will be padded to 16 bytes)
            let plaintext = b"123456789012345"; // 15 bytes
            let expected_ct_len = 16; // Will be padded to 16 bytes
            let mut ciphertext = vec![0u8; expected_ct_len];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Initialize IV
            let iv = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ];

            // Create AES CBC algorithm instance with PKCS#7 padding
            let mut aes_cbc = AesCbcAlgo::new(iv, true);

            // Encrypt the plaintext
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt data with PKCS#7 padding");

            // Verify that ciphertext is different from plaintext
            assert_ne!(
                &ciphertext[..plaintext.len()],
                &plaintext[..],
                "Ciphertext should be different from plaintext"
            );

            // Reset IV for decryption (CBC mode modifies the IV)
            aes_cbc.iv = iv;

            // Decrypt the ciphertext
            aes_cbc
                .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt data with PKCS#7 padding");

            // Verify that decrypted data matches original plaintext
            assert_eq!(
                &decrypted[..],
                &plaintext[..],
                "Decrypted data should match original plaintext"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete AES key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_different_input_sizes() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];

            // Test different input sizes that require different amounts of padding
            let test_cases = vec![
                (b"1".as_slice(), 16),                 // 1 byte -> 16 bytes (15 bytes padding)
                (b"12345".as_slice(), 16),             // 5 bytes -> 16 bytes (11 bytes padding)
                (b"123456789012345".as_slice(), 16),   // 15 bytes -> 16 bytes (1 byte padding)
                (b"1234567890123456".as_slice(), 32),  // 16 bytes -> 32 bytes (16 bytes padding)
                (b"12345678901234567".as_slice(), 32), // 17 bytes -> 32 bytes (15 bytes padding)
            ];

            for (i, (plaintext, expected_ct_len)) in test_cases.into_iter().enumerate() {
                let mut aes_cbc = AesCbcAlgo::new(iv, true);

                // Calculate expected ciphertext length
                let calculated_len = aes_cbc.ciphertext_len(plaintext.len());
                assert_eq!(
                    calculated_len, expected_ct_len,
                    "Test case {}: Expected ciphertext length mismatch",
                    i
                );

                let mut ciphertext = vec![0u8; calculated_len];
                let mut decrypted = vec![0u8; plaintext.len()];

                // Encrypt
                aes_cbc
                    .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                    .unwrap_or_else(|_| panic!("Test case {}: Failed to encrypt", i));

                // Reset IV and decrypt
                aes_cbc.iv = iv;
                aes_cbc
                    .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                    .unwrap_or_else(|_| panic!("Test case {}: Failed to decrypt", i));

                // Verify round-trip
                assert_eq!(
                    &decrypted[..],
                    plaintext,
                    "Test case {}: Round-trip failed",
                    i
                );
            }

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_empty_input() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test empty input - should be padded to 16 bytes
            let plaintext = b"";
            let expected_ct_len = 16; // Empty input gets full block of padding
            let mut ciphertext = vec![0u8; expected_ct_len];
            let mut decrypted = vec![0u8; 0];

            let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
            let mut aes_cbc = AesCbcAlgo::new(iv, true);

            // Encrypt empty input
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt empty input with PKCS#7 padding");

            // Reset IV and decrypt
            aes_cbc.iv = iv;
            aes_cbc
                .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt empty input with PKCS#7 padding");

            // Verify that decrypted data is empty
            assert_eq!(decrypted.len(), 0, "Decrypted empty input should be empty");

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_large_input() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(192)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test large input (1000 bytes)
            let plaintext = vec![0xAB; 1000];
            let expected_blocks = (1000 / 16) + 1; // 62 full blocks + 1 padded block = 63 blocks
            let expected_ct_len = expected_blocks * 16; // 63 * 16 = 1008 bytes

            let iv = [0xCD; AES_CBC_BLOCK_IV_LENGTH];
            let mut aes_cbc = AesCbcAlgo::new(iv, true);

            let calculated_len = aes_cbc.ciphertext_len(plaintext.len()) as usize;
            assert_eq!(calculated_len, expected_ct_len);

            let mut ciphertext = vec![0u8; calculated_len];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Encrypt large input
            aes_cbc
                .encrypt(&session, &aes_key, &plaintext, &mut ciphertext)
                .expect("Failed to encrypt large input with PKCS#7 padding");

            // Reset IV and decrypt
            aes_cbc.iv = iv;
            aes_cbc
                .decrypt(&session, &aes_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt large input with PKCS#7 padding");

            // Verify round-trip
            assert_eq!(
                &decrypted[..],
                &plaintext[..],
                "Large input round-trip failed"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_insufficient_output_buffer() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data that will be padded from 15 to 16 bytes
            let plaintext = b"123456789012345"; // 15 bytes
            let mut small_buffer = vec![0u8; 10]; // Too small for padded output

            let iv = [0u8; AES_CBC_BLOCK_IV_LENGTH];
            let mut aes_cbc = AesCbcAlgo::new(iv, true);

            // Should fail due to insufficient output buffer
            let result = aes_cbc.encrypt(&session, &aes_key, plaintext, &mut small_buffer);
            assert!(result.is_err(), "Should fail with insufficient buffer");
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_unpadded_vs_padded_comparison() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(256)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data that is exactly one block (16 bytes)
            let plaintext = b"1234567890123456"; // Exactly 16 bytes
            let iv = [0x12; AES_CBC_BLOCK_IV_LENGTH];

            // Test unpadded mode
            let mut aes_cbc_unpadded = AesCbcAlgo::new(iv, false);
            let mut ct_unpadded = vec![0u8; 16]; // Same size as input

            aes_cbc_unpadded
                .encrypt(&session, &aes_key, plaintext, &mut ct_unpadded)
                .expect("Failed to encrypt in unpadded mode");

            // Test padded mode
            let mut aes_cbc_padded = AesCbcAlgo::new(iv, true);
            let mut ct_padded = vec![0u8; 32]; // Will be 32 bytes due to padding

            aes_cbc_padded
                .encrypt(&session, &aes_key, plaintext, &mut ct_padded)
                .expect("Failed to encrypt in padded mode");

            // Verify that padded mode produces longer ciphertext
            assert_ne!(
                ct_unpadded.len(),
                ct_padded.len(),
                "Padded and unpadded should produce different lengths"
            );
            assert_eq!(ct_padded.len(), 32, "Padded should be 32 bytes");
            assert_eq!(ct_unpadded.len(), 16, "Unpadded should be 16 bytes");

            // Verify both decrypt correctly
            let mut pt_unpadded = vec![0u8; 16];
            aes_cbc_unpadded.iv = iv;
            aes_cbc_unpadded
                .decrypt(&session, &aes_key, &ct_unpadded, &mut pt_unpadded)
                .expect("Failed to decrypt unpadded");

            let mut pt_padded = vec![0u8; 16];
            aes_cbc_padded.iv = iv;
            aes_cbc_padded
                .decrypt(&session, &aes_key, &ct_padded, &mut pt_padded)
                .expect("Failed to decrypt padded");

            assert_eq!(&pt_unpadded[..], &plaintext[..]);
            assert_eq!(&pt_padded[..], &plaintext[..]);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }
    }

    // ================================================================================
    // AES CBC Streaming (PKCS#7 Padded) Tests
    // ================================================================================
    mod cbc_streaming_pkcs7_padded {
        use crate::crypto::aes::AesCbcAlgo;
        use crate::crypto::aes::AesCbcKey;
        use crate::crypto::aes::AES_CBC_BLOCK_IV_LENGTH;
        use crate::crypto::EncryptOp;
        use crate::crypto::StreamingDecryptOp;
        use crate::crypto::StreamingEncryptOp;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;
        use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;

        #[test]
        fn test_encrypt_basic() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key with 128-bit properties
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test data - 47 bytes (not block-aligned, will be padded)
            let plaintext = b"12345678901234561234567890123456123456789012345";
            let iv = [0x01; AES_CBC_BLOCK_IV_LENGTH];

            // Create streaming algorithm with padding
            let aes_cbc = AesCbcAlgo::new(iv, true);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = [0u8; 48]; // 48 bytes = 3 blocks (padded)
            let mut total_written = 0;

            // Process data in chunks
            let chunks = [16, 16, 15]; // Total: 47 bytes
            let mut offset = 0;

            for chunk_size in chunks {
                let end = offset + chunk_size;
                let bytes_written = encrypt_stream
                    .update(&plaintext[offset..end], &mut ciphertext[total_written..])
                    .expect("Failed to update encrypt stream");
                total_written += bytes_written;
                offset = end;
            }

            // Finalize with padding
            let bytes_written_final = encrypt_stream
                .finalize(&mut ciphertext[total_written..])
                .expect("Failed to finalize encrypt stream");

            total_written += bytes_written_final;
            assert_eq!(total_written, 48, "Should have written 48 bytes (3 blocks)");

            // Verify against non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, true);
            let mut expected_ct = vec![0u8; 48];
            aes_cbc_compare
                .encrypt(&session, &aes_key, plaintext, &mut expected_ct)
                .expect("Failed to encrypt with non-streaming");

            assert_eq!(
                &ciphertext[..total_written],
                &expected_ct[..],
                "Streaming and non-streaming results should match"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_basic() {
            // Create test session using helper
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Create test data and encrypt it first
            let plaintext = b"012345678901234561234567890123456"; // 33 bytes
            let iv: [u8; 16] = [0x55; AES_CBC_BLOCK_IV_LENGTH];

            let mut aes_cbc = AesCbcAlgo::new(iv, true);
            let mut ciphertext = vec![0u8; 48]; // Will be padded to 48 bytes
            aes_cbc
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt");

            // Now test streaming decryption
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, true);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            // Decrypt in chunks - for padded mode, we process all but the last block in update()
            let mut decrypted = [0u8; 48];
            let mut total_written = 0;

            // Process first 32 bytes (2 blocks) with update
            let bytes_written1 = decrypt_stream
                .update(&ciphertext[..32], &mut decrypted[total_written..])
                .expect("Failed to update decrypt stream");
            total_written += bytes_written1;
            println!("Bytes written after first update: {}", total_written);

            // Process remaining 16 bytes (last block) with update
            let bytes_written2 = decrypt_stream
                .update(&ciphertext[32..], &mut decrypted[total_written..])
                .expect("Failed to update decrypt stream");
            total_written += bytes_written2;
            println!("Bytes written after second update: {}", total_written);

            // Finalize with padding removal
            let bytes_written3 = decrypt_stream
                .finalize(&mut decrypted[total_written..])
                .expect("Failed to finalize decrypt stream");
            total_written += bytes_written3;
            println!("Bytes written after finalize: {}", total_written);

            // Verify decrypted data matches original (should be 33 bytes after padding removal)
            assert_eq!(
                total_written, 33,
                "Should have 33 bytes after padding removal"
            );
            assert_eq!(
                &decrypted[..total_written],
                &plaintext[..],
                "Decrypted data should match original plaintext"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_empty_input() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test empty input with padding
            let plaintext = b"";
            let iv = [0x11; AES_CBC_BLOCK_IV_LENGTH];

            let aes_cbc = AesCbcAlgo::new(iv, true);
            let encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = [0u8; 16]; // Should be 16 bytes (one block of padding)

            // No update calls - go directly to finalize
            let bytes_written = encrypt_stream
                .finalize(&mut ciphertext)
                .expect("Failed to finalize empty input");

            assert_eq!(
                bytes_written, 16,
                "Empty input should produce 16 bytes of padding"
            );

            // Verify against non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, true);
            let mut expected_ct = vec![0u8; 16];
            aes_cbc_compare
                .encrypt(&session, &aes_key, plaintext, &mut expected_ct)
                .expect("Failed to encrypt empty input");

            assert_eq!(
                &ciphertext[..],
                &expected_ct[..],
                "Streaming and non-streaming empty input should match"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_empty_result() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // First encrypt empty input to get valid ciphertext
            let plaintext = b"";
            let iv = [0x22; AES_CBC_BLOCK_IV_LENGTH];

            let mut aes_cbc_encrypt = AesCbcAlgo::new(iv, true);
            let mut ciphertext = vec![0u8; 16];
            aes_cbc_encrypt
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt empty input");

            // Now test streaming decryption of the encrypted empty input
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, true);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            let mut decrypted = [0u8; 16];
            let mut total_written = 0;

            // Update with the ciphertext (no bytes should be written yet due to padding handling)
            let bytes_written1 = decrypt_stream
                .update(&ciphertext, &mut decrypted[total_written..])
                .expect("Failed to update decrypt stream");
            total_written += bytes_written1;

            // Finalize should handle padding removal and return empty result
            let bytes_written2 = decrypt_stream
                .finalize(&mut decrypted[total_written..])
                .expect("Failed to finalize decrypt stream");
            total_written += bytes_written2;

            assert_eq!(
                total_written, 0,
                "Decrypting empty input should result in 0 bytes"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_single_byte() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test single byte input
            let plaintext = b"A";
            let iv = [0x33; AES_CBC_BLOCK_IV_LENGTH];

            let aes_cbc = AesCbcAlgo::new(iv, true);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            let mut ciphertext = [0u8; 16]; // Will be padded to 16 bytes
            let mut total_written = 0;

            // Update with single byte
            let bytes_written1 = encrypt_stream
                .update(plaintext, &mut ciphertext[total_written..])
                .expect("Failed to update with single byte");
            total_written += bytes_written1;

            // Should be 0 bytes written (not a complete block yet)
            assert_eq!(
                bytes_written1, 0,
                "Single byte should not produce output yet"
            );

            // Finalize should apply padding and produce one block
            let bytes_written2 = encrypt_stream
                .finalize(&mut ciphertext[total_written..])
                .expect("Failed to finalize single byte");
            total_written += bytes_written2;

            assert_eq!(
                total_written, 16,
                "Single byte should be padded to 16 bytes"
            );

            // Verify against non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, true);
            let mut expected_ct = vec![0u8; 16];
            aes_cbc_compare
                .encrypt(&session, &aes_key, plaintext, &mut expected_ct)
                .expect("Failed to encrypt single byte");

            assert_eq!(
                &ciphertext[..],
                &expected_ct[..],
                "Streaming and non-streaming single byte should match"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_single_byte() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // First encrypt single byte to get valid ciphertext
            let plaintext = b"X";
            let iv = [0x44; AES_CBC_BLOCK_IV_LENGTH];

            let mut aes_cbc_encrypt = AesCbcAlgo::new(iv, true);
            let mut ciphertext = vec![0u8; 16];
            aes_cbc_encrypt
                .encrypt(&session, &aes_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt single byte");

            // Now test streaming decryption
            let aes_cbc_decrypt = AesCbcAlgo::new(iv, true);
            let mut decrypt_stream = session.decrypt_init(&aes_cbc_decrypt, &aes_key).unwrap();

            let mut decrypted = [0u8; 16];
            let mut total_written = 0;

            // Update with ciphertext - should keep last block for finalize
            let bytes_written1 = decrypt_stream
                .update(&ciphertext, &mut decrypted[total_written..])
                .expect("Failed to update decrypt stream");
            total_written += bytes_written1;

            // Should be 0 bytes written (keeping last block for padding removal)
            assert_eq!(bytes_written1, 0, "Should keep last block for finalize");

            // Finalize should decrypt and remove padding
            let bytes_written2 = decrypt_stream
                .finalize(&mut decrypted[total_written..])
                .expect("Failed to finalize decrypt stream");
            total_written += bytes_written2;

            assert_eq!(total_written, 1, "Should have 1 byte after padding removal");
            assert_eq!(
                &decrypted[..total_written],
                plaintext,
                "Decrypted single byte should match original"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_large_data_streaming() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            // Test large data (1000 bytes)
            let plaintext = vec![0xCC; 1000];
            let iv = [0x77; AES_CBC_BLOCK_IV_LENGTH];

            let aes_cbc = AesCbcAlgo::new(iv, true);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            // Calculate expected output size (padded to next 16-byte boundary)
            let expected_size = ((1000 / 16) + 1) * 16; // 1008 bytes
            let mut ciphertext = vec![0u8; expected_size];
            let mut total_written = 0;

            // Process in various chunk sizes
            let chunk_sizes = [100, 200, 300, 150, 250]; // Total: 1000 bytes
            let mut offset = 0;

            for chunk_size in chunk_sizes {
                let end = offset + chunk_size;
                let bytes_written = encrypt_stream
                    .update(&plaintext[offset..end], &mut ciphertext[total_written..])
                    .expect("Failed to update encrypt stream");
                total_written += bytes_written;
                offset = end;
            }

            // Finalize with padding
            let bytes_written_final = encrypt_stream
                .finalize(&mut ciphertext[total_written..])
                .expect("Failed to finalize encrypt stream");
            total_written += bytes_written_final;

            assert_eq!(
                total_written, expected_size,
                "Should have correct padded size"
            );

            // Verify against non-streaming encryption
            let mut aes_cbc_compare = AesCbcAlgo::new(iv, true);
            let mut expected_ct = vec![0u8; expected_size];
            aes_cbc_compare
                .encrypt(&session, &aes_key, &plaintext, &mut expected_ct)
                .expect("Failed to encrypt large data");

            assert_eq!(
                &ciphertext[..total_written],
                &expected_ct[..],
                "Streaming and non-streaming large data should match"
            );

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_error_conditions() {
            // Create test session
            let (_partition, mut session) = create_test_session();

            // Create AES key
            let key_props = KeyProps::builder()
                .bit_len(128)
                .encrypt(true)
                .decrypt(true)
                .build();
            let mut aes_key = AesCbcKey::new(key_props);
            session
                .generate_key(&mut aes_key)
                .expect("Failed to generate AES key");

            let iv = [0x88; AES_CBC_BLOCK_IV_LENGTH];

            // Test 1: Insufficient buffer for complete block output
            let plaintext = b"Test data for error conditions"; // 30 bytes = 1 complete block + 14 partial bytes
            let aes_cbc = AesCbcAlgo::new(iv, true);
            let mut encrypt_stream = session.encrypt_init(&aes_cbc, &aes_key).unwrap();

            // Try to update with insufficient output buffer
            let mut small_buffer = [0u8; 8]; // Too small for 16-byte block output

            // This should FAIL because we need 16 bytes for the complete block output
            let result = encrypt_stream.update(plaintext, &mut small_buffer);
            assert!(
                result.is_err(),
                "Update should fail when output buffer is too small for complete block"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Test 2: Update that only buffers data (no complete blocks)
            let short_plaintext = b"Hello"; // 5 bytes - no complete blocks
            let aes_cbc2 = AesCbcAlgo::new(iv, true);
            let mut encrypt_stream2 = session.encrypt_init(&aes_cbc2, &aes_key).unwrap();

            // This should succeed because no output is produced (just buffering)
            let result = encrypt_stream2.update(short_plaintext, &mut small_buffer);
            assert!(
                result.is_ok(),
                "Update should succeed when only buffering partial data"
            );
            assert_eq!(
                result.unwrap(),
                0,
                "No bytes should be written when buffering"
            );

            // Test 3: Finalize with insufficient buffer for padded output
            let result = encrypt_stream2.finalize(&mut small_buffer);
            assert!(
                result.is_err(),
                "Finalize should fail when buffer is too small for padded output"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Clean up
            session
                .delete_key(&mut aes_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }
    }

    // ================================================================================
    // AES XTS Key Management Tests
    // ================================================================================
    mod xts_key_management {
        use crate::crypto::aes::AesXtsKey;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;
        use crate::AZIHSM_KEY_ALREADY_EXISTS;
        use crate::AZIHSM_KEY_NOT_INITIALIZED;
        use crate::AZIHSM_OPERATION_NOT_SUPPORTED;
        use crate::AZIHSM_UNSUPPORTED_KEY_SIZE;

        #[test]
        fn test_key_gen_512_bit() {
            let (_partition, mut session) = create_test_session();

            // Create AES XTS key with 512-bit properties using builder (for two 256-bit keys)
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            assert!(
                aes_xts_key.id().is_none(),
                "Key ID should be None before generation"
            );

            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            let key_ids = aes_xts_key
                .id()
                .expect("Key IDs should be set after generation");
            assert_ne!(key_ids.0 .0, 0, "First key ID should be non-zero");
            assert_ne!(key_ids.1 .0, 0, "Second key ID should be non-zero");
            assert_ne!(key_ids.0 .0, key_ids.1 .0, "Key IDs should be different");

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete AES XTS keys");

            assert!(
                aes_xts_key.id().is_none(),
                "Key IDs should be None after deletion"
            );

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_gen_invalid_key_size() {
            let (_partition, mut session) = create_test_session();

            // Test invalid key sizes for XTS mode
            let invalid_sizes = vec![128, 192, 256, 1024];

            for invalid_size in invalid_sizes {
                let key_props = KeyProps::builder()
                    .bit_len(invalid_size)
                    .encrypt(true)
                    .decrypt(true)
                    .build();

                let mut aes_xts_key = AesXtsKey::new(key_props);

                let result = session.generate_key(&mut aes_xts_key);
                assert!(
                    result.is_err(),
                    "Key generation should fail for invalid size: {}",
                    invalid_size
                );
                assert_eq!(result.unwrap_err(), AZIHSM_UNSUPPORTED_KEY_SIZE);
            }

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_gen_already_exists() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            session
                .generate_key(&mut aes_xts_key)
                .expect("First key generation should succeed");

            let result = session.generate_key(&mut aes_xts_key);
            assert!(result.is_err(), "Second key generation should fail");
            assert_eq!(result.unwrap_err(), AZIHSM_KEY_ALREADY_EXISTS);

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete AES XTS keys");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_gen_pair_not_supported() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder().bit_len(512).build();
            let mut aes_xts_key = AesXtsKey::new(key_props);

            let result = session.generate_key_pair(&mut aes_xts_key);
            assert!(
                result.is_err(),
                "Key pair generation should not be supported for AES XTS"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_OPERATION_NOT_SUPPORTED);

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_delete_not_initialized() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            let result = session.delete_key(&mut aes_xts_key);
            assert!(result.is_err(), "Delete should fail for uninitialized key");
            assert_eq!(result.unwrap_err(), AZIHSM_KEY_NOT_INITIALIZED);

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_multiple_generation_cycles() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            // Test multiple generate/delete cycles
            for i in 0..3 {
                session
                    .generate_key(&mut aes_xts_key)
                    .unwrap_or_else(|_| panic!("Failed to generate key in cycle {}", i));

                assert!(
                    aes_xts_key.id().is_some(),
                    "Key should be initialized after generation in cycle {}",
                    i
                );

                session
                    .delete_key(&mut aes_xts_key)
                    .unwrap_or_else(|_| panic!("Failed to delete key in cycle {}", i));

                assert!(
                    aes_xts_key.id().is_none(),
                    "Key should be uninitialized after deletion in cycle {}",
                    i
                );
            }

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_individual_deletion() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();
            let mut aes_xts_key = AesXtsKey::new(key_props);

            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            let key_ids = aes_xts_key.id().expect("Key IDs should be set");
            println!(
                "Generated key pair: key1={}, key2={}",
                key_ids.0 .0, key_ids.1 .0
            );

            // Delete both keys (this is what delete_key does for XTS)
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete AES XTS keys");

            // Verify both keys are deleted
            assert!(aes_xts_key.id().is_none(), "Both keys should be deleted");

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_properties_validation() {
            let (_partition, mut session) = create_test_session();

            // Test different property combinations
            let test_cases = vec![
                // Valid case
                (
                    KeyProps::builder()
                        .bit_len(512)
                        .encrypt(true)
                        .decrypt(true)
                        .build(),
                    true,
                ),
                // Valid case - non-exportable
                (
                    KeyProps::builder()
                        .bit_len(512)
                        .encrypt(true)
                        .decrypt(true)
                        .build(),
                    true,
                ),
                // Valid case - with additional properties
                (
                    KeyProps::builder()
                        .bit_len(512)
                        .encrypt(true)
                        .decrypt(true)
                        .build(),
                    true,
                ),
            ];

            for (i, (key_props, should_succeed)) in test_cases.into_iter().enumerate() {
                let mut aes_xts_key = AesXtsKey::new(key_props);

                let result = session.generate_key(&mut aes_xts_key);
                if should_succeed {
                    assert!(
                        result.is_ok(),
                        "Key generation should succeed for test case {}",
                        i
                    );
                    session
                        .delete_key(&mut aes_xts_key)
                        .unwrap_or_else(|_| panic!("Failed to delete key in test case {}", i));
                } else {
                    assert!(
                        result.is_err(),
                        "Key generation should fail for test case {}",
                        i
                    );
                }
            }

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_clone() {
            // Test that AesXtsKey can be cloned properly
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let aes_xts_key = AesXtsKey::new(key_props);
            let cloned_key = aes_xts_key.clone();

            // Both should have the same initial state
            assert_eq!(aes_xts_key.id(), cloned_key.id());
            assert!(aes_xts_key.id().is_none());
            assert!(cloned_key.id().is_none());
        }

        #[test]
        fn test_key_state_consistency() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            // Initial state
            assert!(aes_xts_key.id().is_none(), "Initial state should be None");

            // After generation
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            let initial_key_ids = aes_xts_key.id().expect("Key should be generated");
            assert!(initial_key_ids.0 .0 != 0, "First key ID should be non-zero");
            assert!(
                initial_key_ids.1 .0 != 0,
                "Second key ID should be non-zero"
            );

            // Verify state persists across multiple reads
            for _ in 0..5 {
                let current_key_ids = aes_xts_key.id().expect("Key state should persist");
                assert_eq!(
                    current_key_ids, initial_key_ids,
                    "Key IDs should remain consistent"
                );
            }

            // After deletion
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");

            assert!(
                aes_xts_key.id().is_none(),
                "State should be None after deletion"
            );

            // Verify state persists across multiple reads
            for _ in 0..5 {
                assert!(aes_xts_key.id().is_none(), "Deleted state should persist");
            }

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_generation_uniqueness() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut keys = Vec::new();
            const NUM_KEYS: usize = 5;

            // Generate multiple keys
            for i in 0..NUM_KEYS {
                let mut aes_xts_key = AesXtsKey::new(key_props.clone());
                session
                    .generate_key(&mut aes_xts_key)
                    .unwrap_or_else(|_| panic!("Failed to generate key {}", i));

                let key_ids = aes_xts_key.id().expect("Key should be generated");
                keys.push((aes_xts_key, key_ids));
            }

            // Verify all key IDs are unique
            for i in 0..NUM_KEYS {
                for j in (i + 1)..NUM_KEYS {
                    let (_, key_ids_i) = &keys[i];
                    let (_, key_ids_j) = &keys[j];

                    assert_ne!(
                        key_ids_i.0 .0, key_ids_j.0 .0,
                        "First key ID should be unique between keys {} and {}",
                        i, j
                    );
                    assert_ne!(
                        key_ids_i.1 .0, key_ids_j.1 .0,
                        "Second key ID should be unique between keys {} and {}",
                        i, j
                    );
                    assert_ne!(
                        key_ids_i.0 .0, key_ids_j.1 .0,
                        "Key ID should be unique across all generated keys ({}.0 vs {}.1)",
                        i, j
                    );
                    assert_ne!(
                        key_ids_i.1 .0, key_ids_j.0 .0,
                        "Key ID should be unique across all generated keys ({}.1 vs {}.0)",
                        i, j
                    );
                }
            }

            // Clean up all keys
            for (mut key, _) in keys {
                session
                    .delete_key(&mut key)
                    .expect("Failed to delete key during cleanup");
            }

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_key_error_handling() {
            let (_partition, mut session) = create_test_session();

            // Test invalid bit length
            let invalid_key_props = KeyProps::builder()
                .bit_len(128) // Invalid for XTS
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut invalid_key = AesXtsKey::new(invalid_key_props);

            let result = session.generate_key(&mut invalid_key);
            assert!(result.is_err(), "Should fail with invalid key size");
            assert_eq!(result.unwrap_err(), AZIHSM_UNSUPPORTED_KEY_SIZE);

            // Verify key remains uninitialized after failed generation
            assert!(
                invalid_key.id().is_none(),
                "Key should remain uninitialized after failure"
            );

            // Test deletion of failed key
            let delete_result = session.delete_key(&mut invalid_key);
            assert!(
                delete_result.is_err(),
                "Should fail to delete uninitialized key"
            );
            assert_eq!(delete_result.unwrap_err(), AZIHSM_KEY_NOT_INITIALIZED);

            session.close().expect("Failed to close session");
        }
    }

    // ================================================================================
    // AES XTS One-Shot Crypto Tests
    // ================================================================================
    mod xts_oneshot {
        use crate::crypto::aes::AesXtsAlgo;
        use crate::crypto::aes::AesXtsKey;
        use crate::crypto::DecryptOp;
        use crate::crypto::EncryptOp;
        use crate::test_helpers::create_test_session;
        use crate::types::KeyProps;
        use crate::AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH;
        use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
        use crate::AZIHSM_KEY_NOT_INITIALIZED;

        #[test]
        fn test_encrypt_decrypt() {
            let (_partition, mut session) = create_test_session();

            // Create AES XTS key with 512-bit properties
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);

            // Generate the key
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test data - XTS supports any length >= 16 bytes (minimum one block)
            let plaintext = b"1234567890123456"; // 16 bytes (minimum for XTS)
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Initialize sector number (16 bytes for XTS tweak)
            let sector_num = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ];

            // Create AES XTS algorithm instance
            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Encrypt the plaintext
            aes_xts
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt plaintext");

            // Verify that ciphertext is different from plaintext
            assert_ne!(
                &ciphertext[..],
                &plaintext[..],
                "Ciphertext should be different from plaintext"
            );

            // Decrypt the ciphertext (XTS doesn't modify sector_num like CBC modifies IV)
            aes_xts
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt ciphertext");

            // Verify that decrypted data matches original plaintext
            assert_eq!(
                &decrypted[..],
                &plaintext[..],
                "Decrypted data should match original plaintext"
            );

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete AES XTS key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt_large_data() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test data with multiple blocks (512 bytes = 32 AES blocks)
            let plaintext = vec![0x42u8; 512]; // 512 bytes of 0x42
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            let sector_num = [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20,
            ];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Encrypt large data
            aes_xts
                .encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext)
                .expect("Failed to encrypt large data");

            // Verify encryption changed the data
            assert_ne!(&ciphertext[..], &plaintext[..]);

            // Decrypt large data
            aes_xts
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Failed to decrypt large data");

            // Verify round-trip success
            assert_eq!(&decrypted[..], &plaintext[..]);

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_different_lengths() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test data with different length (should fail)
            let plaintext = b"1234567890123456"; // 16 bytes
            let mut ciphertext = vec![0u8; 8]; // Wrong length - 8 bytes (too small)

            let sector_num = [0u8; 16];
            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Encrypt should fail due to insufficient buffer
            let result = aes_xts.encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext);
            assert!(
                result.is_err(),
                "Encrypt should fail with insufficient buffer"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_decrypt_different_lengths() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test data with different length (should fail)
            let ciphertext = vec![0u8; 16]; // 16 bytes
            let mut plaintext = vec![0u8; 8]; // Wrong length - 8 bytes (too small)

            let sector_num = [0u8; 16];
            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Decrypt should fail due to insufficient buffer
            let result = aes_xts.decrypt(&session, &aes_xts_key, &ciphertext, &mut plaintext);
            assert!(
                result.is_err(),
                "Decrypt should fail with insufficient buffer"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt_larger_buffers() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test data - 64 bytes
            let plaintext = b"This is test data for AES XTS with larger buffers to verify prop"; // 64 bytes
            let mut ciphertext = vec![0u8; 128]; // Larger buffer (128 bytes)
            let mut decrypted = vec![0u8; 96]; // Larger buffer (96 bytes)

            let sector_num = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30,
            ];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Encrypt with larger buffer - should succeed
            let encrypted_len = aes_xts
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext)
                .expect("Failed to encrypt with larger buffer");

            // Verify encrypted length equals original plaintext length
            assert_eq!(encrypted_len, plaintext.len());

            // Verify that only the first 64 bytes contain encrypted data
            assert_ne!(
                &ciphertext[..plaintext.len()],
                &plaintext[..],
                "Encrypted data should be different from plaintext"
            );

            // Decrypt with larger buffer - should succeed
            let decrypted_len = aes_xts
                .decrypt(
                    &session,
                    &aes_xts_key,
                    &ciphertext[..encrypted_len],
                    &mut decrypted,
                )
                .expect("Failed to decrypt with larger buffer");

            // Verify decrypted length equals original plaintext length
            assert_eq!(decrypted_len, plaintext.len());

            // Verify that decrypted data matches original plaintext
            assert_eq!(
                &decrypted[..decrypted_len],
                &plaintext[..],
                "Decrypted data should match original plaintext"
            );

            // Verify that unused buffer space remains unchanged (zeros in this case)
            assert_eq!(
                &ciphertext[encrypted_len..],
                &vec![0u8; ciphertext.len() - encrypted_len][..],
                "Unused ciphertext buffer should remain zero"
            );

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt_not_initialized() {
            let (_partition, mut session) = create_test_session();

            // Create AES XTS key but don't generate it
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let aes_xts_key = AesXtsKey::new(key_props);

            let plaintext = b"1234567890123456";
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted_buf = vec![0u8; plaintext.len()];

            let sector_num = [0u8; 16];
            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // Encrypt should fail - key not initialized
            let result = aes_xts.encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext);
            assert!(
                result.is_err(),
                "Encrypt should fail with uninitialized key"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_KEY_NOT_INITIALIZED);

            // Decrypt should also fail - key not initialized
            let result = aes_xts.decrypt(&session, &aes_xts_key, plaintext, &mut decrypted_buf);
            assert!(
                result.is_err(),
                "Decrypt should fail with uninitialized key"
            );
            assert_eq!(result.unwrap_err(), AZIHSM_KEY_NOT_INITIALIZED);

            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt_different_sector_numbers() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            let plaintext = b"1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes
            let mut ciphertext1 = vec![0u8; plaintext.len()];
            let mut ciphertext2 = vec![0u8; plaintext.len()];

            // Test with different sector numbers
            let sector_num1 = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ];
            let sector_num2 = [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20,
            ];

            let mut aes_xts1 = AesXtsAlgo {
                sector_num: sector_num1,
                data_unit_len: None,
            };
            let mut aes_xts2 = AesXtsAlgo {
                sector_num: sector_num2,
                data_unit_len: None,
            };

            // Encrypt with sector number 1
            aes_xts1
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext1)
                .expect("Failed to encrypt with sector number 1");

            // Encrypt with sector number 2
            aes_xts2
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext2)
                .expect("Failed to encrypt with sector number 2");

            // Ciphertexts should be different due to different sector numbers (tweaks)
            assert_ne!(
                &ciphertext1[..],
                &ciphertext2[..],
                "Different sector numbers should produce different ciphertexts"
            );

            // Both should be different from plaintext
            assert_ne!(&ciphertext1[..], &plaintext[..]);
            assert_ne!(&ciphertext2[..], &plaintext[..]);

            // Decrypt with correct sector numbers
            let mut decrypted1 = vec![0u8; plaintext.len()];
            let mut decrypted2 = vec![0u8; plaintext.len()];

            aes_xts1
                .decrypt(&session, &aes_xts_key, &ciphertext1, &mut decrypted1)
                .expect("Failed to decrypt with sector number 1");

            aes_xts2
                .decrypt(&session, &aes_xts_key, &ciphertext2, &mut decrypted2)
                .expect("Failed to decrypt with sector number 2");

            // Both should decrypt to original plaintext
            assert_eq!(&decrypted1[..], &plaintext[..]);
            assert_eq!(&decrypted2[..], &plaintext[..]);

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_encrypt_decrypt_various_sizes() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            // Test various data sizes that are valid for XTS (>= 16 bytes)
            let test_sizes = vec![16, 32, 48, 64, 128, 256, 1024];

            for size in test_sizes {
                let plaintext = vec![0x55u8; size];
                let mut ciphertext = vec![0u8; size];
                let mut decrypted = vec![0u8; size];

                let sector_num = [
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
                    0x3E, 0x3F, 0x40,
                ];

                let mut aes_xts = AesXtsAlgo {
                    sector_num,
                    data_unit_len: None,
                };

                // Test encryption
                let encrypted_len = aes_xts
                    .encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext)
                    .unwrap_or_else(|_| panic!("Failed to encrypt {} bytes", size));

                assert_eq!(
                    encrypted_len, size,
                    "Encrypted length should equal input size for {} bytes",
                    size
                );
                assert_ne!(
                    &ciphertext[..],
                    &plaintext[..],
                    "Ciphertext should be different from plaintext for {} bytes",
                    size
                );

                // Test decryption
                let decrypted_len = aes_xts
                    .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                    .unwrap_or_else(|_| panic!("Failed to decrypt {} bytes", size));

                assert_eq!(
                    decrypted_len, size,
                    "Decrypted length should equal original size for {} bytes",
                    size
                );
                assert_eq!(
                    &decrypted[..],
                    &plaintext[..],
                    "Decrypted data should match original for {} bytes",
                    size
                );
            }

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_ciphertext_plaintext_len() {
            // Test that length calculation methods work correctly
            let sector_num = [0u8; 16];
            let aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };

            // For XTS, ciphertext length equals plaintext length
            assert_eq!(aes_xts.ciphertext_len(16), 16);
            assert_eq!(aes_xts.ciphertext_len(32), 32);
            assert_eq!(aes_xts.ciphertext_len(64), 64);
            assert_eq!(aes_xts.ciphertext_len(1024), 1024);

            assert_eq!(aes_xts.plaintext_len(16), 16);
            assert_eq!(aes_xts.plaintext_len(32), 32);
            assert_eq!(aes_xts.plaintext_len(64), 64);
            assert_eq!(aes_xts.plaintext_len(1024), 1024);
        }

        #[test]
        fn test_sector_number_consistency() {
            let (_partition, mut session) = create_test_session();

            // Create and generate AES XTS key
            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate AES XTS key");

            let plaintext =
                b"This is a test message for XTS mode encryption and decryption testing. Done!!!!!"; // 80 bytes
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            // Test that same sector number produces consistent results
            let sector_num = [
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
                0x4F, 0x50,
            ];

            // First encryption
            let mut aes_xts1 = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };
            aes_xts1
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext)
                .expect("Failed first encryption");

            // Second encryption with same sector number
            let mut ciphertext2 = vec![0u8; plaintext.len()];
            let mut aes_xts2 = AesXtsAlgo {
                sector_num,
                data_unit_len: None,
            };
            aes_xts2
                .encrypt(&session, &aes_xts_key, plaintext, &mut ciphertext2)
                .expect("Failed second encryption");

            // Results should be identical
            assert_eq!(
                &ciphertext[..],
                &ciphertext2[..],
                "Same sector number should produce identical results"
            );

            // Decrypt and verify
            aes_xts1
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Failed decryption");

            assert_eq!(&decrypted[..], &plaintext[..]);

            // Clean up
            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_data_unit_len_512() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            let plaintext = vec![0xCD; 1024]; // Two data units of 512 bytes each
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            let sector_num = [0x02; 16];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(512),
            };

            aes_xts
                .encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext)
                .expect("Encryption should succeed with data_unit_len=512");

            aes_xts
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Decryption should succeed with data_unit_len=512");

            assert_eq!(&decrypted[..], &plaintext[..]);

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_data_unit_len_4096() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            let plaintext = vec![0xEF; 4096 * 4]; // Four data units of 4096 bytes each
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            let sector_num = [0x03; 16];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(4096),
            };

            aes_xts
                .encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext)
                .expect("Encryption should succeed with data_unit_len=4096");

            aes_xts
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Decryption should succeed with data_unit_len=4096");

            assert_eq!(&decrypted[..], &plaintext[..]);

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_data_unit_len_8192() {
            // Test with data_unit_len = 8192 bytes
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            let plaintext = vec![0x12; 8192 * 3]; // Three data units of 8192 bytes each
            let mut ciphertext = vec![0u8; plaintext.len()];
            let mut decrypted = vec![0u8; plaintext.len()];

            let sector_num = [0x04; 16];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(8192),
            };

            aes_xts
                .encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext)
                .expect("Encryption should succeed with data_unit_len=8192");

            aes_xts
                .decrypt(&session, &aes_xts_key, &ciphertext, &mut decrypted)
                .expect("Decryption should succeed with data_unit_len=8192");

            assert_eq!(&decrypted[..], &plaintext[..]);

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_data_unit_len_invalid() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            let plaintext = vec![0x34; 1024]; // 1024 bytes
            let mut ciphertext = vec![0u8; plaintext.len()];

            let sector_num = [0x05; 16];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(2048), // Invalid: not equal to plaintext length and not 512/4096/8192
            };

            let result = aes_xts.encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext);
            assert!(result.is_err(), "Should fail with invalid data_unit_len");
            assert_eq!(result.unwrap_err(), AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH);

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }

        #[test]
        fn test_data_unit_len_not_multiple_of_plaintext() {
            let (_partition, mut session) = create_test_session();

            let key_props = KeyProps::builder()
                .bit_len(512)
                .encrypt(true)
                .decrypt(true)
                .build();

            let mut aes_xts_key = AesXtsKey::new(key_props);
            session
                .generate_key(&mut aes_xts_key)
                .expect("Failed to generate key");

            // Plaintext is 4097 bytes
            let plaintext = vec![0xAB; 4096 + 1]; // Not a multiple of 4096
            let mut ciphertext = vec![0u8; plaintext.len()];

            let sector_num = [0x06; 16];

            let mut aes_xts = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(4096), // Standard size, but plaintext is not a multiple
            };

            let result = aes_xts.encrypt(&session, &aes_xts_key, &plaintext, &mut ciphertext);
            assert!(
                result.is_err(),
                "Should fail when plaintext is not a multiple of data_unit_len"
            );

            // Plaintext is 513 bytes
            let plaintext2 = vec![0xCD; 512 + 1]; // Not a multiple of 512
            let mut ciphertext2 = vec![0u8; plaintext2.len()];

            let mut aes_xts2 = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(512),
            };

            let result2 = aes_xts2.encrypt(&session, &aes_xts_key, &plaintext2, &mut ciphertext2);
            assert!(
                result2.is_err(),
                "Should fail when plaintext (1000 bytes) is not a multiple of data_unit_len (512)"
            );

            // Plaintext is 8097 bytes
            let plaintext3 = vec![0xCD; 8096 + 1]; // Not a multiple of 8096
            let mut ciphertext3 = vec![0u8; plaintext3.len()];

            let mut aes_xts3 = AesXtsAlgo {
                sector_num,
                data_unit_len: Some(8096),
            };

            let result3 = aes_xts3.encrypt(&session, &aes_xts_key, &plaintext3, &mut ciphertext3);
            assert!(
                result3.is_err(),
                "Should fail when plaintext (8097 bytes) is not a multiple of data_unit_len (8096)"
            );

            session
                .delete_key(&mut aes_xts_key)
                .expect("Failed to delete key");
            session.close().expect("Failed to close session");
        }
    }
}
