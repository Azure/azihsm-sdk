// Copyright (C) Microsoft Corporation. All rights reserved.

#[cfg(test)]
mod tests {
    use crate::crypto::sha::ShaAlgo;
    use crate::crypto::DigestOp;
    use crate::crypto::StreamingDigestOp;
    use crate::session::test_helpers::create_test_session;
    use crate::types::AlgoId;
    use crate::AZIHSM_ALGORITHM_NOT_SUPPORTED;
    use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;

    #[test]
    fn test_sha_digest_len() {
        let test_cases = [
            (AlgoId::Sha1, 20, "SHA1"),
            (AlgoId::Sha256, 32, "SHA256"),
            (AlgoId::Sha384, 48, "SHA384"),
            (AlgoId::Sha512, 64, "SHA512"),
        ];

        for (algo_id, expected_len, algo_name) in test_cases {
            let sha_algo = ShaAlgo { algo: algo_id };
            let result = sha_algo
                .digest_len()
                .unwrap_or_else(|_| panic!("digest_len should succeed for {}", algo_name));
            assert_eq!(
                result, expected_len,
                "{} digest length should be {} bytes",
                algo_name, expected_len
            );
        }
    }

    #[test]
    fn test_unsupported_algo_digest_len() {
        let sha_algo = ShaAlgo {
            algo: AlgoId::AesCbc,
        };

        let result = sha_algo.digest_len();
        assert!(
            result.is_err(),
            "digest_len should fail for unsupported algorithm"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_ALGORITHM_NOT_SUPPORTED,
            "Should return AZIHSM_ALGORITHM_NOT_SUPPORTED for unsupported algorithm"
        );
    }

    #[test]
    fn test_sha_digest_with_known_values() {
        let (_partition, session) = create_test_session();

        // Test cases with known input "abc" and expected outputs
        let test_cases = [
            (
                AlgoId::Sha1,
                20,
                "SHA1",
                // Expected SHA1 of "abc": a9993e364706816aba3e25717850c26c9cd0d89d
                vec![
                    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
                    0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
                ],
            ),
            (
                AlgoId::Sha256,
                32,
                "SHA256",
                // Expected SHA256 of "abc": ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
                vec![
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
            ),
            (
                AlgoId::Sha384,
                48,
                "SHA384",
                // Expected SHA384 of "abc": cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
                vec![
                    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a,
                    0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b,
                    0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc,
                    0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
                ],
            ),
            (
                AlgoId::Sha512,
                64,
                "SHA512",
                // Expected SHA512 of "abc": ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
                vec![
                    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
                    0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
                    0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
                    0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
                    0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
                ],
            ),
        ];

        let message = b"abc";

        for (algo_id, digest_len, algo_name, expected) in test_cases {
            let mut sha_algo = ShaAlgo { algo: algo_id };
            let mut digest = vec![0u8; digest_len];

            let result = sha_algo.digest(&session, message, &mut digest);
            assert!(result.is_ok(), "{} digest should succeed", algo_name);
            assert_eq!(
                digest, expected,
                "{} digest should match expected value",
                algo_name
            );
        }
    }

    #[test]
    fn test_unsupported_algo_digest() {
        let (_partition, session) = create_test_session();
        let mut sha_algo = ShaAlgo {
            algo: AlgoId::AesCbc,
        };

        let message = b"test";
        let mut digest = vec![0u8; 32];

        let result = sha_algo.digest(&session, message, &mut digest);
        assert!(
            result.is_err(),
            "digest should fail for unsupported algorithm"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_ALGORITHM_NOT_SUPPORTED,
            "Should return AZIHSM_ALGORITHM_NOT_SUPPORTED for unsupported algorithm"
        );
    }

    #[test]
    fn test_sha256_insufficient_buffer() {
        let (_partition, session) = create_test_session();
        let mut sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        let message = b"test";
        let mut digest = vec![0u8; 16]; // Too small buffer (SHA256 needs 32 bytes)

        let result = sha_algo.digest(&session, message, &mut digest);
        assert!(
            result.is_err(),
            "digest should fail with insufficient buffer"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_ERROR_INSUFFICIENT_BUFFER,
            "Should return AZIHSM_ERROR_INSUFFICIENT_BUFFER for too small buffer"
        );
    }

    #[test]
    fn test_empty_message_digest() {
        let (_partition, session) = create_test_session();
        let mut sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Test with empty message
        let message = b"";
        let mut digest = vec![0u8; 32];

        let result = sha_algo.digest(&session, message, &mut digest);
        assert!(
            result.is_ok(),
            "SHA256 digest should succeed with empty message"
        );

        // Verify the digest is the expected SHA256 of empty string
        // Expected SHA256 of "": e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            digest, expected,
            "SHA256 digest of empty string should match expected value"
        );
    }

    #[test]
    fn test_large_message_digest() {
        let (_partition, session) = create_test_session();
        let mut sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Test with larger message (1KB of 'a's)
        let message = vec![b'a'; 1024];
        let mut digest = vec![0u8; 32];

        let result = sha_algo.digest(&session, &message, &mut digest);
        assert!(
            result.is_ok(),
            "SHA256 digest should succeed with large message"
        );

        // The digest should be computed correctly for the large input
        // We don't verify the exact value here since it's less commonly known,
        // but we ensure the operation completes successfully
        assert_ne!(digest, vec![0u8; 32], "Digest should not be all zeros");
    }

    #[test]
    fn test_sha_streaming_digest_all_algorithms() {
        let (_partition, session) = create_test_session();

        let test_cases = [
            (AlgoId::Sha1, 20, "SHA1"),
            (AlgoId::Sha256, 32, "SHA256"),
            (AlgoId::Sha384, 48, "SHA384"),
            (AlgoId::Sha512, 64, "SHA512"),
        ];

        for (algo_id, expected_len, algo_name) in test_cases {
            let sha_algo = ShaAlgo { algo: algo_id };

            // Streaming digest
            let mut digest_stream = session
                .digest_init(&sha_algo)
                .unwrap_or_else(|_| panic!("Failed to init {} digest stream", algo_name));

            let message = b"Test message for streaming digest";
            digest_stream
                .update(message)
                .unwrap_or_else(|_| panic!("Failed to update {} digest stream", algo_name));

            let mut digest = vec![0u8; expected_len];
            digest_stream
                .finalize(&mut digest)
                .unwrap_or_else(|_| panic!("Failed to finalize {} digest stream", algo_name));

            // Non-streaming digest for comparison
            let mut sha_algo_non_streaming = ShaAlgo { algo: algo_id };
            let mut expected_digest = vec![0u8; expected_len];
            sha_algo_non_streaming
                .digest(&session, message, &mut expected_digest)
                .unwrap_or_else(|_| panic!("Failed non-streaming {} digest", algo_name));

            assert_eq!(
                digest, expected_digest,
                "{} streaming and non-streaming digests should match",
                algo_name
            );
        }
    }

    #[test]
    fn test_sha_streaming_digest_empty_message() {
        let (_partition, session) = create_test_session();
        let sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Initialize digest stream
        let digest_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init digest stream");

        // Don't call update - finalize immediately with empty data
        let mut digest = vec![0u8; 32];
        digest_stream
            .finalize(&mut digest)
            .expect("Failed to finalize with empty message");

        // Verify against expected SHA256 of empty string
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            digest, expected,
            "SHA-256 digest of empty message should match expected value"
        );
    }

    #[test]
    fn test_sha_streaming_digest_large_message() {
        let (_partition, session) = create_test_session();
        let sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Initialize digest stream
        let mut digest_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init digest stream");

        // Update with large message in chunks
        let chunk_size = 1024;
        let num_chunks = 1024; // 1MB total
        for i in 0..num_chunks {
            let chunk = vec![(i % 256) as u8; chunk_size];
            digest_stream
                .update(&chunk)
                .expect("Failed to update with large chunk");
        }

        // Finalize
        let mut digest = vec![0u8; 32];
        digest_stream
            .finalize(&mut digest)
            .expect("Failed to finalize large message digest");

        // Verify against non-streaming version
        let mut sha_algo_non_streaming = ShaAlgo {
            algo: AlgoId::Sha256,
        };
        let mut large_message = Vec::new();
        for i in 0..num_chunks {
            large_message.extend(vec![(i % 256) as u8; chunk_size]);
        }
        let mut expected_digest = vec![0u8; 32];
        sha_algo_non_streaming
            .digest(&session, &large_message, &mut expected_digest)
            .expect("Failed non-streaming large message digest");

        assert_eq!(
            digest, expected_digest,
            "Large message digests should match"
        );
    }

    #[test]
    fn test_sha_streaming_digest_multiple_small_updates() {
        let (_partition, session) = create_test_session();
        let sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Initialize digest stream
        let mut digest_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init digest stream");

        // Update with many small chunks (single bytes)
        let message = b"abcdefghijklmnopqrstuvwxyz";
        for &byte in message.iter() {
            digest_stream
                .update(&[byte])
                .expect("Failed to update with single byte");
        }

        // Finalize
        let mut digest = vec![0u8; 32];
        digest_stream
            .finalize(&mut digest)
            .expect("Failed to finalize digest");

        // Verify against non-streaming version
        let mut sha_algo_non_streaming = ShaAlgo {
            algo: AlgoId::Sha256,
        };
        let mut expected_digest = vec![0u8; 32];
        sha_algo_non_streaming
            .digest(&session, message, &mut expected_digest)
            .expect("Failed non-streaming digest");

        assert_eq!(
            digest, expected_digest,
            "Multiple small update digests should match"
        );
    }

    #[test]
    fn test_sha_streaming_digest_insufficient_buffer() {
        let (_partition, session) = create_test_session();
        let sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        // Initialize digest stream
        let mut digest_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init digest stream");

        digest_stream
            .update(b"Test message")
            .expect("Failed to update");

        // Try to finalize with insufficient buffer
        let mut small_digest = vec![0u8; 16]; // Too small for SHA-256

        let result = digest_stream.finalize(&mut small_digest);
        assert!(
            result.is_err(),
            "Finalize should fail with insufficient buffer"
        );
        assert_eq!(
            result.unwrap_err(),
            AZIHSM_ERROR_INSUFFICIENT_BUFFER,
            "Should return AZIHSM_ERROR_INSUFFICIENT_BUFFER"
        );
    }

    #[test]
    fn test_sha_streaming_digest_len() {
        let (_partition, session) = create_test_session();

        let test_cases = [
            (AlgoId::Sha1, 20, "SHA1"),
            (AlgoId::Sha256, 32, "SHA256"),
            (AlgoId::Sha384, 48, "SHA384"),
            (AlgoId::Sha512, 64, "SHA512"),
        ];

        for (algo_id, expected_len, algo_name) in test_cases {
            let sha_algo = ShaAlgo { algo: algo_id };

            let digest_stream = session
                .digest_init(&sha_algo)
                .unwrap_or_else(|_| panic!("Failed to init {} digest stream", algo_name));

            let digest_len = digest_stream.digest_len();
            assert_eq!(
                digest_len, expected_len,
                "{} digest length should be {} bytes",
                algo_name, expected_len
            );
        }
    }

    #[test]
    fn test_sha_streaming_vs_non_streaming_consistency() {
        let (_partition, session) = create_test_session();

        let test_messages = [
            b"" as &[u8],
            b"a",
            b"abc",
            b"message digest",
            b"abcdefghijklmnopqrstuvwxyz",
            b"The quick brown fox jumps over the lazy dog",
        ];

        let test_algos = [
            (AlgoId::Sha1, 20),
            (AlgoId::Sha256, 32),
            (AlgoId::Sha384, 48),
            (AlgoId::Sha512, 64),
        ];

        for (algo_id, digest_len) in test_algos {
            for message in &test_messages {
                // Streaming digest
                let sha_algo = ShaAlgo { algo: algo_id };
                let mut digest_stream = session
                    .digest_init(&sha_algo)
                    .expect("Failed to init digest stream");
                digest_stream.update(message).expect("Failed to update");
                let mut streaming_digest = vec![0u8; digest_len];
                digest_stream
                    .finalize(&mut streaming_digest)
                    .expect("Failed to finalize");

                // Non-streaming digest
                let mut sha_algo_non_streaming = ShaAlgo { algo: algo_id };
                let mut non_streaming_digest = vec![0u8; digest_len];
                sha_algo_non_streaming
                    .digest(&session, message, &mut non_streaming_digest)
                    .expect("Failed non-streaming digest");

                assert_eq!(
                    streaming_digest, non_streaming_digest,
                    "Streaming and non-streaming digests should match for {:?}",
                    algo_id
                );
            }
        }
    }

    #[test]
    fn test_sha_streaming_digest_chunked_vs_whole() {
        let (_partition, session) = create_test_session();
        let sha_algo = ShaAlgo {
            algo: AlgoId::Sha256,
        };

        let message = b"The quick brown fox jumps over the lazy dog";

        // Stream with multiple chunks
        let mut chunked_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init chunked stream");
        for chunk in message.chunks(5) {
            chunked_stream
                .update(chunk)
                .expect("Failed to update chunked stream");
        }
        let mut chunked_digest = vec![0u8; 32];
        chunked_stream
            .finalize(&mut chunked_digest)
            .expect("Failed to finalize chunked stream");

        // Stream with whole message
        let mut whole_stream = session
            .digest_init(&sha_algo)
            .expect("Failed to init whole stream");
        whole_stream
            .update(message)
            .expect("Failed to update whole stream");
        let mut whole_digest = vec![0u8; 32];
        whole_stream
            .finalize(&mut whole_digest)
            .expect("Failed to finalize whole stream");

        assert_eq!(
            chunked_digest, whole_digest,
            "Chunked and whole message digests should match"
        );
    }
}
