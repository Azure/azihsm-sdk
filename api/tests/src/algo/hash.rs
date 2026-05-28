// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

// ================================
// Helpers
// ================================

/// Hashes data in one shot and verifies the digest matches the expected bytes.
fn hash_and_compare_single_shot(
    session: HsmSession,
    algo: &mut HsmHashAlgo,
    data: &[u8],
    expected: &[u8],
) {
    let hash = HsmHasher::hash_vec(&session, algo, data).expect("Hashing failed");
    assert_eq!(hash, expected);
}

/// Hashes data through streaming updates and verifies the digest matches the expected bytes.
fn hash_and_compare_streaming(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
    expected: &[u8],
    chunk_sizes: &[usize],
) {
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");

    if chunk_sizes.is_empty() {
        hasher.update(data).expect("Failed to update hasher");
    } else {
        let non_zero_chunk_sizes: Vec<usize> = chunk_sizes
            .iter()
            .copied()
            .filter(|&size| size > 0)
            .collect();

        assert!(
            !non_zero_chunk_sizes.is_empty() || data.is_empty(),
            "chunk_sizes must contain at least one non-zero size for non-empty data"
        );

        if chunk_sizes.contains(&0) {
            hasher
                .update(b"")
                .expect("Failed to update hasher with empty chunk");
        }

        let mut offset = 0;
        let mut i = 0;

        while offset < data.len() {
            let size =
                non_zero_chunk_sizes[i % non_zero_chunk_sizes.len()].min(data.len() - offset);

            let chunk = &data[offset..offset + size];
            hasher.update(chunk).expect("Failed to update hasher");

            offset += size;
            i += 1;
        }
    }

    let hash = hasher.finish_vec().expect("Failed to finalize hash");

    assert_eq!(hash, expected);
}

/// Verifies single-shot hashing fails when the output buffer is too small.
fn buffer_too_small_single_shot(session: HsmSession, algo: &mut HsmHashAlgo, data: &[u8]) {
    let output_size =
        HsmHasher::hash(&session, algo, data, None).expect("Failed to query hash size");
    let mut too_small = vec![0u8; output_size - 1];
    let result = HsmHasher::hash(&session, algo, data, Some(too_small.as_mut_slice()));
    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Verifies streaming hashing fails when the output buffer is too small.
fn buffer_too_small_streaming(session: HsmSession, algo: HsmHashAlgo, data: &[u8]) {
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");
    for part in data.chunks(8) {
        hasher.update(part).expect("Failed to update hasher");
    }
    let output_size = hasher.finish(None).expect("Failed to query hash size");
    let mut too_small = vec![0u8; output_size - 1];
    let result = hasher.finish(Some(too_small.as_mut_slice()));
    assert!(matches!(result, Err(HsmError::InternalError)));
}

/// Compares a single-shot digest against a streaming digest using the given chunk sizes.
fn compare_single_shot_vs_streaming(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
    chunk_sizes: &[usize],
) {
    let single_shot =
        HsmHasher::hash_vec(&session, &mut algo, data).expect("Single-shot hashing failed");

    hash_and_compare_streaming(session, algo, data, &single_shot, chunk_sizes);
}

/// Verifies block-boundary input lengths produce matching single-shot and streaming digests.
fn assert_hash_block_boundary_inputs_match_streaming(
    session: HsmSession,
    algo: HsmHashAlgo,
    lengths: &[usize],
) {
    for &len in lengths {
        let data = vec![0xA5; len];

        compare_single_shot_vs_streaming(session.clone(), algo, &data, &[1, 3, 7, 16, 31, 64, 128]);
    }
}

/// Verifies single-shot hashing remains reusable after a too-small output buffer failure.
fn assert_single_shot_failed_small_buffer_does_not_poison_algo(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
) {
    let expected =
        HsmHasher::hash_vec(&session, &mut algo, data).expect("initial hash_vec should succeed");

    let mut too_small = vec![0u8; expected.len() - 1];
    let result = HsmHasher::hash(&session, &mut algo, data, Some(too_small.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for too-small output buffer, got {:?}",
        result
    );

    let actual =
        HsmHasher::hash_vec(&session, &mut algo, data).expect("hash_vec should still succeed");

    assert_eq!(
        actual, expected,
        "single-shot algo should remain reusable after failed small-buffer hash"
    );
}

/// Verifies different messages produce different digest outputs.
fn assert_hash_different_messages_produce_different_digests(
    session: HsmSession,
    mut algo: HsmHashAlgo,
) {
    let digest_1 =
        HsmHasher::hash_vec(&session, &mut algo, b"message one").expect("hash_vec should succeed");
    let digest_2 =
        HsmHasher::hash_vec(&session, &mut algo, b"message two").expect("hash_vec should succeed");

    assert_ne!(
        digest_1, digest_2,
        "different messages should not produce the same digest"
    );
}

/// Verifies byte-by-byte streaming produces the same digest as single-shot hashing.
fn assert_streaming_one_byte_at_a_time_matches_single_shot(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut algo_for_single_shot = algo;
    let expected = HsmHasher::hash_vec(&session, &mut algo_for_single_shot, data)
        .expect("single-shot hash should succeed");

    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    for byte in data {
        hasher
            .update(&[*byte])
            .expect("one-byte update should succeed");
    }

    let actual = hasher.finish_vec().expect("finish_vec should succeed");

    assert_eq!(actual, expected);
}

/// Verifies hash size query returns the same length as hash_vec output.
fn assert_hash_size_query_matches_vec(session: HsmSession, mut algo: HsmHashAlgo, data: &[u8]) {
    let output_size =
        HsmHasher::hash(&session, &mut algo, data, None).expect("hash size query should succeed");

    let digest = HsmHasher::hash_vec(&session, &mut algo, data).expect("hash_vec should succeed");

    assert_eq!(
        output_size,
        digest.len(),
        "hash size query should match digest length"
    );
}

/// Verifies hashing succeeds with an exact-size output buffer.
fn assert_hash_exact_output_buffer_succeeds(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
) {
    let expected = HsmHasher::hash_vec(&session, &mut algo, data).expect("hash_vec should succeed");

    let mut output = vec![0u8; expected.len()];
    let written = HsmHasher::hash(&session, &mut algo, data, Some(output.as_mut_slice()))
        .expect("hash with exact-size output buffer should succeed");

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

/// Verifies hashing with an oversized output buffer either succeeds without
/// overwriting extra bytes, or returns the backend-specific InternalError.
fn assert_hash_oversized_output_buffer_succeeds_or_returns_internal_error(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
) {
    let expected = HsmHasher::hash_vec(&session, &mut algo, data).expect("hash_vec should succeed");

    let sentinel = 0xAA;
    let mut output = vec![sentinel; expected.len() + 16];

    let result = HsmHasher::hash(&session, &mut algo, data, Some(output.as_mut_slice()));

    match result {
        Ok(written) => {
            assert_eq!(written, expected.len());
            assert_eq!(&output[..expected.len()], expected.as_slice());

            assert!(
                output[expected.len()..].iter().all(|&b| b == sentinel),
                "oversized output buffer tail should remain unchanged after written digest bytes"
            );
        }
        Err(err) => {
            assert!(
                matches!(err, HsmError::InternalError),
                "expected oversized output buffer to either succeed or return InternalError, got {:?}",
                err
            );
        }
    }
}

/// Verifies explicit empty streaming updates do not change the final digest.
fn assert_streaming_empty_updates_match_single_shot(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut algo_for_single_shot = algo;
    let expected = HsmHasher::hash_vec(&session, &mut algo_for_single_shot, data)
        .expect("single-shot hash should succeed");

    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    hasher
        .update(b"")
        .expect("leading empty update should succeed");

    let mid = data.len() / 2;
    hasher
        .update(&data[..mid])
        .expect("first update should succeed");
    hasher
        .update(b"")
        .expect("middle empty update should succeed");
    hasher
        .update(&data[mid..])
        .expect("second update should succeed");

    hasher
        .update(b"")
        .expect("trailing empty update should succeed");

    let actual = hasher.finish_vec().expect("finish_vec should succeed");

    assert_eq!(actual, expected);
}

/// Verifies streaming finish size query followed by output retrieval returns the correct digest.
fn assert_streaming_size_query_then_finish_matches_single_shot(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut algo_for_single_shot = algo;
    let expected = HsmHasher::hash_vec(&session, &mut algo_for_single_shot, data)
        .expect("single-shot hash should succeed");

    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    for part in data.chunks(7) {
        hasher.update(part).expect("update should succeed");
    }

    let output_size = hasher
        .finish(None)
        .expect("finish size query should succeed");
    assert_eq!(output_size, expected.len());

    let mut output = vec![0u8; output_size];
    let written = hasher
        .finish(Some(output.as_mut_slice()))
        .expect("finish after size query should succeed");

    assert_eq!(written, expected.len());
    assert_eq!(output, expected);
}

/// Verifies a streaming too-small output buffer failure does not poison the context.
fn assert_streaming_failed_small_buffer_does_not_poison_context(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut algo_for_expected = algo;
    let expected = HsmHasher::hash_vec(&session, &mut algo_for_expected, data)
        .expect("single-shot hash should succeed");

    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    for part in data.chunks(8) {
        hasher.update(part).expect("update should succeed");
    }

    let output_size = hasher
        .finish(None)
        .expect("finish size query should succeed");

    assert_eq!(
        output_size,
        expected.len(),
        "streaming size query should match expected digest length"
    );

    let mut too_small = vec![0u8; output_size - 1];
    let result = hasher.finish(Some(too_small.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for too-small output buffer, got {:?}",
        result
    );

    let mut output = vec![0u8; output_size];
    let written = hasher
        .finish(Some(output.as_mut_slice()))
        .expect("context should remain usable after failed small-buffer finish");

    assert_eq!(written, expected.len());
    assert_eq!(
        output, expected,
        "recovered streaming digest should match single-shot digest"
    );
}

/// Verifies failed single-shot hashing does not modify a too-small output buffer.
fn assert_hash_single_shot_small_buffer_not_modified_on_failure(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
) {
    let output_size =
        HsmHasher::hash(&session, &mut algo, data, None).expect("hash size query should succeed");

    let sentinel = 0xAA;
    let mut too_small = vec![sentinel; output_size - 1];

    let result = HsmHasher::hash(&session, &mut algo, data, Some(too_small.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for too-small output buffer, got {:?}",
        result
    );

    assert!(
        too_small.iter().all(|&b| b == sentinel),
        "too-small output buffer should not be modified on failure"
    );
}

// ============================================================
// Test Cases
// ============================================================

/// Verifies SHA1 single-shot hashing against a known digest.
#[session_test]
fn test_hash_sha1(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    let mut algo = HsmHashAlgo::sha1();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA1 streaming hashing against a known digest.
#[session_test]
fn test_hash_sha1_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    let algo = HsmHashAlgo::sha1();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA256 single-shot hashing against a known digest.
#[session_test]
fn test_hash_sha256(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash =
        hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").unwrap();
    let mut algo = HsmHashAlgo::sha256();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA256 streaming hashing against a known digest.
#[session_test]
fn test_hash_sha256_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash =
        hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").unwrap();
    let algo = HsmHashAlgo::sha256();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA384 single-shot hashing against a known digest.
#[session_test]
fn test_hash_sha384(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e\
        85a941bbee3d7f2afbc9b1",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha384();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA384 streaming hashing against a known digest.
#[session_test]
fn test_hash_sha384_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e\
         85a941bbee3d7f2afbc9b1",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha384();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA512 single-shot hashing against a known digest.
#[session_test]
fn test_hash_sha512(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a\
         954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha512();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA512 streaming hashing against a known digest.
#[session_test]
fn test_hash_sha512_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a\
         954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha512();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA1 single-shot hashing of empty input.
#[session_test]
fn test_hash_sha1_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
    let mut algo = HsmHashAlgo::sha1();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA256 single-shot hashing of empty input.
#[session_test]
fn test_hash_sha256_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let mut algo = HsmHashAlgo::sha256();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA384 single-shot hashing of empty input.
#[session_test]
fn test_hash_sha384_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe7\
         6f65fbd51ad2f14898b95b",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha384();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA512 single-shot hashing of empty input.
#[session_test]
fn test_hash_sha512_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d\
         85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha512();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

/// Verifies SHA1 streaming hashing of empty input.
#[session_test]
fn test_hash_sha1_streaming_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
    let algo = HsmHashAlgo::sha1();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA256 streaming hashing of empty input.
#[session_test]
fn test_hash_sha256_streaming_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let algo = HsmHashAlgo::sha256();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA384 streaming hashing of empty input.
#[session_test]
fn test_hash_sha384_streaming_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe7\
         6f65fbd51ad2f14898b95b",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha384();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA512 streaming hashing of empty input.
#[session_test]
fn test_hash_sha512_streaming_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d\
        85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha512();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    hash_and_compare_streaming(session, algo, data, &expected_hash, &chunk_sizes);
}

/// Verifies SHA1 single-shot hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha1_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha1();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

/// Verifies SHA256 single-shot hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha256_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha256();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

/// Verifies SHA384 single-shot hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha384_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha384();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

/// Verifies SHA512 single-shot hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha512_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha512();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

/// Verifies SHA1 streaming hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha1_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha1();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

/// Verifies SHA256 streaming hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha256_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

/// Verifies SHA384 streaming hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha384_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha384();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

/// Verifies SHA512 streaming hashing fails with a too-small output buffer.
#[session_test]
fn test_hash_sha512_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha512();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

/// Verifies SHA1 single-shot and streaming hashing produce the same digest.
#[session_test]
fn test_hash_sha1_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha1();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

/// Verifies SHA256 single-shot and streaming hashing produce the same digest.
#[session_test]
fn test_hash_sha256_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

/// Verifies SHA384 single-shot and streaming hashing produce the same digest.
#[session_test]
fn test_hash_sha384_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha384();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

/// Verifies SHA512 single-shot and streaming hashing produce the same digest.
#[session_test]
fn test_hash_sha512_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha512();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

/// Verifies SHA1 streaming hashing works across multiple chunk patterns.
#[session_test]
fn test_hash_sha1_streaming_chunk_patterns(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha1();
    let chunk_patterns: &[&[usize]] = &[
        &[1, 2, 3, 7, 8, 16, data.len()],
        &[1, 2, 3, 7, 31, 128],
        &[1, 1, 1, 1, 1, 1, data.len()],
        &[16, 16, 16, 16, 16, 16, data.len()],
        &[255, 3, 5, 3, 5, 3, data.len()],
        &[0, data.len()],
    ];

    // run test
    for chunk_pattern in chunk_patterns {
        compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
    }
}

/// Verifies SHA256 streaming hashing works across multiple chunk patterns.
#[session_test]
fn test_hash_sha256_streaming_chunk_patterns(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();
    let chunk_patterns: &[&[usize]] = &[
        &[1, 2, 3, 7, 8, 16, data.len()],
        &[1, 2, 3, 7, 31, 128],
        &[1, 1, 1, 1, 1, 1, data.len()],
        &[16, 16, 16, 16, 16, 16, data.len()],
        &[255, 3, 5, 3, 5, 3, data.len()],
        &[0, data.len()],
    ];

    // run test
    for chunk_pattern in chunk_patterns {
        compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
    }
}

/// Verifies SHA384 streaming hashing works across multiple chunk patterns.
#[session_test]
fn test_hash_sha384_streaming_chunk_patterns(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha384();
    let chunk_patterns: &[&[usize]] = &[
        &[1, 2, 3, 7, 8, 16, data.len()],
        &[1, 2, 3, 7, 31, 128],
        &[1, 1, 1, 1, 1, 1, data.len()],
        &[16, 16, 16, 16, 16, 16, data.len()],
        &[255, 3, 5, 3, 5, 3, data.len()],
        &[0, data.len()],
    ];

    // run test
    for chunk_pattern in chunk_patterns {
        compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
    }
}

/// Verifies SHA512 streaming hashing works across multiple chunk patterns.
#[session_test]
fn test_hash_sha512_streaming_chunk_patterns(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha512();
    let chunk_patterns: &[&[usize]] = &[
        &[1, 2, 3, 7, 8, 16, data.len()],
        &[1, 2, 3, 7, 31, 128],
        &[1, 1, 1, 1, 1, 1, data.len()],
        &[16, 16, 16, 16, 16, 16, data.len()],
        &[255, 3, 5, 3, 5, 3, data.len()],
        &[0, data.len()],
    ];

    // run test
    for chunk_pattern in chunk_patterns {
        compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
    }
}

/// Verifies SHA1 streaming handles an 8-byte input with an empty chunk.
#[session_test]
fn test_hash_sha1_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha1();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

/// Verifies SHA256 streaming handles an 8-byte input with an empty chunk.
#[session_test]
fn test_hash_sha256_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha256();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

/// Verifies SHA384 streaming handles an 8-byte input with an empty chunk.
#[session_test]
fn test_hash_sha384_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha384();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

/// Verifies SHA512 streaming handles an 8-byte input with an empty chunk.
#[session_test]
fn test_hash_sha512_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha512();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

/// Verifies hash context rejects update and finish after successful finish.
#[session_test]
fn test_hash_streaming_update_after_finish_fails(session: HsmSession) {
    let algo = HsmHashAlgo::sha256();
    let mut ctx = algo.hash_init(session).expect("hash_init should succeed");

    ctx.update(b"test data").expect("update should succeed");

    let _hash = ctx.finish_vec().expect("first finish_vec should succeed");

    // update after finish must fail
    let res = ctx.update(b"more data");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState, got {:?}",
        res
    );

    // second finish must fail
    let res = ctx.finish_vec();
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState, got {:?}",
        res
    );
}

/// Verifies hash size query matches digest length for all algorithms.
#[session_test]
fn test_hash_size_query_matches_digest_length_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_size_query_matches_vec(session.clone(), HsmHashAlgo::sha1(), data);
    assert_hash_size_query_matches_vec(session.clone(), HsmHashAlgo::sha256(), data);
    assert_hash_size_query_matches_vec(session.clone(), HsmHashAlgo::sha384(), data);
    assert_hash_size_query_matches_vec(session, HsmHashAlgo::sha512(), data);
}

/// Verifies exact-size output buffers succeed for all hash algorithms.
#[session_test]
fn test_hash_exact_output_buffer_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_exact_output_buffer_succeeds(session.clone(), HsmHashAlgo::sha1(), data);
    assert_hash_exact_output_buffer_succeeds(session.clone(), HsmHashAlgo::sha256(), data);
    assert_hash_exact_output_buffer_succeeds(session.clone(), HsmHashAlgo::sha384(), data);
    assert_hash_exact_output_buffer_succeeds(session, HsmHashAlgo::sha512(), data);
}
/// Verifies oversized output buffer behavior for all hash algorithms.
#[session_test]
fn test_hash_oversized_output_buffer_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_oversized_output_buffer_succeeds_or_returns_internal_error(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
    );
    assert_hash_oversized_output_buffer_succeeds_or_returns_internal_error(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
    );
    assert_hash_oversized_output_buffer_succeeds_or_returns_internal_error(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
    );
    assert_hash_oversized_output_buffer_succeeds_or_returns_internal_error(
        session,
        HsmHashAlgo::sha512(),
        data,
    );
}

/// Verifies explicit empty streaming updates preserve the final digest.
#[session_test]
fn test_hash_streaming_explicit_empty_updates_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_streaming_empty_updates_match_single_shot(session.clone(), HsmHashAlgo::sha1(), data);
    assert_streaming_empty_updates_match_single_shot(session.clone(), HsmHashAlgo::sha256(), data);
    assert_streaming_empty_updates_match_single_shot(session.clone(), HsmHashAlgo::sha384(), data);
    assert_streaming_empty_updates_match_single_shot(session, HsmHashAlgo::sha512(), data);
}

/// Verifies streaming with only empty updates matches the empty input digest.
#[session_test]
fn test_hash_streaming_only_empty_updates_matches_empty_hash(session: HsmSession) {
    let mut hasher = HsmHasher::hash_init(session.clone(), HsmHashAlgo::sha256())
        .expect("hash_init should succeed");

    hasher
        .update(b"")
        .expect("first empty update should succeed");
    hasher
        .update(b"")
        .expect("second empty update should succeed");
    hasher
        .update(b"")
        .expect("third empty update should succeed");

    let actual = hasher.finish_vec().expect("finish_vec should succeed");

    let mut algo = HsmHashAlgo::sha256();
    let expected = HsmHasher::hash_vec(&session, &mut algo, b"")
        .expect("empty single-shot hash should succeed");

    assert_eq!(actual, expected);
}

/// Verifies streaming finish supports size query followed by output retrieval.
#[session_test]
fn test_hash_streaming_size_query_then_finish_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_streaming_size_query_then_finish_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
    );
    assert_streaming_size_query_then_finish_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
    );
    assert_streaming_size_query_then_finish_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
    );
    assert_streaming_size_query_then_finish_matches_single_shot(
        session,
        HsmHashAlgo::sha512(),
        data,
    );
}

/// Verifies failed streaming small-buffer finish does not poison the context.
#[session_test]
fn test_hash_streaming_failed_small_buffer_does_not_poison_context_all_algorithms(
    session: HsmSession,
) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_streaming_failed_small_buffer_does_not_poison_context(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
    );
    assert_streaming_failed_small_buffer_does_not_poison_context(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
    );
    assert_streaming_failed_small_buffer_does_not_poison_context(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
    );
    assert_streaming_failed_small_buffer_does_not_poison_context(
        session,
        HsmHashAlgo::sha512(),
        data,
    );
}

/// Verifies final finish closes the context after recovering from a small-buffer failure.
#[session_test]
fn test_hash_streaming_update_after_failed_small_buffer_finish_still_fails_after_final_finish(
    session: HsmSession,
) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();

    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    hasher.update(data).expect("update should succeed");

    let output_size = hasher
        .finish(None)
        .expect("finish size query should succeed");

    let mut too_small = vec![0u8; output_size - 1];
    let result = hasher.finish(Some(too_small.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for too-small output buffer, got {:?}",
        result
    );

    let mut output = vec![0u8; output_size];
    hasher
        .finish(Some(output.as_mut_slice()))
        .expect("finish with exact output buffer should succeed");

    let result = hasher.update(b"more data");
    assert!(
        matches!(result, Err(HsmError::InvalidContextState)),
        "update after final finish should return InvalidContextState, got {:?}",
        result
    );

    let result = hasher.finish_vec();
    assert!(
        matches!(result, Err(HsmError::InvalidContextState)),
        "second final finish should return InvalidContextState, got {:?}",
        result
    );
}

/// Verifies hash correctness around SHA1/SHA256 64-byte block boundaries.
#[session_test]
fn test_hash_sha1_sha256_block_boundary_lengths(session: HsmSession) {
    let lengths = &[1usize, 55, 56, 57, 63, 64, 65, 127, 128, 129, 1024];

    assert_hash_block_boundary_inputs_match_streaming(
        session.clone(),
        HsmHashAlgo::sha1(),
        lengths,
    );
    assert_hash_block_boundary_inputs_match_streaming(session, HsmHashAlgo::sha256(), lengths);
}

/// Verifies hash correctness around SHA384/SHA512 128-byte block boundaries.
#[session_test]
fn test_hash_sha384_sha512_block_boundary_lengths(session: HsmSession) {
    let lengths = &[1usize, 111, 112, 113, 127, 128, 129, 255, 256, 257, 2048];

    assert_hash_block_boundary_inputs_match_streaming(
        session.clone(),
        HsmHashAlgo::sha384(),
        lengths,
    );
    assert_hash_block_boundary_inputs_match_streaming(session, HsmHashAlgo::sha512(), lengths);
}

/// Verifies single-shot hashing remains usable after a failed small-buffer call.
#[session_test]
fn test_hash_single_shot_failed_small_buffer_does_not_poison_algo_all_algorithms(
    session: HsmSession,
) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_single_shot_failed_small_buffer_does_not_poison_algo(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
    );
    assert_single_shot_failed_small_buffer_does_not_poison_algo(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
    );
    assert_single_shot_failed_small_buffer_does_not_poison_algo(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
    );
    assert_single_shot_failed_small_buffer_does_not_poison_algo(
        session,
        HsmHashAlgo::sha512(),
        data,
    );
}

/// Verifies different inputs do not accidentally produce identical digest output.
#[session_test]
fn test_hash_different_messages_produce_different_digests_all_algorithms(session: HsmSession) {
    assert_hash_different_messages_produce_different_digests(session.clone(), HsmHashAlgo::sha1());
    assert_hash_different_messages_produce_different_digests(
        session.clone(),
        HsmHashAlgo::sha256(),
    );
    assert_hash_different_messages_produce_different_digests(
        session.clone(),
        HsmHashAlgo::sha384(),
    );
    assert_hash_different_messages_produce_different_digests(session, HsmHashAlgo::sha512());
}

/// Verifies byte-by-byte streaming produces the same digest as single-shot hashing.
#[session_test]
fn test_hash_streaming_one_byte_at_a_time_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_streaming_one_byte_at_a_time_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
    );
    assert_streaming_one_byte_at_a_time_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
    );
    assert_streaming_one_byte_at_a_time_matches_single_shot(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
    );
    assert_streaming_one_byte_at_a_time_matches_single_shot(session, HsmHashAlgo::sha512(), data);
}

/// Verifies single-shot hashing fails with a zero-length output buffer.
fn assert_hash_zero_length_output_buffer_fails(
    session: HsmSession,
    mut algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut output = vec![];
    let result = HsmHasher::hash(&session, &mut algo, data, Some(output.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for zero-length output buffer, got {:?}",
        result
    );
}

/// Verifies zero-length output buffers fail for all hash algorithms.
#[session_test]
fn test_hash_zero_length_output_buffer_fails_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha1(), data);
    assert_hash_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha256(), data);
    assert_hash_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha384(), data);
    assert_hash_zero_length_output_buffer_fails(session, HsmHashAlgo::sha512(), data);
}

/// Verifies streaming finish fails with a zero-length output buffer.
fn assert_streaming_zero_length_output_buffer_fails(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
) {
    let mut hasher = HsmHasher::hash_init(session, algo).expect("hash_init should succeed");

    hasher.update(data).expect("update should succeed");

    let mut output = vec![];
    let result = hasher.finish(Some(output.as_mut_slice()));

    assert!(
        matches!(result, Err(HsmError::InternalError)),
        "expected InternalError for zero-length output buffer, got {:?}",
        result
    );
}

/// Verifies streaming zero-length output buffers fail for all hash algorithms.
#[session_test]
fn test_hash_streaming_zero_length_output_buffer_fails_all_algorithms(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_streaming_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha1(), data);
    assert_streaming_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha256(), data);
    assert_streaming_zero_length_output_buffer_fails(session.clone(), HsmHashAlgo::sha384(), data);
    assert_streaming_zero_length_output_buffer_fails(session, HsmHashAlgo::sha512(), data);
}

/// Verifies all hash algorithms against known digests for the standard "abc" test vector.
#[session_test]
fn test_hash_known_abc_vectors_all_algorithms(session: HsmSession) {
    let data = b"abc";

    let mut sha1 = HsmHashAlgo::sha1();
    hash_and_compare_single_shot(
        session.clone(),
        &mut sha1,
        data,
        &hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap(),
    );

    let mut sha256 = HsmHashAlgo::sha256();
    hash_and_compare_single_shot(
        session.clone(),
        &mut sha256,
        data,
        &hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap(),
    );

    let mut sha384 = HsmHashAlgo::sha384();
    hash_and_compare_single_shot(
        session.clone(),
        &mut sha384,
        data,
        &hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap(),
    );

    let mut sha512 = HsmHashAlgo::sha512();
    hash_and_compare_single_shot(
        session,
        &mut sha512,
        data,
        &hex::decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap(),
    );
}

/// Verifies streaming hash algorithms against known digests for the standard "abc" test vector.
#[session_test]
fn test_hash_streaming_known_abc_vectors_all_algorithms(session: HsmSession) {
    let data = b"abc";

    hash_and_compare_streaming(
        session.clone(),
        HsmHashAlgo::sha1(),
        data,
        &hex::decode("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap(),
        &[1, 1, 1],
    );

    hash_and_compare_streaming(
        session.clone(),
        HsmHashAlgo::sha256(),
        data,
        &hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap(),
        &[1, 1, 1],
    );

    hash_and_compare_streaming(
        session.clone(),
        HsmHashAlgo::sha384(),
        data,
        &hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap(),
        &[1, 1, 1],
    );

    hash_and_compare_streaming(
        session,
        HsmHashAlgo::sha512(),
        data,
        &hex::decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap(),
        &[1, 1, 1],
    );
}

/// Verifies large inputs produce matching single-shot and streaming digests.
#[session_test]
fn test_hash_large_input_single_shot_matches_streaming_all_algorithms(session: HsmSession) {
    // Keep this large enough to span many hash blocks, but small enough for HSM-backed CI.
    let data = vec![0x5Au8; 256 * 1024];

    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha1(),
        &data,
        &[4096, 8191, 16384],
    );
    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha256(),
        &data,
        &[4096, 8191, 16384],
    );
    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha384(),
        &data,
        &[4096, 8191, 16384],
    );
    compare_single_shot_vs_streaming(session, HsmHashAlgo::sha512(), &data, &[4096, 8191, 16384]);
}

/// Verifies patterned binary input hashes consistently across single-shot and streaming.
#[session_test]
fn test_hash_patterned_binary_input_all_algorithms(session: HsmSession) {
    let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha1(),
        &data,
        &[13, 29, 61, 127],
    );
    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha256(),
        &data,
        &[13, 29, 61, 127],
    );
    compare_single_shot_vs_streaming(
        session.clone(),
        HsmHashAlgo::sha384(),
        &data,
        &[13, 29, 61, 127],
    );
    compare_single_shot_vs_streaming(session, HsmHashAlgo::sha512(), &data, &[13, 29, 61, 127]);
}

/// Verifies streaming update after finish size query is included in the final digest.
#[session_test]
fn test_hash_streaming_update_after_finish_size_query_succeeds(session: HsmSession) {
    let algo = HsmHashAlgo::sha256();
    let mut hasher = HsmHasher::hash_init(session.clone(), algo).expect("hash_init should succeed");

    hasher
        .update(b"test data")
        .expect("first update should succeed");

    let output_size = hasher
        .finish(None)
        .expect("finish size query should succeed");

    hasher
        .update(b" more data")
        .expect("update after finish size query should succeed");

    let mut output = vec![0u8; output_size];
    let written = hasher
        .finish(Some(output.as_mut_slice()))
        .expect("finish after size query and more updates should succeed");

    assert_eq!(written, output_size);

    let mut expected_algo = HsmHashAlgo::sha256();
    let expected = HsmHasher::hash_vec(&session, &mut expected_algo, b"test data more data")
        .expect("single-shot hash should succeed");

    assert_eq!(
        output, expected,
        "final digest should include data added after finish(None)"
    );
}

/// Verifies failed single-shot SHA256 hashing does not modify a too-small output buffer.
#[session_test]
fn test_hash_sha256_single_shot_small_buffer_not_modified_on_failure(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_single_shot_small_buffer_not_modified_on_failure(
        session,
        HsmHashAlgo::sha256(),
        data,
    );
}

/// Verifies failed single-shot SHA1 hashing does not modify a too-small output buffer.
#[session_test]
fn test_hash_sha1_single_shot_small_buffer_not_modified_on_failure(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_single_shot_small_buffer_not_modified_on_failure(
        session,
        HsmHashAlgo::sha1(),
        data,
    );
}

/// Verifies failed single-shot SHA384 hashing does not modify a too-small output buffer.
#[session_test]
fn test_hash_sha384_single_shot_small_buffer_not_modified_on_failure(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_single_shot_small_buffer_not_modified_on_failure(
        session,
        HsmHashAlgo::sha384(),
        data,
    );
}

/// Verifies failed single-shot SHA512 hashing does not modify a too-small output buffer.
#[session_test]
fn test_hash_sha512_single_shot_small_buffer_not_modified_on_failure(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";

    assert_hash_single_shot_small_buffer_not_modified_on_failure(
        session,
        HsmHashAlgo::sha512(),
        data,
    );
}

/// Verifies the same hash algorithm value can be reused for multiple single-shot hashes.
#[session_test]
fn test_hash_single_shot_algo_reuse_with_different_inputs(session: HsmSession) {
    let mut algo = HsmHashAlgo::sha256();

    let digest_1 = HsmHasher::hash_vec(&session, &mut algo, b"first message")
        .expect("first hash should succeed");
    let digest_2 = HsmHasher::hash_vec(&session, &mut algo, b"second message")
        .expect("second hash should succeed");
    let digest_3 = HsmHasher::hash_vec(&session, &mut algo, b"first message")
        .expect("third hash should succeed");

    assert_ne!(digest_1, digest_2);
    assert_eq!(digest_1, digest_3);
}
