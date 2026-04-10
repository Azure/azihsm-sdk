// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

// ================================
// Helpers
// ================================

fn hash_and_compare_single_shot(
    session: HsmSession,
    algo: &mut HsmHashAlgo,
    data: &[u8],
    expected: &[u8],
) {
    let hash = HsmHasher::hash_vec(&session, algo, data).expect("Hashing failed");
    assert_eq!(hash, expected);
}

fn hash_and_compare_streaming(
    session: HsmSession,
    algo: HsmHashAlgo,
    data: &[u8],
    expected: &[u8],
    chunk_sizes: &[usize],
) {
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");

    let mut offset = 0;
    let mut i = 0;
    while offset < data.len() && i < chunk_sizes.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(data.len() - offset);
        let chunk = &data[offset..offset + size];
        offset += size;
        i += 1;

        hasher.update(chunk).expect("Failed to update hasher");
    }

    let hash = hasher.finish_vec().expect("Failed to finalize hash");

    assert_eq!(hash, expected);
}

fn buffer_too_small_single_shot(session: HsmSession, algo: &mut HsmHashAlgo, data: &[u8]) {
    let output_size =
        HsmHasher::hash(&session, algo, data, None).expect("Failed to query hash size");
    let mut too_small = vec![0u8; output_size - 1];
    let result = HsmHasher::hash(&session, algo, data, Some(too_small.as_mut_slice()));
    assert!(matches!(result, Err(HsmError::InternalError)));
}

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

// ============================================================
// Test Cases
// ============================================================

#[session_test]
fn test_hash_sha1(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    let mut algo = HsmHashAlgo::sha1();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

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

#[session_test]
fn test_hash_sha1_empty_data(session: HsmSession) {
    // test data
    let data = b"";
    let expected_hash = hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
    let mut algo = HsmHashAlgo::sha1();

    // run test
    hash_and_compare_single_shot(session, &mut algo, data, &expected_hash);
}

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

#[session_test]
fn test_hash_sha1_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha1();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

#[session_test]
fn test_hash_sha256_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha256();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

#[session_test]
fn test_hash_sha384_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha384();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

#[session_test]
fn test_hash_sha512_buffer_too_small_single_shot(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut algo = HsmHashAlgo::sha512();

    // run test
    buffer_too_small_single_shot(session, &mut algo, data);
}

#[session_test]
fn test_hash_sha1_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha1();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

#[session_test]
fn test_hash_sha256_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

#[session_test]
fn test_hash_sha384_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha384();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

#[session_test]
fn test_hash_sha512_buffer_too_small_streaming(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha512();

    // run test
    buffer_too_small_streaming(session, algo, data);
}

#[session_test]
fn test_hash_sha1_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha1();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

#[session_test]
fn test_hash_sha256_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha256();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

#[session_test]
fn test_hash_sha384_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha384();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

#[session_test]
fn test_hash_sha512_single_shot_vs_streaming_comparison(session: HsmSession) {
    // test data
    let data = b"The quick brown fox jumps over the lazy dog";
    let algo = HsmHashAlgo::sha512();
    let chunk_sizes = vec![8; data.len() / 8 + 1];

    // run test
    compare_single_shot_vs_streaming(session, algo, data, &chunk_sizes);
}

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

#[session_test]
fn test_hash_sha1_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha1();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

#[session_test]
fn test_hash_sha256_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha256();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

#[session_test]
fn test_hash_sha384_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha384();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

#[session_test]
fn test_hash_sha512_8_bytes(session: HsmSession) {
    // test data
    let data = b"12345678";
    let algo = HsmHashAlgo::sha512();
    let chunk_pattern = &[4, 0, 4];

    // run test
    compare_single_shot_vs_streaming(session.clone(), algo, data, chunk_pattern);
}

/// Verifies that hash context rejects update and finish after successful finish.
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
