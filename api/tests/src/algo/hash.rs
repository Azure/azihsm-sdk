// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[session_test]
fn test_hash_sha1(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    let mut algo = HsmHashAlgo::sha1();
    let hash = HsmHasher::hash_vec(&session, &mut algo, data).expect("Hashing failed");

    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha1_streaming(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();
    let algo = HsmHashAlgo::sha1();
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");
    for part in data.chunks(8) {
        hasher.update(part).expect("Failed to update hasher");
    }
    let hash = hasher.finish_vec().expect("Failed to finalize hash");
    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha256(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash =
        hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").unwrap();

    let mut algo = HsmHashAlgo::sha256();
    let hash = HsmHasher::hash_vec(&session, &mut algo, data).expect("Hashing failed");

    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha256_streaming(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash =
        hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").unwrap();

    let algo = HsmHashAlgo::sha256();
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");
    for part in data.chunks(8) {
        hasher.update(part).expect("Failed to update hasher");
    }
    let hash = hasher.finish_vec().expect("Failed to finalize hash");
    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha384(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e\
        85a941bbee3d7f2afbc9b1",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha384();
    let hash = HsmHasher::hash_vec(&session, &mut algo, data).expect("Hashing failed");
    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha384_streaming(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e\
         85a941bbee3d7f2afbc9b1",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha384();
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");
    for part in data.chunks(8) {
        hasher.update(part).expect("Failed to update hasher");
    }
    let hash = hasher.finish_vec().expect("Failed to finalize hash");
    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha512(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a\
         954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
    )
    .unwrap();
    let mut algo = HsmHashAlgo::sha512();
    let hash = HsmHasher::hash_vec(&session, &mut algo, data).expect("Hashing failed");
    assert_eq!(hash, expected_hash);
}

#[session_test]
fn test_hash_sha512_streaming(session: HsmSession) {
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected_hash = hex::decode(
        "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a\
         954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
    )
    .unwrap();
    let algo = HsmHashAlgo::sha512();
    let mut hasher = HsmHasher::hash_init(session, algo).expect("Failed to create hasher");
    for part in data.chunks(8) {
        hasher.update(part).expect("Failed to update hasher");
    }
    let hash = hasher.finish_vec().expect("Failed to finalize hash");
    assert_eq!(hash, expected_hash);
}
