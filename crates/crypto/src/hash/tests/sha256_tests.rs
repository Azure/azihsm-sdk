// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hash::tests::testvectors::SHA256_LONG_MSG_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA256_MONTE_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA256_SHORT_MSG_TEST_VECTORS;

#[test]
fn test_sha256_hash() {
    const DATA: [u8; 1024] = [1u8; 1024];
    let mut actual_digest: [u8; 32] = [0; 32];
    const EXPECTED_DIGEST: [u8; 32] = [
        0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf, 0x17,
        0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35, 0x8e, 0xa5,
        0x3a, 0x69,
    ];

    let mut algo = HashAlgo::sha256();
    let result = Hasher::hash(&mut algo, &DATA, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha256_hash_init_update_finish() {
    const DATA: [u8; 1024] = [1u8; 1024];

    let algo = HashAlgo::sha256();
    let mut hash_context = Hasher::hash_init(algo).expect("init sha256");
    hash_context
        .update(&DATA[..700])
        .expect("update sha256 part1");
    hash_context
        .update(&DATA[700..])
        .expect("update sha256 part2");
    let mut out = [0u8; 32];
    hash_context.finish(Some(&mut out)).expect("final sha256");
    assert_eq!(
        out,
        [
            0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf,
            0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35,
            0x8e, 0xa5, 0x3a, 0x69,
        ]
    );
}

#[test]
fn test_sha256_hash_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    let mut actual_digest = [0u8; 32];
    const EXPECTED_DIGEST: [u8; 32] = [
        0x39, 0x65, 0x3b, 0xb8, 0x6f, 0xe6, 0xb8, 0x19, 0xc7, 0xef, 0x49, 0x65, 0xd0, 0x79, 0x7e,
        0x22, 0x38, 0x7c, 0x7e, 0xd5, 0x6b, 0x75, 0x74, 0x7d, 0x48, 0x67, 0x23, 0x21, 0x50, 0xbb,
        0xb1, 0x9f,
    ];

    let mut algo = HashAlgo::sha256();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha256_hash_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    let mut actual_digest = [0u8; 32];
    const EXPECTED_DIGEST: [u8; 32] = [
        0xb7, 0x18, 0x62, 0x40, 0x77, 0xcb, 0xfb, 0x48, 0xd9, 0x4b, 0x16, 0xf8, 0xf6, 0xcd, 0xc0,
        0x61, 0x36, 0xed, 0x40, 0xbb, 0xb6, 0x8f, 0x97, 0xac, 0x71, 0x66, 0x35, 0x79, 0xff, 0xe4,
        0x31, 0xc1,
    ];

    let mut algo = HashAlgo::sha256();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha256_hash_init_update_finish_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    const EXPECTED_DIGEST: [u8; 32] = [
        0x39, 0x65, 0x3b, 0xb8, 0x6f, 0xe6, 0xb8, 0x19, 0xc7, 0xef, 0x49, 0x65, 0xd0, 0x79, 0x7e,
        0x22, 0x38, 0x7c, 0x7e, 0xd5, 0x6b, 0x75, 0x74, 0x7d, 0x48, 0x67, 0x23, 0x21, 0x50, 0xbb,
        0xb1, 0x9f,
    ];

    let algo = HashAlgo::sha256();
    let mut hasher = Hasher::hash_init(algo).expect("init sha256");
    hasher.update(&data[..700]).expect("update sha256 part1");
    hasher.update(&data[700..]).expect("update sha256 part2");
    let mut actual_digest = [0u8; 32];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha256");

    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha256_hash_init_update_finish_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    const EXPECTED_DIGEST: [u8; 32] = [
        0xb7, 0x18, 0x62, 0x40, 0x77, 0xcb, 0xfb, 0x48, 0xd9, 0x4b, 0x16, 0xf8, 0xf6, 0xcd, 0xc0,
        0x61, 0x36, 0xed, 0x40, 0xbb, 0xb6, 0x8f, 0x97, 0xac, 0x71, 0x66, 0x35, 0x79, 0xff, 0xe4,
        0x31, 0xc1,
    ];

    let algo = HashAlgo::sha256();
    let mut hasher = Hasher::hash_init(algo).expect("init sha256");
    hasher.update(&data[..700]).expect("update sha256 part1");
    hasher.update(&data[700..]).expect("update sha256 part2");
    let mut actual_digest = [0u8; 32];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha256");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

fn sha256_monte_vector_one_shot(vector: &ShaMonteTestVector) {
    // NIST SHA-256 Monte Carlo algorithm (as specified by the .rsp):
    //
    // INPUT: Seed (L bytes)
    // for j in 0..100 {
    //   MD0 = MD1 = MD2 = Seed
    //   for i in 3..1003 {
    //     Mi  = MD(i-3) || MD(i-2) || MD(i-1)
    //     MDi = SHA256(Mi)
    //   }
    //   Seed = MD1002
    //   OUTPUT: MDj == Seed
    // }
    let mut algo = HashAlgo::sha256();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha256 size query");
    assert_eq!(digest_len, vector.expected_digest_len_bytes);
    assert_eq!(vector.seed.len(), digest_len);

    let mut seed = vec![0u8; digest_len];
    seed.copy_from_slice(vector.seed);

    let mut md0 = vec![0u8; digest_len];
    let mut md1 = vec![0u8; digest_len];
    let mut md2 = vec![0u8; digest_len];
    let mut md3 = vec![0u8; digest_len];
    let mut mi = vec![0u8; digest_len * 3];

    for (j, expected_digest) in vector.expected_digests.iter().enumerate() {
        assert_eq!(expected_digest.len(), digest_len);

        md0.clone_from(&seed);
        md1.clone_from(&seed);
        md2.clone_from(&seed);

        for _i in 3..1003 {
            mi[..digest_len].copy_from_slice(&md0);
            mi[digest_len..(2 * digest_len)].copy_from_slice(&md1);
            mi[(2 * digest_len)..].copy_from_slice(&md2);

            let mut algo = HashAlgo::sha256();
            let written =
                Hasher::hash(&mut algo, &mi, Some(md3.as_mut_slice())).expect("sha256 monte hash");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA256 NIST Monte Carlo (one-shot) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha256_monte_vector_streaming(vector: &ShaMonteTestVector) {
    let mut algo = HashAlgo::sha256();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha256 size query");
    assert_eq!(digest_len, vector.expected_digest_len_bytes);
    assert_eq!(vector.seed.len(), digest_len);

    let mut seed = vec![0u8; digest_len];
    seed.copy_from_slice(vector.seed);

    let mut md0 = vec![0u8; digest_len];
    let mut md1 = vec![0u8; digest_len];
    let mut md2 = vec![0u8; digest_len];
    let mut md3 = vec![0u8; digest_len];

    // Use the same split points as SHA1 Monte, capped to the digest length.
    let split_a = 1usize.min(digest_len);
    let split_b = 7usize.min(digest_len);
    let split_c = 13usize.min(digest_len);

    for (j, expected_digest) in vector.expected_digests.iter().enumerate() {
        assert_eq!(expected_digest.len(), digest_len);

        md0.clone_from(&seed);
        md1.clone_from(&seed);
        md2.clone_from(&seed);

        for _i in 3..1003 {
            let algo = HashAlgo::sha256();
            let mut ctx = Hasher::hash_init(algo).expect("init sha256");

            ctx.update(&md0[..split_a]).expect("sha256 update");
            ctx.update(&md0[split_a..]).expect("sha256 update");

            ctx.update(&md1[..split_b]).expect("sha256 update");
            ctx.update(&md1[split_b..]).expect("sha256 update");

            ctx.update(&md2[..split_c]).expect("sha256 update");
            ctx.update(&md2[split_c..]).expect("sha256 update");

            let written = ctx.finish(Some(md3.as_mut_slice())).expect("sha256 finish");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA256 NIST Monte Carlo (streaming) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha256_vector_one_shot(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha256();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha256 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut actual = vec![0u8; required_len];
    let written =
        Hasher::hash(&mut algo, vector.msg, Some(actual.as_mut_slice())).expect("sha256 one-shot");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA256 NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn sha256_vector_streaming(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha256();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha256 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let algo = HashAlgo::sha256();
    let mut ctx = Hasher::hash_init(algo).expect("init sha256");

    let chunk_sizes = [1usize, 7, 5, 12, 2, 19, 60, 132];
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;

    while cursor < vector.msg.len() {
        let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
        chunk_index += 1;

        let end = (cursor + chunk_len).min(vector.msg.len());
        ctx.update(&vector.msg[cursor..end]).expect("sha256 update");
        cursor = end;
    }

    let mut actual = vec![0u8; required_len];
    let written = ctx
        .finish(Some(actual.as_mut_slice()))
        .expect("sha256 finish");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA256 NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

#[test]
fn test_sha256_nist_short_msg_vectors_one_shot() {
    for vector in SHA256_SHORT_MSG_TEST_VECTORS {
        sha256_vector_one_shot(vector);
    }
}

#[test]
fn test_sha256_nist_short_msg_vectors_streaming() {
    for vector in SHA256_SHORT_MSG_TEST_VECTORS {
        sha256_vector_streaming(vector);
    }
}

#[test]
fn test_sha256_nist_long_msg_vectors_one_shot() {
    for vector in SHA256_LONG_MSG_TEST_VECTORS {
        sha256_vector_one_shot(vector);
    }
}

#[test]
fn test_sha256_nist_long_msg_vectors_streaming() {
    for vector in SHA256_LONG_MSG_TEST_VECTORS {
        sha256_vector_streaming(vector);
    }
}

#[test]
fn test_sha256_nist_monte_vectors_one_shot() {
    for vector in SHA256_MONTE_TEST_VECTORS {
        sha256_monte_vector_one_shot(vector);
    }
}

#[test]
fn test_sha256_nist_monte_vectors_streaming() {
    for vector in SHA256_MONTE_TEST_VECTORS {
        sha256_monte_vector_streaming(vector);
    }
}
