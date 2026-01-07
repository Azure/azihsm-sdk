// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hash::tests::testvectors::SHA512_LONG_MSG_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA512_MONTE_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA512_SHORT_MSG_TEST_VECTORS;

#[test]
fn test_sha512_hash() {
    const DATA: [u8; 1024] = [1u8; 1024];
    let mut actual_digest: [u8; 64] = [0; 64];
    const EXPECTED_DIGEST: [u8; 64] = [
        0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9, 0x38,
        0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d, 0x94, 0x53,
        0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda, 0x95, 0x54, 0xe9,
        0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb, 0xde, 0x66, 0x15, 0x37,
        0x5b, 0xab, 0x4a, 0xe8,
    ];

    let mut algo = HashAlgo::sha512();
    let result = Hasher::hash(&mut algo, &DATA, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha512_hash_init_update_finish() {
    const DATA: [u8; 1024] = [1u8; 1024];

    let algo = HashAlgo::sha512();
    let mut hasher = Hasher::hash_init(algo).expect("init sha512");
    hasher.update(&DATA[..256]).expect("update sha512 part1");
    hasher.update(&DATA[256..768]).expect("update sha512 part2");
    hasher.update(&DATA[768..]).expect("update sha512 part3");
    let mut out = [0u8; 64];
    hasher.finish(Some(&mut out)).expect("final sha512");
    assert_eq!(
        out,
        [
            0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9,
            0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d,
            0x94, 0x53, 0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda,
            0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb,
            0xde, 0x66, 0x15, 0x37, 0x5b, 0xab, 0x4a, 0xe8,
        ]
    );
}

#[test]
fn test_sha512_hash_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    let mut actual_digest = [0u8; 64];
    const EXPECTED_DIGEST: [u8; 64] = [
        0x3a, 0x03, 0x78, 0xaa, 0x87, 0xa5, 0x3f, 0xb1, 0xf5, 0x32, 0x54, 0x89, 0xa3, 0x39, 0x8b,
        0x66, 0x22, 0x7b, 0xf0, 0x22, 0x97, 0xe3, 0x77, 0x24, 0xc2, 0x0b, 0x56, 0xab, 0x98, 0xf8,
        0x94, 0x23, 0x1c, 0x16, 0xc4, 0x0b, 0xeb, 0x65, 0x92, 0x32, 0xf0, 0x9e, 0x5c, 0x09, 0xfe,
        0xd4, 0xfd, 0xd8, 0x4b, 0xbe, 0xf6, 0xfd, 0x66, 0x15, 0x6d, 0xda, 0x35, 0x21, 0xd4, 0xfc,
        0xd9, 0xe5, 0x7d, 0xd9,
    ];

    let mut algo = HashAlgo::sha512();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha512_hash_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    let mut actual_digest = [0u8; 64];
    const EXPECTED_DIGEST: [u8; 64] = [
        0x21, 0x42, 0x55, 0x85, 0xd3, 0x70, 0x67, 0x4e, 0x46, 0xe3, 0xa0, 0x6a, 0x65, 0xf5, 0xc9,
        0x3d, 0xeb, 0x2f, 0x4b, 0xc3, 0xf7, 0x30, 0xb1, 0x7b, 0x7f, 0xe3, 0x13, 0xa2, 0x28, 0xd1,
        0xba, 0xb6, 0xcd, 0x71, 0xa1, 0xa7, 0xc7, 0xa7, 0x3e, 0x5a, 0xca, 0x67, 0x35, 0xb4, 0x4d,
        0x0f, 0x26, 0xb7, 0xc5, 0x96, 0x12, 0x7f, 0x20, 0x5c, 0x34, 0x2f, 0x4c, 0x06, 0x95, 0x64,
        0x89, 0xd9, 0xf3, 0x6a,
    ];

    let mut algo = HashAlgo::sha512();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha512_hash_init_update_finish_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    const EXPECTED_DIGEST: [u8; 64] = [
        0x3a, 0x03, 0x78, 0xaa, 0x87, 0xa5, 0x3f, 0xb1, 0xf5, 0x32, 0x54, 0x89, 0xa3, 0x39, 0x8b,
        0x66, 0x22, 0x7b, 0xf0, 0x22, 0x97, 0xe3, 0x77, 0x24, 0xc2, 0x0b, 0x56, 0xab, 0x98, 0xf8,
        0x94, 0x23, 0x1c, 0x16, 0xc4, 0x0b, 0xeb, 0x65, 0x92, 0x32, 0xf0, 0x9e, 0x5c, 0x09, 0xfe,
        0xd4, 0xfd, 0xd8, 0x4b, 0xbe, 0xf6, 0xfd, 0x66, 0x15, 0x6d, 0xda, 0x35, 0x21, 0xd4, 0xfc,
        0xd9, 0xe5, 0x7d, 0xd9,
    ];

    let algo = HashAlgo::sha512();
    let mut hasher = Hasher::hash_init(algo).expect("init sha512");
    hasher.update(&data[..256]).expect("update sha512 part1");
    hasher.update(&data[256..768]).expect("update sha512 part2");
    hasher.update(&data[768..]).expect("update sha512 part3");
    let mut actual_digest = [0u8; 64];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha512");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha512_hash_init_update_finish_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    const EXPECTED_DIGEST: [u8; 64] = [
        0x21, 0x42, 0x55, 0x85, 0xd3, 0x70, 0x67, 0x4e, 0x46, 0xe3, 0xa0, 0x6a, 0x65, 0xf5, 0xc9,
        0x3d, 0xeb, 0x2f, 0x4b, 0xc3, 0xf7, 0x30, 0xb1, 0x7b, 0x7f, 0xe3, 0x13, 0xa2, 0x28, 0xd1,
        0xba, 0xb6, 0xcd, 0x71, 0xa1, 0xa7, 0xc7, 0xa7, 0x3e, 0x5a, 0xca, 0x67, 0x35, 0xb4, 0x4d,
        0x0f, 0x26, 0xb7, 0xc5, 0x96, 0x12, 0x7f, 0x20, 0x5c, 0x34, 0x2f, 0x4c, 0x06, 0x95, 0x64,
        0x89, 0xd9, 0xf3, 0x6a,
    ];

    let algo = HashAlgo::sha512();
    let mut hasher = Hasher::hash_init(algo).expect("init sha512");
    hasher.update(&data[..256]).expect("update sha512 part1");
    hasher.update(&data[256..768]).expect("update sha512 part2");
    hasher.update(&data[768..]).expect("update sha512 part3");
    let mut actual_digest = [0u8; 64];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha512");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

fn sha512_monte_vector_one_shot(vector: &ShaMonteTestVector) {
    // NIST SHA-512 Monte Carlo algorithm (as specified by the .rsp):
    //
    // INPUT: Seed (L bytes)
    // for j in 0..100 {
    //   MD0 = MD1 = MD2 = Seed
    //   for i in 3..1003 {
    //     Mi  = MD(i-3) || MD(i-2) || MD(i-1)
    //     MDi = SHA512(Mi)
    //   }
    //   Seed = MD1002
    //   OUTPUT: MDj == Seed
    // }
    let mut algo = HashAlgo::sha512();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha512 size query");
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

            let mut algo = HashAlgo::sha512();
            let written =
                Hasher::hash(&mut algo, &mi, Some(md3.as_mut_slice())).expect("sha512 monte hash");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA512 NIST Monte Carlo (one-shot) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha512_monte_vector_streaming(vector: &ShaMonteTestVector) {
    let mut algo = HashAlgo::sha512();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha512 size query");
    assert_eq!(digest_len, vector.expected_digest_len_bytes);
    assert_eq!(vector.seed.len(), digest_len);

    let mut seed = vec![0u8; digest_len];
    seed.copy_from_slice(vector.seed);

    let mut md0 = vec![0u8; digest_len];
    let mut md1 = vec![0u8; digest_len];
    let mut md2 = vec![0u8; digest_len];
    let mut md3 = vec![0u8; digest_len];

    let split_a = 1usize.min(digest_len);
    let split_b = 7usize.min(digest_len);
    let split_c = 13usize.min(digest_len);

    for (j, expected_digest) in vector.expected_digests.iter().enumerate() {
        assert_eq!(expected_digest.len(), digest_len);

        md0.clone_from(&seed);
        md1.clone_from(&seed);
        md2.clone_from(&seed);

        for _i in 3..1003 {
            let algo = HashAlgo::sha512();
            let mut ctx = Hasher::hash_init(algo).expect("init sha512");

            ctx.update(&md0[..split_a]).expect("sha512 update");
            ctx.update(&md0[split_a..]).expect("sha512 update");

            ctx.update(&md1[..split_b]).expect("sha512 update");
            ctx.update(&md1[split_b..]).expect("sha512 update");

            ctx.update(&md2[..split_c]).expect("sha512 update");
            ctx.update(&md2[split_c..]).expect("sha512 update");

            let written = ctx.finish(Some(md3.as_mut_slice())).expect("sha512 finish");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA512 NIST Monte Carlo (streaming) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha512_vector_one_shot(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha512();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha512 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut actual = vec![0u8; required_len];
    let written =
        Hasher::hash(&mut algo, vector.msg, Some(actual.as_mut_slice())).expect("sha512 one-shot");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA512 NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn sha512_vector_streaming(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha512();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha512 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let algo = HashAlgo::sha512();
    let mut ctx = Hasher::hash_init(algo).expect("init sha512");

    let chunk_sizes = [1usize, 3, 7, 10, 4, 19, 64, 128];
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;

    while cursor < vector.msg.len() {
        let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
        chunk_index += 1;

        let end = (cursor + chunk_len).min(vector.msg.len());
        ctx.update(&vector.msg[cursor..end]).expect("sha512 update");
        cursor = end;
    }

    let mut actual = vec![0u8; required_len];
    let written = ctx
        .finish(Some(actual.as_mut_slice()))
        .expect("sha512 finish");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA512 NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

#[test]
fn test_sha512_nist_short_msg_vectors_one_shot() {
    for vector in SHA512_SHORT_MSG_TEST_VECTORS {
        sha512_vector_one_shot(vector);
    }
}

#[test]
fn test_sha512_nist_short_msg_vectors_streaming() {
    for vector in SHA512_SHORT_MSG_TEST_VECTORS {
        sha512_vector_streaming(vector);
    }
}

#[test]
fn test_sha512_nist_long_msg_vectors_one_shot() {
    for vector in SHA512_LONG_MSG_TEST_VECTORS {
        sha512_vector_one_shot(vector);
    }
}

#[test]
fn test_sha512_nist_long_msg_vectors_streaming() {
    for vector in SHA512_LONG_MSG_TEST_VECTORS {
        sha512_vector_streaming(vector);
    }
}

#[test]
fn test_sha512_nist_monte_vectors_one_shot() {
    for vector in SHA512_MONTE_TEST_VECTORS {
        sha512_monte_vector_one_shot(vector);
    }
}

#[test]
fn test_sha512_nist_monte_vectors_streaming() {
    for vector in SHA512_MONTE_TEST_VECTORS {
        sha512_monte_vector_streaming(vector);
    }
}
