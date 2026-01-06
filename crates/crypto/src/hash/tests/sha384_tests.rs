// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hash::tests::testvectors::SHA384_LONG_MSG_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA384_MONTE_TEST_VECTORS;
use crate::hash::tests::testvectors::SHA384_SHORT_MSG_TEST_VECTORS;

#[test]
fn test_sha384_hash() {
    const DATA: [u8; 1024] = [1u8; 1024];
    let mut actual_digest: [u8; 48] = [0; 48];
    const EXPECTED_DIGEST: [u8; 48] = [
        0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00, 0xa0,
        0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92, 0xef, 0x9e,
        0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a, 0x5f, 0x1e, 0x78,
        0x2a, 0x7c, 0xc7,
    ];

    let mut algo = HashAlgo::sha384();
    let result = Hasher::hash(&mut algo, &DATA, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha384_hash_init_update_finish() {
    const DATA: [u8; 1024] = [1u8; 1024];

    let algo = HashAlgo::sha384();
    let mut hasher = Hasher::hash_init(algo).expect("init sha384");
    hasher.update(&DATA[..1000]).expect("update sha384 part1");
    hasher.update(&DATA[1000..]).expect("update sha384 part2");
    let mut out = [0u8; 48];
    hasher.finish(Some(&mut out)).expect("final sha384");
    assert_eq!(
        out,
        [
            0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00,
            0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92,
            0xef, 0x9e, 0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a,
            0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7,
        ]
    );
}

#[test]
fn test_sha384_hash_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    let mut actual_digest = [0u8; 48];
    const EXPECTED_DIGEST: [u8; 48] = [
        0x37, 0xe8, 0xc1, 0xb7, 0x8b, 0x12, 0x98, 0x2f, 0xcd, 0xaa, 0xb3, 0xee, 0x3d, 0x47, 0x49,
        0xf5, 0x6c, 0xca, 0x9c, 0xc5, 0x89, 0x89, 0xa6, 0x78, 0x2a, 0x92, 0xa0, 0x07, 0x78, 0x1e,
        0x0f, 0x0a, 0x1c, 0xde, 0x3e, 0x57, 0xde, 0xbf, 0xf5, 0x63, 0x35, 0xc6, 0x96, 0xb9, 0x13,
        0x3e, 0x50, 0x78,
    ];

    let mut algo = HashAlgo::sha384();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha384_hash_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    let mut actual_digest = [0u8; 48];
    const EXPECTED_DIGEST: [u8; 48] = [
        0xd0, 0x1c, 0x87, 0x85, 0x28, 0x38, 0x39, 0x68, 0xc5, 0xc4, 0xbb, 0x32, 0x5e, 0x37, 0x46,
        0x4d, 0x4d, 0xe7, 0xfe, 0x96, 0x3d, 0x6b, 0x68, 0x55, 0xa8, 0x9e, 0x6a, 0xc0, 0x58, 0xe9,
        0x24, 0x56, 0x92, 0x8e, 0x33, 0xf8, 0x6d, 0x50, 0xdb, 0x8d, 0x06, 0xaf, 0xe6, 0x72, 0x3c,
        0xe7, 0x4b, 0x51,
    ];

    let mut algo = HashAlgo::sha384();
    let result = Hasher::hash(&mut algo, &data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha384_hash_init_update_finish_big_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    const EXPECTED_DIGEST: [u8; 48] = [
        0x37, 0xe8, 0xc1, 0xb7, 0x8b, 0x12, 0x98, 0x2f, 0xcd, 0xaa, 0xb3, 0xee, 0x3d, 0x47, 0x49,
        0xf5, 0x6c, 0xca, 0x9c, 0xc5, 0x89, 0x89, 0xa6, 0x78, 0x2a, 0x92, 0xa0, 0x07, 0x78, 0x1e,
        0x0f, 0x0a, 0x1c, 0xde, 0x3e, 0x57, 0xde, 0xbf, 0xf5, 0x63, 0x35, 0xc6, 0x96, 0xb9, 0x13,
        0x3e, 0x50, 0x78,
    ];

    let algo = HashAlgo::sha384();
    let mut hasher = Hasher::hash_init(algo).expect("init sha384");
    hasher.update(&data[..1000]).expect("update sha384 part1");
    hasher.update(&data[1000..]).expect("update sha384 part2");
    let mut actual_digest = [0u8; 48];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha384");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha384_hash_init_update_finish_little_endian_data() {
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    const EXPECTED_DIGEST: [u8; 48] = [
        0xd0, 0x1c, 0x87, 0x85, 0x28, 0x38, 0x39, 0x68, 0xc5, 0xc4, 0xbb, 0x32, 0x5e, 0x37, 0x46,
        0x4d, 0x4d, 0xe7, 0xfe, 0x96, 0x3d, 0x6b, 0x68, 0x55, 0xa8, 0x9e, 0x6a, 0xc0, 0x58, 0xe9,
        0x24, 0x56, 0x92, 0x8e, 0x33, 0xf8, 0x6d, 0x50, 0xdb, 0x8d, 0x06, 0xaf, 0xe6, 0x72, 0x3c,
        0xe7, 0x4b, 0x51,
    ];

    let algo = HashAlgo::sha384();
    let mut hasher = Hasher::hash_init(algo).expect("init sha384");
    hasher.update(&data[..1000]).expect("update sha384 part1");
    hasher.update(&data[1000..]).expect("update sha384 part2");
    let mut actual_digest = [0u8; 48];
    hasher
        .finish(Some(&mut actual_digest))
        .expect("final sha384");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

fn sha384_monte_vector_one_shot(vector: &ShaMonteTestVector) {
    // NIST SHA-384 Monte Carlo algorithm (as specified by the .rsp):
    //
    // INPUT: Seed (L bytes)
    // for j in 0..100 {
    //   MD0 = MD1 = MD2 = Seed
    //   for i in 3..1003 {
    //     Mi  = MD(i-3) || MD(i-2) || MD(i-1)
    //     MDi = SHA384(Mi)
    //   }
    //   Seed = MD1002
    //   OUTPUT: MDj == Seed
    // }
    let mut algo = HashAlgo::sha384();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha384 size query");
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

            let mut algo = HashAlgo::sha384();
            let written =
                Hasher::hash(&mut algo, &mi, Some(md3.as_mut_slice())).expect("sha384 monte hash");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA384 NIST Monte Carlo (one-shot) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha384_monte_vector_streaming(vector: &ShaMonteTestVector) {
    let mut algo = HashAlgo::sha384();
    let digest_len = Hasher::hash(&mut algo, &[], None).expect("sha384 size query");
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
            let algo = HashAlgo::sha384();
            let mut ctx = Hasher::hash_init(algo).expect("init sha384");

            ctx.update(&md0[..split_a]).expect("sha384 update");
            ctx.update(&md0[split_a..]).expect("sha384 update");

            ctx.update(&md1[..split_b]).expect("sha384 update");
            ctx.update(&md1[split_b..]).expect("sha384 update");

            ctx.update(&md2[..split_c]).expect("sha384 update");
            ctx.update(&md2[split_c..]).expect("sha384 update");

            let written = ctx.finish(Some(md3.as_mut_slice())).expect("sha384 finish");
            assert_eq!(written, digest_len);

            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA384 NIST Monte Carlo (streaming) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha384_vector_one_shot(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha384();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha384 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut actual = vec![0u8; required_len];
    let written =
        Hasher::hash(&mut algo, vector.msg, Some(actual.as_mut_slice())).expect("sha384 one-shot");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA384 NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn sha384_vector_streaming(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha384();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("sha384 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let algo = HashAlgo::sha384();
    let mut ctx = Hasher::hash_init(algo).expect("init sha384");

    let chunk_sizes = [1usize, 1, 9, 11, 3, 20, 65, 128];
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;

    while cursor < vector.msg.len() {
        let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
        chunk_index += 1;

        let end = (cursor + chunk_len).min(vector.msg.len());
        ctx.update(&vector.msg[cursor..end]).expect("sha384 update");
        cursor = end;
    }

    let mut actual = vec![0u8; required_len];
    let written = ctx
        .finish(Some(actual.as_mut_slice()))
        .expect("sha384 finish");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA384 NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

#[test]
fn test_sha384_nist_short_msg_vectors_one_shot() {
    for vector in SHA384_SHORT_MSG_TEST_VECTORS {
        sha384_vector_one_shot(vector);
    }
}

#[test]
fn test_sha384_nist_short_msg_vectors_streaming() {
    for vector in SHA384_SHORT_MSG_TEST_VECTORS {
        sha384_vector_streaming(vector);
    }
}

#[test]
fn test_sha384_nist_long_msg_vectors_one_shot() {
    for vector in SHA384_LONG_MSG_TEST_VECTORS {
        sha384_vector_one_shot(vector);
    }
}

#[test]
fn test_sha384_nist_long_msg_vectors_streaming() {
    for vector in SHA384_LONG_MSG_TEST_VECTORS {
        sha384_vector_streaming(vector);
    }
}

#[test]
fn test_sha384_nist_monte_vectors_one_shot() {
    for vector in SHA384_MONTE_TEST_VECTORS {
        sha384_monte_vector_one_shot(vector);
    }
}

#[test]
fn test_sha384_nist_monte_vectors_streaming() {
    for vector in SHA384_MONTE_TEST_VECTORS {
        sha384_monte_vector_streaming(vector);
    }
}
