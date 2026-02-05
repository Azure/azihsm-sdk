// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_sha1_one_shot() {
    const DATA: [u8; 1024] = [1u8; 1024];
    let mut actual_digest: [u8; 20] = [0; 20];
    const EXPECTED_DIGEST: [u8; 20] = [
        0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3, 0x24,
        0x78, 0xca, 0xaa, 0x7e, 0x39,
    ];

    let mut algo = HashAlgo::sha1();
    let result = algo.hash(&DATA, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha1_streaming() {
    const DATA: [u8; 1024] = [1u8; 1024];

    let algo = HashAlgo::sha1();
    let mut hash_context = algo.hash_init().expect("init sha1");
    hash_context
        .update(&DATA[..512])
        .expect("update sha1 part1");
    hash_context
        .update(&DATA[512..])
        .expect("update sha1 part2");
    let mut out = [0u8; 20];
    hash_context.finish(Some(&mut out)).expect("final sha1");
    assert_eq!(
        out,
        [
            0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3,
            0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39,
        ]
    );
}

#[test]
fn test_sha1_big_endian_data() {
    // 1024 bytes, filled with repeated 0x11223344 in big endian
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    let mut actual_digest = [0u8; 20];
    const EXPECTED_DIGEST: [u8; 20] = [
        0xa3, 0xfb, 0x5e, 0x21, 0x19, 0x18, 0xea, 0x79, 0x4b, 0x65, 0x4d, 0x83, 0xaf, 0xa5, 0x33,
        0x9a, 0x91, 0x11, 0x0e, 0xb7,
    ];

    let mut algo = HashAlgo::sha1();
    let result = algo.hash(&data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha1_little_endian_data() {
    // 1024 bytes, filled with repeated 0x11223344 in little endian
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    let mut actual_digest = [0u8; 20];
    const EXPECTED_DIGEST: [u8; 20] = [
        0x26, 0xc8, 0x9b, 0x67, 0x45, 0x17, 0xa9, 0xbc, 0xba, 0xc1, 0xc8, 0x63, 0x03, 0x72, 0x23,
        0x09, 0x10, 0xde, 0xb1, 0x6b,
    ];

    let mut algo = HashAlgo::sha1();
    let result = algo.hash(&data, Some(&mut actual_digest));
    assert!(result.is_ok());
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha1_streaming_big_endian_data() {
    // 1024 bytes, filled with repeated 0x11223344 in big endian
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
    }

    const EXPECTED_DIGEST: [u8; 20] = [
        0xa3, 0xfb, 0x5e, 0x21, 0x19, 0x18, 0xea, 0x79, 0x4b, 0x65, 0x4d, 0x83, 0xaf, 0xa5, 0x33,
        0x9a, 0x91, 0x11, 0x0e, 0xb7,
    ];

    let algo = HashAlgo::sha1();
    let mut hasher = algo.hash_init().expect("init sha1");
    hasher.update(&data[..512]).expect("update sha1 part1");
    hasher.update(&data[512..]).expect("update sha1 part2");
    let mut actual_digest = [0u8; 20];
    hasher.finish(Some(&mut actual_digest)).expect("final sha1");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

#[test]
fn test_sha1_streaming_little_endian_data() {
    // 1024 bytes, filled with repeated 0x11223344 in little endian
    let mut data = [0u8; 1024];
    for i in 0..(1024 / 4) {
        data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
    }

    const EXPECTED_DIGEST: [u8; 20] = [
        0x26, 0xc8, 0x9b, 0x67, 0x45, 0x17, 0xa9, 0xbc, 0xba, 0xc1, 0xc8, 0x63, 0x03, 0x72, 0x23,
        0x09, 0x10, 0xde, 0xb1, 0x6b,
    ];

    let algo = HashAlgo::sha1();
    let mut hasher = algo.hash_init().expect("init sha1");
    hasher.update(&data[..512]).expect("update sha1 part1");
    hasher.update(&data[512..]).expect("update sha1 part2");
    let mut actual_digest = [0u8; 20];
    hasher.finish(Some(&mut actual_digest)).expect("final sha1");
    assert_eq!(actual_digest, EXPECTED_DIGEST);
}

fn sha1_monte_vector_one_shot(vector: &ShaMonteTestVector) {
    // NIST SHA-1 Monte Carlo (one-shot) algorithm (as specified by the .rsp):
    //
    // INPUT: Seed (L bytes)
    // for j in 0..100 {
    //   MD0 = MD1 = MD2 = Seed
    //   for i in 3..1003 {
    //     Mi  = MD(i-3) || MD(i-2) || MD(i-1)
    //     MDi = SHA1(Mi)
    //   }
    //   Seed = MD1002
    //   OUTPUT: MDj == Seed
    // }

    let mut algo = HashAlgo::sha1();
    let digest_len = algo.hash(&[], None).expect("sha1 size query");
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

            let written = algo
                .hash(&mi, Some(md3.as_mut_slice()))
                .expect("sha1 monte hash");
            assert_eq!(written, digest_len);

            // Rotate MDs for next iteration,
            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA1 NIST Monte Carlo (one-shot) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha1_monte_vector_streaming(vector: &ShaMonteTestVector) {
    let mut algo = HashAlgo::sha1();
    let digest_len = algo.hash(&[], None).expect("sha1 size query");
    assert_eq!(digest_len, vector.expected_digest_len_bytes);
    assert_eq!(vector.seed.len(), digest_len);

    let mut seed = vec![0u8; digest_len];
    seed.copy_from_slice(vector.seed);

    let mut md0 = vec![0u8; digest_len];
    let mut md1 = vec![0u8; digest_len];
    let mut md2 = vec![0u8; digest_len];
    let mut md3 = vec![0u8; digest_len];

    for (j, expected_digest) in vector.expected_digests.iter().enumerate() {
        assert_eq!(expected_digest.len(), digest_len);

        md0.clone_from(&seed);
        md1.clone_from(&seed);
        md2.clone_from(&seed);

        for _i in 3..1003 {
            // Mi = MD(i-3) || MD(i-2) || MD(i-1)
            // Exercise incremental hashing by feeding Mi in multiple updates.
            let mut ctx = algo.clone().hash_init().expect("init sha1");

            // Split each MD into non-uniform chunks.
            ctx.update(&md0[..1]).expect("sha1 update");
            ctx.update(&md0[1..]).expect("sha1 update");

            ctx.update(&md1[..7]).expect("sha1 update");
            ctx.update(&md1[7..]).expect("sha1 update");

            ctx.update(&md2[..13]).expect("sha1 update");
            ctx.update(&md2[13..]).expect("sha1 update");

            let written = ctx.finish(Some(md3.as_mut_slice())).expect("sha1 finish");
            assert_eq!(written, digest_len);

            // Rotate MDs for next iteration.
            std::mem::swap(&mut md0, &mut md1);
            std::mem::swap(&mut md1, &mut md2);
            std::mem::swap(&mut md2, &mut md3);
        }

        seed.clone_from(&md2);

        if seed.as_slice() != *expected_digest {
            panic!(
                "SHA1 NIST Monte Carlo (streaming) failed!\nOuterIter(j): {}\nSeed/MD1002 Expected: {:02x?}\nSeed/MD1002 Actual:   {:02x?}",
                j, expected_digest, seed
            );
        }
    }
}

fn sha1_vector_one_shot(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha1();
    let required_len = algo.hash(vector.msg, None).expect("sha1 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut actual = vec![0u8; required_len];
    let written = algo
        .hash(vector.msg, Some(actual.as_mut_slice()))
        .expect("sha1 one-shot");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA1 NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn sha1_vector_streaming(vector: &ShaTestVector) {
    let mut algo = HashAlgo::sha1();
    let required_len = algo.hash(&[], None).expect("sha1 size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut ctx = algo.hash_init().expect("init sha1");

    // Feed input in multiple chunk sizes to exercise streaming.
    let chunk_sizes = [1usize, 3, 7, 12, 2, 19, 64, 128];
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;

    while cursor < vector.msg.len() {
        let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
        chunk_index += 1;

        let end = (cursor + chunk_len).min(vector.msg.len());
        ctx.update(&vector.msg[cursor..end]).expect("sha1 update");
        cursor = end;
    }

    let mut actual = vec![0u8; required_len];
    let written = ctx
        .finish(Some(actual.as_mut_slice()))
        .expect("sha1 finish");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "SHA1 NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

#[test]
fn test_sha1_nist_short_msg_vectors_one_shot() {
    for vector in SHA1_SHORT_MSG_TEST_VECTORS {
        sha1_vector_one_shot(vector);
    }
}

#[test]
fn test_sha1_nist_short_msg_vectors_streaming() {
    for vector in SHA1_SHORT_MSG_TEST_VECTORS {
        sha1_vector_streaming(vector);
    }
}

#[test]
fn test_sha1_nist_long_msg_vectors_one_shot() {
    for vector in SHA1_LONG_MSG_TEST_VECTORS {
        sha1_vector_one_shot(vector);
    }
}

#[test]
fn test_sha1_nist_long_msg_vectors_streaming() {
    for vector in SHA1_LONG_MSG_TEST_VECTORS {
        sha1_vector_streaming(vector);
    }
}

#[test]
fn test_sha1_nist_monte_vectors_one_shot() {
    for vector in SHA1_MONTE_TEST_VECTORS {
        sha1_monte_vector_one_shot(vector);
    }
}

#[test]
fn test_sha1_nist_monte_vectors_streaming() {
    for vector in SHA1_MONTE_TEST_VECTORS {
        sha1_monte_vector_streaming(vector);
    }
}
