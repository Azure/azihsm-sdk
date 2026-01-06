// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hmac::tests::testvectors::HMAC_SHA512_NIST_TEST_VECTORS;

#[test]
fn test_hmac_sha512_one_shot() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 64] = [0; 64];
    const EXPECTED_MAC: [u8; 64] = [
        0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b,
        0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27,
        0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e,
        0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59,
        0xe1, 0x32, 0x92, 0xfb,
    ];
    let hash = HashAlgo::sha512();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha512 key");
    let result = Signer::sign(&mut hmac, &key, &DATA, Some(&mut actual_mac));
    assert!(result.is_ok());
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha512_streaming() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 64] = [0; 64];
    const EXPECTED_MAC: [u8; 64] = [
        0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b,
        0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27,
        0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e,
        0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59,
        0xe1, 0x32, 0x92, 0xfb,
    ];
    let hash = HashAlgo::sha512();
    let hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha512 key");
    let mut sign_context = Signer::sign_init(hmac, key).expect("init hmac sha512 sign");
    sign_context
        .update(&DATA[..25])
        .expect("update hmac sha512 sign part1");
    sign_context
        .update(&DATA[25..])
        .expect("update hmac sha512 sign part2");
    sign_context
        .finish(Some(&mut actual_mac))
        .expect("final hmac sha512 sign");
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha512_nist_vectors() {
    for vector in HMAC_SHA512_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha512();
        let mut hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha512 key");
        let mut actual_mac: [u8; 64] = [0; 64];
        let result = Signer::sign(&mut hmac, &key, vector.msg, Some(&mut actual_mac));
        assert!(result.is_ok());
        //check if returned mac size matches expected
        assert_eq!(result.unwrap(), actual_mac.len());
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA512 NIST test vector failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}

#[test]
fn test_hmac_sha512_nist_vectors_streaming() {
    for vector in HMAC_SHA512_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha512();
        let hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha512 key");
        let mut actual_mac: [u8; 64] = [0; 64];
        let mut sign_context = Signer::sign_init(hmac, key).expect("init NIST hmac sha512 sign");
        // split the message into two parts for update
        let mid = vector.msg.len() / 2;
        sign_context
            .update(&vector.msg[..mid])
            .expect("update NIST hmac sha512 sign part1");
        sign_context
            .update(&vector.msg[mid..])
            .expect("update NIST hmac sha512 sign part2");
        sign_context
            .finish(Some(&mut actual_mac))
            .expect("final NIST hmac sha512 sign");
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA512 NIST test vector(streaming) failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}
