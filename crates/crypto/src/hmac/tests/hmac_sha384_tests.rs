// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hmac::tests::testvectors::HMAC_SHA384_NIST_TEST_VECTORS;

#[test]
fn test_hmac_sha384_one_shot() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 48] = [0; 48];
    const EXPECTED_MAC: [u8; 48] = [
        0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0, 0x14, 0xc8, 0xa8,
        0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb, 0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66,
        0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d, 0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a, 0xb6, 0xe1, 0x01,
        0xa3, 0x4f, 0x27,
    ];
    let hash = HashAlgo::sha384();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha384 key");
    let result = Signer::sign(&mut hmac, &key, &DATA, Some(&mut actual_mac));
    assert!(result.is_ok());
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha384_streaming() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 48] = [0; 48];
    const EXPECTED_MAC: [u8; 48] = [
        0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0, 0x14, 0xc8, 0xa8,
        0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb, 0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66,
        0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d, 0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a, 0xb6, 0xe1, 0x01,
        0xa3, 0x4f, 0x27,
    ];
    let hash = HashAlgo::sha384();
    let hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha384 key");
    let mut sign_context = Signer::sign_init(hmac, key).expect("init hmac sha384 sign");
    sign_context
        .update(&DATA[..25])
        .expect("update hmac sha384 sign part1");
    sign_context
        .update(&DATA[25..])
        .expect("update hmac sha384 sign part2");
    sign_context
        .finish(Some(&mut actual_mac))
        .expect("final hmac sha384 sign");
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha384_nist_vectors() {
    for vector in HMAC_SHA384_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha384();
        let mut hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha384 key");
        let mut actual_mac: [u8; 48] = [0; 48];
        let result = Signer::sign(&mut hmac, &key, vector.msg, Some(&mut actual_mac));
        assert!(result.is_ok());
        //check if returned mac size matches expected
        assert_eq!(result.unwrap(), actual_mac.len());
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA384 NIST test vector failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}

#[test]
fn test_hmac_sha384_nist_vectors_streaming() {
    for vector in HMAC_SHA384_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha384();
        let hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha384 key");
        let mut actual_mac: [u8; 48] = [0; 48];
        let mut sign_context = Signer::sign_init(hmac, key).expect("init NIST hmac sha384 sign");
        // split the message into two parts for update
        let mid = vector.msg.len() / 2;
        sign_context
            .update(&vector.msg[..mid])
            .expect("update NIST hmac sha384 sign part1");
        sign_context
            .update(&vector.msg[mid..])
            .expect("update NIST hmac sha384 sign part2");
        sign_context
            .finish(Some(&mut actual_mac))
            .expect("final NIST hmac sha384 sign");
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA384 NIST test vector(streaming) failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}
