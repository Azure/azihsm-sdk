// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hmac::tests::testvectors::HMAC_SHA1_NIST_TEST_VECTORS;

#[test]
fn test_hmac_sha1_one_shot() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 20] = [0; 20];
    const EXPECTED_MAC: [u8; 20] = [
        0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b,
        0x4f, 0x63, 0xf1, 0x75, 0xd3,
    ];
    let hash = HashAlgo::sha1();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha1 key");
    let result = Signer::sign(&mut hmac, &key, &DATA, Some(&mut actual_mac));
    assert!(result.is_ok());
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha1_streaming() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 20] = [0; 20];
    const EXPECTED_MAC: [u8; 20] = [
        0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b,
        0x4f, 0x63, 0xf1, 0x75, 0xd3,
    ];
    let hash = HashAlgo::sha1();
    let hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha1 key");
    let mut sign_context = Signer::sign_init(hmac, key).expect("init hmac sha1 sign");
    sign_context
        .update(&DATA[..25])
        .expect("update hmac sha1 sign part1");
    sign_context
        .update(&DATA[25..])
        .expect("update hmac sha1 sign part2");
    sign_context
        .finish(Some(&mut actual_mac))
        .expect("final hmac sha1 sign");
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_verify() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    const EXPECTED_MAC: [u8; 20] = [
        0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b,
        0x4f, 0x63, 0xf1, 0x75, 0xd3,
    ];
    let hash = HashAlgo::sha1();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha1 key");
    let result = Verifier::verify(&mut hmac, &key, &DATA, &EXPECTED_MAC).expect("verify hmac");
    assert!(result);
}

#[test]
fn test_hmac_verify_streaming() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    const EXPECTED_MAC: [u8; 20] = [
        0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b,
        0x4f, 0x63, 0xf1, 0x75, 0xd3,
    ];
    let hash = HashAlgo::sha1();
    let hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha1 key");
    let mut verify_context = Verifier::verify_init(hmac, key).expect("init hmac sha1 verify");
    verify_context
        .update(&DATA[..25])
        .expect("update hmac sha1 verify part1");
    verify_context
        .update(&DATA[25..])
        .expect("update hmac sha1 verify part2");
    let result = verify_context
        .finish(&EXPECTED_MAC)
        .expect("final hmac sha1 verify");
    assert!(result);
}

#[test]
fn test_hmac_sha1_nist_vectors() {
    for vector in HMAC_SHA1_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha1();
        let mut hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha1 key");
        let mut actual_mac: [u8; 20] = [0; 20];
        let result = Signer::sign(&mut hmac, &key, vector.msg, Some(&mut actual_mac));
        assert!(result.is_ok());
        //check if returned mac size matches expected
        assert_eq!(result.unwrap(), actual_mac.len());
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA1 NIST test vector failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}

#[test]
fn test_hmac_sha1_nist_vectors_streaming() {
    for vector in HMAC_SHA1_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha1();
        let hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha1 key");
        let mut actual_mac: [u8; 20] = [0; 20];
        let mut sign_context = Signer::sign_init(hmac, key).expect("init NIST hmac sha1 sign");
        // split the message into two parts for update
        let mid = vector.msg.len() / 2;
        sign_context
            .update(&vector.msg[..mid])
            .expect("update NIST hmac sha1 sign part1");
        sign_context
            .update(&vector.msg[mid..])
            .expect("update NIST hmac sha1 sign part2");
        sign_context
            .finish(Some(&mut actual_mac))
            .expect("final NIST hmac sha1 sign");
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA1 NIST test vector(streaming) failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}
