// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::hmac::tests::testvectors::HMAC_SHA256_NIST_TEST_VECTORS;

#[test]
fn test_hmac_sha256_one_shot() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 32] = [0; 32];
    const EXPECTED_MAC: [u8; 32] = [
        0x77, 0x3E, 0xA9, 0x1E, 0x36, 0x80, 0x0E, 0x46, 0x85, 0x4D, 0xB8, 0xEB, 0xD0, 0x91, 0x81,
        0xA7, 0x29, 0x59, 0x09, 0x8B, 0x3E, 0xF8, 0xC1, 0x22, 0xD9, 0x63, 0x55, 0x14, 0xCE, 0xD5,
        0x65, 0xFE,
    ];
    let hash = HashAlgo::sha256();
    let mut hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha256 key");
    let result = Signer::sign(&mut hmac, &key, &DATA, Some(&mut actual_mac));
    assert!(result.is_ok());
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha256_streaming() {
    const KEY: [u8; 20] = [0xAAu8; 20];
    const DATA: [u8; 50] = [0xDDu8; 50];
    let mut actual_mac: [u8; 32] = [0; 32];
    const EXPECTED_MAC: [u8; 32] = [
        0x77, 0x3E, 0xA9, 0x1E, 0x36, 0x80, 0x0E, 0x46, 0x85, 0x4D, 0xB8, 0xEB, 0xD0, 0x91, 0x81,
        0xA7, 0x29, 0x59, 0x09, 0x8B, 0x3E, 0xF8, 0xC1, 0x22, 0xD9, 0x63, 0x55, 0x14, 0xCE, 0xD5,
        0x65, 0xFE,
    ];
    let hash = HashAlgo::sha256();
    let hmac = HmacAlgo::new(hash);
    let key = HmacKey::from_bytes(&KEY).expect("create hmac sha256 key");
    let mut sign_context = Signer::sign_init(hmac, key).expect("init hmac sha256 sign");
    sign_context
        .update(&DATA[..25])
        .expect("update hmac sha256 sign part1");
    sign_context
        .update(&DATA[25..])
        .expect("update hmac sha256 sign part2");
    sign_context
        .finish(Some(&mut actual_mac))
        .expect("final hmac sha256 sign");
    assert_eq!(actual_mac, EXPECTED_MAC);
}

#[test]
fn test_hmac_sha256_nist_vectors() {
    for vector in HMAC_SHA256_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha256();
        let mut hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha256 key");
        let mut actual_mac: [u8; 32] = [0; 32];
        let result = Signer::sign(&mut hmac, &key, vector.msg, Some(&mut actual_mac));
        assert!(result.is_ok());
        //check if returned mac size matches expected
        assert_eq!(result.unwrap(), actual_mac.len());
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA256 NIST test vector failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}

#[test]
fn test_hmac_sha256_nist_vectors_streaming() {
    for vector in HMAC_SHA256_NIST_TEST_VECTORS {
        let hash = HashAlgo::sha256();
        let hmac = HmacAlgo::new(hash);
        let key = HmacKey::from_bytes(vector.key).expect("create NIST hmac sha256 key");
        let mut actual_mac: [u8; 32] = [0; 32];
        let mut sign_context = Signer::sign_init(hmac, key).expect("init NIST hmac sha256 sign");
        // split the message into two parts for update
        let mid = vector.msg.len() / 2;
        sign_context
            .update(&vector.msg[..mid])
            .expect("update NIST hmac sha256 sign part1");
        sign_context
            .update(&vector.msg[mid..])
            .expect("update NIST hmac sha256 sign part2");
        sign_context
            .finish(Some(&mut actual_mac))
            .expect("final NIST hmac sha256 sign");
        if actual_mac != vector.mac {
            panic!(
                "HMAC SHA256 NIST test vector(streaming) failed!\nTest Count ID: {}\nKey: {:02x?}\nMsg: {:02x?}\nExpected MAC: {:02x?}\nActual MAC: {:02x?}",
                vector.vector_count_id, vector.key, vector.msg, vector.mac, actual_mac
            );
        }
    }
}
