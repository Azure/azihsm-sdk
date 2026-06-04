// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-schedule output stability tests across all four modes.

use crate::HpkeSuite;
use crate::hpke::schedule::key_schedule;

#[test]
fn modes_produce_different_keys() {
    // Same shared_secret + info, different mode bytes — outputs must
    // diverge (mode is a distinct input to the KSC).
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let shared = vec![0xAAu8; suite.nsecret()];
    let info = b"app";

    let (key0, nonce0) = key_schedule(suite, 0x00, &shared, info, &[], &[]).expect("base");
    let (key1, nonce1) = key_schedule(suite, 0x01, &shared, info, b"pskbytes", b"id").expect("psk");
    let (key2, nonce2) = key_schedule(suite, 0x02, &shared, info, &[], &[]).expect("auth");
    let (key3, nonce3) =
        key_schedule(suite, 0x03, &shared, info, b"pskbytes", b"id").expect("auth_psk");

    assert_ne!(key0, key1);
    assert_ne!(key0, key2);
    assert_ne!(key0, key3);
    assert_ne!(key1, key2);
    assert_ne!(key1, key3);
    assert_ne!(key2, key3);
    assert_ne!(nonce0, nonce1);
    assert_ne!(nonce0, nonce2);
    assert_ne!(nonce0, nonce3);
}

#[test]
fn key_schedule_is_deterministic() {
    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    let shared = vec![0x55u8; suite.nsecret()];
    let info = b"deterministic";

    let a = key_schedule(suite, 0x00, &shared, info, &[], &[]).unwrap();
    let b = key_schedule(suite, 0x00, &shared, info, &[], &[]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn key_schedule_sizes_per_suite() {
    for &suite in &[
        HpkeSuite::DHKemP256Sha256AesGcm256,
        HpkeSuite::DHKemP256Sha256Aes256Cbc,
        HpkeSuite::DHKemP384Sha384AesGcm256,
        HpkeSuite::DHKemP384Sha384Aes256Cbc,
        HpkeSuite::DHKemP521Sha512AesGcm256,
        HpkeSuite::DHKemP521Sha512Aes256Cbc,
    ] {
        let shared = vec![0u8; suite.nsecret()];
        let (key, nonce) = key_schedule(suite, 0x00, &shared, &[], &[], &[]).expect("ks");
        assert_eq!(key.len(), suite.nk(), "key len mismatch for {:?}", suite);
        assert_eq!(
            nonce.len(),
            suite.nn(),
            "nonce len mismatch for {:?}",
            suite
        );
    }
}
