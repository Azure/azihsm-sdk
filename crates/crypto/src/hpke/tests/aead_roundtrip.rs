// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AEAD round-trip for both GCM and CBC-HMAC variants in all three
//! curve sizes. Also asserts tag tampering returns
//! [`CryptoError::HpkeAeadOpenFailed`].

use crate::CryptoError;
use crate::HpkeSuite;
use crate::Rng;
use crate::hpke::aead;

fn random_key_nonce(suite: HpkeSuite) -> (Vec<u8>, Vec<u8>) {
    let mut key = vec![0u8; suite.nk()];
    let mut nonce = vec![0u8; suite.nn()];
    Rng::rand_bytes(&mut key).unwrap();
    Rng::rand_bytes(&mut nonce).unwrap();
    (key, nonce)
}

#[test]
fn gcm_roundtrip_empty_aad() {
    for &suite in &[
        HpkeSuite::DHKemP256Sha256AesGcm256,
        HpkeSuite::DHKemP384Sha384AesGcm256,
        HpkeSuite::DHKemP521Sha512AesGcm256,
    ] {
        let (key, nonce) = random_key_nonce(suite);
        let pt = b"hello, hpke";
        let mut ct = vec![0u8; aead::ct_len(suite, pt.len())];
        let n = aead::seal(suite, &key, &nonce, &[], pt, &mut ct).unwrap();
        assert_eq!(n, ct.len());
        let mut out = vec![0u8; ct.len()];
        let m = aead::open(suite, &key, &nonce, &[], &ct, &mut out).unwrap();
        assert_eq!(&out[..m], pt);
    }
}

#[test]
fn gcm_roundtrip_with_aad() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let (key, nonce) = random_key_nonce(suite);
    let pt = b"hello, hpke";
    let aad = b"some-aad";
    let mut ct = vec![0u8; aead::ct_len(suite, pt.len())];
    aead::seal(suite, &key, &nonce, aad, pt, &mut ct).unwrap();
    let mut out = vec![0u8; ct.len()];
    let n = aead::open(suite, &key, &nonce, aad, &ct, &mut out).unwrap();
    assert_eq!(&out[..n], pt);
}

#[test]
fn cbc_roundtrip_with_aad() {
    for &suite in &[
        HpkeSuite::DHKemP256Sha256Aes256Cbc,
        HpkeSuite::DHKemP384Sha384Aes256Cbc,
        HpkeSuite::DHKemP521Sha512Aes256Cbc,
    ] {
        let (key, nonce) = random_key_nonce(suite);
        let pt = b"hello, cbc-hmac";
        let aad = b"hpke-aad";
        let mut ct = vec![0u8; aead::ct_len(suite, pt.len())];
        aead::seal(suite, &key, &nonce, aad, pt, &mut ct).unwrap();
        let mut out = vec![0u8; ct.len()];
        let n = aead::open(suite, &key, &nonce, aad, &ct, &mut out).unwrap();
        assert_eq!(&out[..n], pt);
    }
}

#[test]
fn gcm_tag_tamper_fails() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let (key, nonce) = random_key_nonce(suite);
    let pt = b"important";
    let mut ct = vec![0u8; aead::ct_len(suite, pt.len())];
    aead::seal(suite, &key, &nonce, &[], pt, &mut ct).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    let mut out = vec![0u8; ct.len()];
    let err = aead::open(suite, &key, &nonce, &[], &ct, &mut out).unwrap_err();
    assert_eq!(err, CryptoError::HpkeAeadOpenFailed);
}

#[test]
fn cbc_tag_tamper_fails() {
    let suite = HpkeSuite::DHKemP256Sha256Aes256Cbc;
    let (key, nonce) = random_key_nonce(suite);
    let pt = b"important";
    let mut ct = vec![0u8; aead::ct_len(suite, pt.len())];
    aead::seal(suite, &key, &nonce, &[], pt, &mut ct).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    let mut out = vec![0u8; ct.len()];
    let err = aead::open(suite, &key, &nonce, &[], &ct, &mut out).unwrap_err();
    assert_eq!(err, CryptoError::HpkeAeadOpenFailed);
}
