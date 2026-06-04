// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Self-consistency tests for HPKE `LabeledExtract` / `LabeledExpand`.

use crate::HpkeSuite;
use crate::hpke::kdf::labeled_expand;
use crate::hpke::kdf::labeled_extract;

#[test]
fn labeled_extract_is_deterministic() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let algo = suite.kdf_hash();
    let suite_id = suite.hpke_suite_id();
    let a = labeled_extract(&algo, &suite_id, b"salt", b"label", b"ikm").unwrap();
    let b = labeled_extract(&algo, &suite_id, b"salt", b"label", b"ikm").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);
}

#[test]
fn labeled_expand_is_deterministic_and_sized() {
    let suite = HpkeSuite::DHKemP384Sha384AesGcm256;
    let algo = suite.kdf_hash();
    let suite_id = suite.hpke_suite_id();
    let prk = vec![0xAAu8; 48];
    let out1 = labeled_expand(&algo, &suite_id, &prk, b"key", b"ctx", 80).unwrap();
    let out2 = labeled_expand(&algo, &suite_id, &prk, b"key", b"ctx", 80).unwrap();
    assert_eq!(out1, out2);
    assert_eq!(out1.len(), 80);
}

#[test]
fn labeled_expand_rejects_oversize() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let algo = suite.kdf_hash();
    let suite_id = suite.hpke_suite_id();
    let prk = vec![0u8; 32];
    let l = 255 * 32 + 1;
    let err = labeled_expand(&algo, &suite_id, &prk, b"k", b"", l).unwrap_err();
    assert_eq!(err, crate::CryptoError::HpkeExportTooLarge);
}

#[test]
fn label_diverges_outputs() {
    let suite = HpkeSuite::DHKemP256Sha256AesGcm256;
    let algo = suite.kdf_hash();
    let suite_id = suite.hpke_suite_id();
    let a = labeled_extract(&algo, &suite_id, &[], b"label-a", b"ikm").unwrap();
    let b = labeled_extract(&algo, &suite_id, &[], b"label-b", b"ikm").unwrap();
    assert_ne!(a, b);
}

#[test]
fn suite_id_diverges_outputs() {
    let s1 = HpkeSuite::DHKemP256Sha256AesGcm256;
    let s2 = HpkeSuite::DHKemP384Sha384AesGcm256;
    let id1 = s1.hpke_suite_id();
    let id2 = s2.hpke_suite_id();
    let algo = s1.kdf_hash();
    let a = labeled_extract(&algo, &id1, &[], b"label", b"ikm").unwrap();
    let b = labeled_extract(&algo, &id2, &[], b"label", b"ikm").unwrap();
    assert_ne!(a, b);
}
