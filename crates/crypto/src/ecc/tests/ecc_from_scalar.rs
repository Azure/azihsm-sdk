// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for [`EccPrivateKey::from_scalar`].
//!
//! These tests verify that:
//!
//! - A key built from a raw scalar `d` produces the same `(X, Y)` public point
//!   as the key it was derived from (round-trip via PKCS#8).
//! - Known-answer tests with `d = 1` produce the curve generator `G`.
//! - Known-answer tests with `d = n - 1` produce `-G` (same `X`, mirrored `Y`).
//! - Invalid scalars are rejected with the expected errors.
//!
//! The same test bodies execute on both the OpenSSL and Windows CNG backends,
//! so they serve as cross-platform parity tests for the deterministic
//! key-generation path.

use super::*;

fn scalar_one(point_size: usize) -> Vec<u8> {
    let mut s = vec![0u8; point_size];
    s[point_size - 1] = 1;
    s
}

fn scalar_n_minus_one(curve: EccCurve) -> Vec<u8> {
    let mut s = curve.order().to_vec();
    // Subtract 1 from big-endian byte string. Order's last byte is always > 0 for
    // the supported curves, so this is a single byte decrement.
    *s.last_mut().expect("order must be non-empty") -= 1;
    s
}

fn check_d_eq_one(curve: EccCurve, gx: &[u8], gy: &[u8]) {
    let d = scalar_one(curve.point_size());
    let key = EccPrivateKey::from_scalar(curve, &d).expect("from_scalar(d=1) failed");
    assert_eq!(key.curve(), curve);
    let (x, y) = key.coord_vec().expect("coord_vec failed");
    assert_eq!(x.as_slice(), gx, "X != Gx for d=1 on {:?}", curve);
    assert_eq!(y.as_slice(), gy, "Y != Gy for d=1 on {:?}", curve);
}

fn check_d_eq_n_minus_one(curve: EccCurve, gx: &[u8], gy: &[u8]) {
    let d = scalar_n_minus_one(curve);
    let key = EccPrivateKey::from_scalar(curve, &d).expect("from_scalar(d=n-1) failed");
    let (x, y) = key.coord_vec().expect("coord_vec failed");
    assert_eq!(x.as_slice(), gx, "X != Gx for d=n-1 on {:?}", curve);
    let neg_gy = negate_y_modp(curve, gy);
    assert_eq!(y, neg_gy, "Y != -Gy mod p for d=n-1 on {:?}", curve);
}

fn check_round_trip(curve: EccCurve) {
    // Generate a fresh random key, extract its raw scalar d via the PKCS#8
    // export path, then rebuild a key from that scalar and assert both keys
    // produce the same public coordinates.
    let key1 = EccPrivateKey::from_curve(curve).expect("from_curve failed");
    let der = export_key_bytes(&key1);
    let parsed = DerEccPrivateKey::from_der(&der).expect("DerEccPrivateKey::from_der failed");
    assert_eq!(parsed.curve(), curve);
    assert_eq!(parsed.priv_key().len(), curve.point_size());

    let key2 = EccPrivateKey::from_scalar(curve, parsed.priv_key())
        .expect("from_scalar round-trip failed");
    assert_eq!(key2.curve(), curve);

    let coord1 = key1.coord_vec().expect("coord_vec key1");
    let coord2 = key2.coord_vec().expect("coord_vec key2");
    assert_eq!(coord1, coord2, "public coords differ on round-trip");
}

fn check_sign_verify_round_trip(curve: EccCurve) {
    // Build a key via from_scalar, then sign/verify a digest to make sure the
    // imported key is usable for ECDSA on the active backend.
    let key1 = EccPrivateKey::from_curve(curve).expect("from_curve failed");
    let der = export_key_bytes(&key1);
    let parsed = DerEccPrivateKey::from_der(&der).expect("from_der failed");
    let pri = EccPrivateKey::from_scalar(curve, parsed.priv_key()).expect("from_scalar failed");
    let pubk = pri.public_key().expect("public_key failed");

    let digest = vec![0xa5u8; curve.point_size()];
    let mut algo = EccAlgo {};
    let sig_size = Signer::sign(&mut algo, &pri, &digest, None).expect("sign size");
    let mut sig = vec![0u8; sig_size];
    Signer::sign(&mut algo, &pri, &digest, Some(&mut sig)).expect("sign");
    assert!(Verifier::verify(&mut algo, &pubk, &digest, &sig).expect("verify"));
}

fn check_negative_cases(curve: EccCurve) {
    // Wrong length.
    let short = vec![1u8; curve.point_size() - 1];
    assert_eq!(
        EccPrivateKey::from_scalar(curve, &short).err(),
        Some(CryptoError::EccInvalidKeySize),
    );
    let long = vec![1u8; curve.point_size() + 1];
    assert_eq!(
        EccPrivateKey::from_scalar(curve, &long).err(),
        Some(CryptoError::EccInvalidKeySize),
    );

    // d == 0.
    let zero = vec![0u8; curve.point_size()];
    assert_eq!(
        EccPrivateKey::from_scalar(curve, &zero).err(),
        Some(CryptoError::EccKeyImportError),
    );

    // d == n (curve order) — out of range.
    let order = curve.order().to_vec();
    assert_eq!(
        EccPrivateKey::from_scalar(curve, &order).err(),
        Some(CryptoError::EccKeyImportError),
    );

    // d > n: all-0xff is always >= curve order for supported curves.
    let max = vec![0xffu8; curve.point_size()];
    assert_eq!(
        EccPrivateKey::from_scalar(curve, &max).err(),
        Some(CryptoError::EccKeyImportError),
    );
}

#[test]
fn p256_from_scalar_d_eq_one_is_generator() {
    check_d_eq_one(EccCurve::P256, &P256_GX, &P256_GY);
}

#[test]
fn p384_from_scalar_d_eq_one_is_generator() {
    check_d_eq_one(EccCurve::P384, &P384_GX, &P384_GY);
}

#[test]
fn p521_from_scalar_d_eq_one_is_generator() {
    check_d_eq_one(EccCurve::P521, &P521_GX, &P521_GY);
}

#[test]
fn p256_from_scalar_d_eq_n_minus_one_is_negated_generator() {
    check_d_eq_n_minus_one(EccCurve::P256, &P256_GX, &P256_GY);
}

#[test]
fn p384_from_scalar_d_eq_n_minus_one_is_negated_generator() {
    check_d_eq_n_minus_one(EccCurve::P384, &P384_GX, &P384_GY);
}

#[test]
fn p521_from_scalar_d_eq_n_minus_one_is_negated_generator() {
    check_d_eq_n_minus_one(EccCurve::P521, &P521_GX, &P521_GY);
}

#[test]
fn p256_from_scalar_round_trip() {
    check_round_trip(EccCurve::P256);
}

#[test]
fn p384_from_scalar_round_trip() {
    check_round_trip(EccCurve::P384);
}

#[test]
fn p521_from_scalar_round_trip() {
    check_round_trip(EccCurve::P521);
}

#[test]
fn p256_from_scalar_sign_verify() {
    check_sign_verify_round_trip(EccCurve::P256);
}

#[test]
fn p384_from_scalar_sign_verify() {
    check_sign_verify_round_trip(EccCurve::P384);
}

#[test]
fn p521_from_scalar_sign_verify() {
    check_sign_verify_round_trip(EccCurve::P521);
}

#[test]
fn p256_from_scalar_negative_cases() {
    check_negative_cases(EccCurve::P256);
}

#[test]
fn p384_from_scalar_negative_cases() {
    check_negative_cases(EccCurve::P384);
}

#[test]
fn p521_from_scalar_negative_cases() {
    check_negative_cases(EccCurve::P521);
}
