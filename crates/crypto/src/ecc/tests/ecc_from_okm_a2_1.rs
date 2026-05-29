// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for [`EccPrivateKey::from_okm_a2_1`] (FIPS 186-5 Appendix A.2.1).
//!
//! Covers:
//! - The required OKM length per curve (`a2_1_okm_len`).
//! - Boundary KATs for the `d = (c mod (n - 1)) + 1` reduction:
//!     * `c = 0`     ⇒ `d = 1`     ⇒ `Q = G`.
//!     * `c = n - 1` ⇒ `d = 1`     ⇒ `Q = G`.
//!     * `c = n - 2` ⇒ `d = n - 1` ⇒ `Q = -G`.
//!     * `c = n`     ⇒ `d = 2`     ⇒ `Q = 2*G`.
//! - Length validation rejects too-short and too-long OKM with
//!   [`CryptoError::EccInvalidKeySize`].
//! - Determinism: identical OKM yields identical public coords.

use super::*;

fn okm_zero(curve: EccCurve) -> Vec<u8> {
    vec![0u8; curve.a2_1_okm_len()]
}

/// Build an OKM of length `curve.a2_1_okm_len()` whose big-endian integer
/// value equals `be_value` left-padded with zeros.
fn okm_with_value(curve: EccCurve, be_value: &[u8]) -> Vec<u8> {
    let len = curve.a2_1_okm_len();
    assert!(be_value.len() <= len);
    let mut out = vec![0u8; len];
    let offset = len - be_value.len();
    out[offset..].copy_from_slice(be_value);
    out
}

fn order_minus_k(curve: EccCurve, k: u8) -> Vec<u8> {
    let mut n = curve.order().to_vec();
    *n.last_mut().unwrap() -= k;
    n
}

fn check_c_eq_zero(curve: EccCurve) {
    let okm = okm_zero(curve);
    let key = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("from_okm_a2_1(c=0) failed");
    let (x, y) = key.coord_vec().expect("coord_vec failed");
    let (gx, gy) = generator(curve);
    assert_eq!(x, gx, "X != Gx for c=0 on {:?}", curve);
    assert_eq!(y, gy, "Y != Gy for c=0 on {:?}", curve);
}

fn check_c_eq_n_minus_one(curve: EccCurve) {
    let okm = okm_with_value(curve, &order_minus_k(curve, 1));
    let key = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("from_okm_a2_1(c=n-1) failed");
    let (x, y) = key.coord_vec().expect("coord_vec failed");
    let (gx, gy) = generator(curve);
    assert_eq!(x, gx, "X != Gx for c=n-1 on {:?}", curve);
    assert_eq!(y, gy, "Y != Gy for c=n-1 on {:?}", curve);
}

fn check_c_eq_n_minus_two(curve: EccCurve) {
    let okm = okm_with_value(curve, &order_minus_k(curve, 2));
    let key = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("from_okm_a2_1(c=n-2) failed");
    let (x, y) = key.coord_vec().expect("coord_vec failed");
    let (gx, gy) = generator(curve);
    assert_eq!(x, gx, "X != Gx for c=n-2 on {:?}", curve);
    let neg_gy = negate_y_modp(curve, &gy);
    assert_eq!(y, neg_gy, "Y != -Gy for c=n-2 on {:?}", curve);
}

fn check_c_eq_n(curve: EccCurve) {
    // c = n ⇒ c mod (n - 1) = 1 ⇒ d = 2 ⇒ Q = 2 * G.
    let okm = okm_with_value(curve, curve.order());
    let key_okm = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("from_okm_a2_1(c=n) failed");

    // Reference: d = 2 via from_scalar.
    let mut d_two = vec![0u8; curve.point_size()];
    *d_two.last_mut().unwrap() = 2;
    let key_ref = EccPrivateKey::from_scalar(curve, &d_two).expect("from_scalar(d=2) failed");

    assert_eq!(
        key_okm.coord_vec().unwrap(),
        key_ref.coord_vec().unwrap(),
        "Q != 2*G for c=n on {:?}",
        curve,
    );
}

fn check_determinism(curve: EccCurve) {
    let mut okm = okm_zero(curve);
    for (i, b) in okm.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x9d).wrapping_add(0x37);
    }
    let k1 = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("derive 1");
    let k2 = EccPrivateKey::from_okm_a2_1(curve, &okm).expect("derive 2");
    assert_eq!(
        k1.coord_vec().unwrap(),
        k2.coord_vec().unwrap(),
        "determinism on {:?}",
        curve,
    );
}

fn check_length_validation(curve: EccCurve) {
    let need = curve.a2_1_okm_len();

    let short = vec![0u8; need - 1];
    assert_eq!(
        EccPrivateKey::from_okm_a2_1(curve, &short).err(),
        Some(CryptoError::EccInvalidKeySize),
    );

    let long = vec![0u8; need + 1];
    assert_eq!(
        EccPrivateKey::from_okm_a2_1(curve, &long).err(),
        Some(CryptoError::EccInvalidKeySize),
    );
}

#[test]
fn a2_1_okm_len_matches_spec() {
    assert_eq!(EccCurve::P256.a2_1_okm_len(), 40);
    assert_eq!(EccCurve::P384.a2_1_okm_len(), 56);
    assert_eq!(EccCurve::P521.a2_1_okm_len(), 74);
}

#[test]
fn p256_from_okm_a2_1_c_eq_zero_is_generator() {
    check_c_eq_zero(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_c_eq_zero_is_generator() {
    check_c_eq_zero(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_c_eq_zero_is_generator() {
    check_c_eq_zero(EccCurve::P521);
}

#[test]
fn p256_from_okm_a2_1_c_eq_n_minus_one_is_generator() {
    check_c_eq_n_minus_one(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_c_eq_n_minus_one_is_generator() {
    check_c_eq_n_minus_one(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_c_eq_n_minus_one_is_generator() {
    check_c_eq_n_minus_one(EccCurve::P521);
}

#[test]
fn p256_from_okm_a2_1_c_eq_n_minus_two_is_negated_generator() {
    check_c_eq_n_minus_two(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_c_eq_n_minus_two_is_negated_generator() {
    check_c_eq_n_minus_two(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_c_eq_n_minus_two_is_negated_generator() {
    check_c_eq_n_minus_two(EccCurve::P521);
}

#[test]
fn p256_from_okm_a2_1_c_eq_n_is_two_times_g() {
    check_c_eq_n(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_c_eq_n_is_two_times_g() {
    check_c_eq_n(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_c_eq_n_is_two_times_g() {
    check_c_eq_n(EccCurve::P521);
}

#[test]
fn p256_from_okm_a2_1_is_deterministic() {
    check_determinism(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_is_deterministic() {
    check_determinism(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_is_deterministic() {
    check_determinism(EccCurve::P521);
}

#[test]
fn p256_from_okm_a2_1_length_validation() {
    check_length_validation(EccCurve::P256);
}

#[test]
fn p384_from_okm_a2_1_length_validation() {
    check_length_validation(EccCurve::P384);
}

#[test]
fn p521_from_okm_a2_1_length_validation() {
    check_length_validation(EccCurve::P521);
}
