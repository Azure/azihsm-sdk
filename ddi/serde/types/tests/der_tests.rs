// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::*;
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
use azihsm_ddi_types::*;

#[cfg(feature = "pre_encode")]
fn test_ecc_pub_key_der_to_raw(curve: DdiEccCurve) {
    let (curve_name, der_len) = match curve {
        DdiEccCurve::P256 => (EccCurve::P256, 32),
        DdiEccCurve::P384 => (EccCurve::P384, 48),
        DdiEccCurve::P521 => (EccCurve::P521, 66),
        _ => return,
    };

    // Generate ecc public key
    let ecc_private = EccPrivateKey::from_curve(curve_name).unwrap();
    let ecc_public = ecc_private.public_key().unwrap();
    let (x, y) = ecc_public.coord_vec().unwrap();

    // Get key in der format
    let public_key_der = ecc_public.to_vec().unwrap();

    // Call ecc_pub_key_der_to_raw to get affine coordinate data from der
    let key_data = ecc_pub_key_der_to_raw(&public_key_der).unwrap();

    // Verify key_data
    assert_eq!(key_data.curve, curve);
    // key_data might have a leading 0u8 byte, just compare up to OpenSSL data length
    let x_len_diff = der_len - x.len();
    let y_len_diff = der_len - y.len();
    assert_eq!(key_data.x[x_len_diff..der_len], x);
    assert_eq!(key_data.y[y_len_diff..der_len], y);
}

#[cfg(feature = "post_decode")]
fn test_ecc_pub_key_raw_to_der(curve: DdiEccCurve) {
    let (curve_name, der_len) = match curve {
        DdiEccCurve::P256 => (EccCurve::P256, 32),
        DdiEccCurve::P384 => (EccCurve::P384, 48),
        DdiEccCurve::P521 => (EccCurve::P521, 66),
        _ => return,
    };

    // Generate ecc public key
    let ecc_private = EccPrivateKey::from_curve(curve_name).unwrap();
    let ecc_public = ecc_private.public_key().unwrap();
    let (x, y) = ecc_public.coord_vec().unwrap();

    let mut x_array = [0u8; 66];
    let mut y_array = [0u8; 66];
    x_array[der_len - x.to_vec().len()..der_len].copy_from_slice(&x.to_vec());
    y_array[der_len - y.to_vec().len()..der_len].copy_from_slice(&y.to_vec());
    let pub_key_data = EccPublicKeyData {
        x: x_array,
        y: y_array,
        curve,
    };

    // Construct DER
    let der = ecc_pub_key_raw_to_der(pub_key_data.clone()).unwrap();

    // Test with inverse function (or test against OpenSSL to der?)
    let new_key_data = ecc_pub_key_der_to_raw(&der).unwrap();

    assert_eq!(pub_key_data, new_key_data);
    assert_eq!(pub_key_data.curve, new_key_data.curve);
    assert_eq!(pub_key_data.x, new_key_data.x);
    assert_eq!(pub_key_data.y, new_key_data.y);
}

#[cfg(feature = "post_decode")]
fn test_rsa_pub_key_raw_to_der(size: u32) {
    // Generate rsa public key

    let rsa_private = RsaPrivateKey::generate((size / 8) as usize).unwrap();

    let n = rsa_private.n_vec().unwrap();
    let e = rsa_private.e_vec().unwrap();

    let key_data = RsaPublicKeyData {
        n: n.clone(),
        e: e.clone(),
        little_endian: false,
    };
    let der_vec = rsa_pub_key_raw_to_der(key_data).unwrap();

    let rsa_public = RsaPublicKey::from_bytes(&der_vec).unwrap();
    let new_n = rsa_public.n_vec().unwrap();
    let new_e = rsa_public.e_vec().unwrap();

    // let new_size = rsa_public.
    // assert_eq!(size, new_size);
    assert_eq!(n, new_n);
    assert_eq!(e, new_e);
}

#[test]
#[cfg(feature = "pre_encode")]
fn test_ecc_pub_key_der_to_raw_256() {
    test_ecc_pub_key_der_to_raw(DdiEccCurve::P256);
}

#[test]
#[cfg(feature = "pre_encode")]
fn test_ecc_pub_key_der_to_raw_384() {
    test_ecc_pub_key_der_to_raw(DdiEccCurve::P384);
}

#[test]
#[cfg(feature = "pre_encode")]
fn test_ecc_pub_key_der_to_raw_521() {
    test_ecc_pub_key_der_to_raw(DdiEccCurve::P521);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_ecc_pub_key_raw_to_der_256() {
    test_ecc_pub_key_raw_to_der(DdiEccCurve::P256);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_ecc_pub_key_raw_to_der_384() {
    test_ecc_pub_key_raw_to_der(DdiEccCurve::P256);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_ecc_pub_key_raw_to_der_521() {
    test_ecc_pub_key_raw_to_der(DdiEccCurve::P256);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_rsa_pub_key_raw_to_der_2048() {
    test_rsa_pub_key_raw_to_der(2048);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_rsa_pub_key_raw_to_der_3072() {
    test_rsa_pub_key_raw_to_der(3072);
}

#[test]
#[cfg(feature = "post_decode")]
fn test_rsa_pub_key_raw_to_der_4096() {
    test_rsa_pub_key_raw_to_der(4096);
}
