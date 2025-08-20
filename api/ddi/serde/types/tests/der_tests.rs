// Copyright (C) Microsoft Corporation. All rights reserved.

// TODO: Currently restricting tests to Linux as openssl use is disallowed on Windows
// and causes S360 issues. Need to find a good way to run these tests on Windows.
#![cfg(target_os = "linux")]

#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
use mcr_ddi_types::*;

#[cfg(feature = "pre_encode")]
fn test_ecc_pub_key_der_to_raw(curve: DdiEccCurve) {
    let (curve_name, der_len) = match curve {
        DdiEccCurve::P256 => (openssl::nid::Nid::X9_62_PRIME256V1, 32),
        DdiEccCurve::P384 => (openssl::nid::Nid::SECP384R1, 48),
        DdiEccCurve::P521 => (openssl::nid::Nid::SECP521R1, 66),
        _ => return,
    };

    // Generate ecc public key
    let group = openssl::ec::EcGroup::from_curve_name(curve_name).unwrap();
    let ecc_private = openssl::ec::EcKey::generate(&group).unwrap();
    let ecc_public = openssl::ec::EcKey::from_public_key(&group, ecc_private.public_key()).unwrap();

    // Get affine coordinate data
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    ecc_public
        .public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
        .unwrap();

    // Get key in der format
    let public_key_der = ecc_public.public_key_to_der().unwrap();

    // Call ecc_pub_key_der_to_raw to get affine coordinate data from der
    let key_data = ecc_pub_key_der_to_raw(&public_key_der).unwrap();

    // Verify key_data
    assert_eq!(key_data.curve, curve);
    // key_data might have a leading 0u8 byte, just compare up to OpenSSL data length
    let x_len_diff = der_len - x.to_vec().len();
    let y_len_diff = der_len - y.to_vec().len();
    assert_eq!(key_data.x[x_len_diff..der_len], x.to_vec());
    assert_eq!(key_data.y[y_len_diff..der_len], y.to_vec());
}

#[cfg(feature = "post_decode")]
fn test_ecc_pub_key_raw_to_der(curve: DdiEccCurve) {
    let (curve_name, der_len) = match curve {
        DdiEccCurve::P256 => (openssl::nid::Nid::X9_62_PRIME256V1, 32),
        DdiEccCurve::P384 => (openssl::nid::Nid::SECP384R1, 48),
        DdiEccCurve::P521 => (openssl::nid::Nid::SECP521R1, 66),
        _ => return,
    };

    // Generate ecc public key
    let group = openssl::ec::EcGroup::from_curve_name(curve_name).unwrap();
    let ecc_private = openssl::ec::EcKey::generate(&group).unwrap();
    let ecc_public = openssl::ec::EcKey::from_public_key(&group, ecc_private.public_key()).unwrap();

    // Get affine coordinate data
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    ecc_public
        .public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
        .unwrap();

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
    let rsa_private = openssl::rsa::Rsa::generate(size).unwrap();

    let n = rsa_private.n().to_owned().unwrap();
    let e = rsa_private.e().to_owned().unwrap();

    let key_data = RsaPublicKeyData {
        n: n.to_vec(),
        e: e.to_vec(),
        little_endian: false,
    };
    let der_vec = rsa_pub_key_raw_to_der(key_data).unwrap();

    let rsa_public = openssl::rsa::Rsa::public_key_from_der(&der_vec).unwrap();
    let new_n = rsa_public.n().to_owned().unwrap();
    let new_e = rsa_public.e().to_owned().unwrap();

    let pkey = openssl::pkey::PKey::from_rsa(rsa_public).unwrap();

    let new_size = pkey.bits();
    assert_eq!(size, new_size);
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
