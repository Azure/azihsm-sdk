// Copyright (C) Microsoft Corporation. All rights reserved.

//! Tests for DER encoding and decoding of RSA keys.
//!
//! These tests validate bidirectional DER conversion for:
//! - RSA public keys in X.509 SubjectPublicKeyInfo (SPKI) form
//! - RSA private keys in PKCS#8 PrivateKeyInfo form

use super::rsa_vectors;
use super::*;

fn assert_rsa_spki_vector(vector: &rsa_vectors::SpkiDerVector) {
    let der = DerRsaPublicKey::from_der(vector.key_der).unwrap();
    assert_eq!(der.n(), vector.modulus);
    assert_eq!(der.e(), vector.exponent);

    let len = der.to_der(None).unwrap();
    let mut buf = vec![0u8; len];
    let len2 = der.to_der(Some(&mut buf)).unwrap();
    assert_eq!(len, len2);
    assert_eq!(buf.as_slice(), vector.key_der);

    let der2 = DerRsaPublicKey::from_der(&buf).unwrap();
    assert_eq!(der2.n(), vector.modulus);
    assert_eq!(der2.e(), vector.exponent);
}

fn assert_rsa_pkcs8_vector(vector: &rsa_vectors::Pkcs8DerVector) {
    let der = DerRsaPrivateKey::from_der(vector.key_der).unwrap();

    assert_eq!(der.n(), vector.modulus);
    assert_eq!(der.e(), vector.public_exponent);
    assert_eq!(der.d(), vector.private_exponent);
    assert_eq!(der.p(), vector.prime1);
    assert_eq!(der.q(), vector.prime2);
    assert_eq!(der.dp(), vector.exponent1);
    assert_eq!(der.dq(), vector.exponent2);
    assert_eq!(der.qi(), vector.coefficient);

    let len = der.to_der(None).unwrap();
    let mut buf = vec![0u8; len];
    let len2 = der.to_der(Some(&mut buf)).unwrap();
    assert_eq!(len, len2);
    assert_eq!(buf.as_slice(), vector.key_der);

    let der2 = DerRsaPrivateKey::from_der(&buf).unwrap();
    assert_eq!(der2.n(), vector.modulus);
    assert_eq!(der2.e(), vector.public_exponent);
    assert_eq!(der2.d(), vector.private_exponent);
    assert_eq!(der2.p(), vector.prime1);
    assert_eq!(der2.q(), vector.prime2);
    assert_eq!(der2.dp(), vector.exponent1);
    assert_eq!(der2.dq(), vector.exponent2);
    assert_eq!(der2.qi(), vector.coefficient);
}

#[test]
fn test_rsa_2048_spki_der_encoding_decoding() {
    assert_rsa_spki_vector(&rsa_vectors::SPKI_DER_VECTOR_2048);
}

#[test]
fn test_rsa_3072_spki_der_encoding_decoding() {
    assert_rsa_spki_vector(&rsa_vectors::SPKI_DER_VECTOR_3072);
}

#[test]
fn test_rsa_4096_spki_der_encoding_decoding() {
    assert_rsa_spki_vector(&rsa_vectors::SPKI_DER_VECTOR_4096);
}

#[test]
fn test_rsa_2048_pkcs8_der_encoding_decoding() {
    assert_rsa_pkcs8_vector(&rsa_vectors::PKCS8_DER_VECTOR_2048);
}

#[test]
fn test_rsa_3072_pkcs8_der_encoding_decoding() {
    assert_rsa_pkcs8_vector(&rsa_vectors::PKCS8_DER_VECTOR_3072);
}

#[test]
fn test_rsa_4096_pkcs8_der_encoding_decoding() {
    assert_rsa_pkcs8_vector(&rsa_vectors::PKCS8_DER_VECTOR_4096);
}
