// Copyright (C) Microsoft Corporation. All rights reserved.

// This contains helper functions for pre_encode and post_decode functions

#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
extern crate alloc;
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
use alloc::vec::Vec;

#[cfg(feature = "post_decode")]
use mcr_ddi_mbor::MborDecodeError;
#[cfg(feature = "pre_encode")]
use mcr_ddi_mbor::MborEncodeError;

#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
use crate::DdiEccCurve;
#[cfg(feature = "post_decode")]
use crate::MAX_ECC_DER_COMPONENT_SIZE;

#[cfg(feature = "post_decode")]
const RSA_OID: pkcs1::ObjectIdentifier =
    pkcs1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
#[cfg(feature = "post_decode")]
const EC_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
const P256_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
const P384_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
const P521_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// Reverse copy a slice from src to destination
/// Helper function for implementing pre_encode_fn and post_decode_fn
pub fn reverse_copy(dst: &mut [u8], src: &[u8]) {
    for (item1, item2) in src.iter().rev().zip(dst.iter_mut()) {
        *item2 = *item1;
    }
}

/// Structure to represent Ecc key data (Big endian format)
/// Helper struct for pre_encode_fn and post_decode_fn
#[cfg(any(feature = "pre_encode", feature = "post_decode"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublicKeyData {
    pub x: [u8; MAX_ECC_DER_COMPONENT_SIZE],
    pub y: [u8; MAX_ECC_DER_COMPONENT_SIZE],
    pub curve: DdiEccCurve,
}

/// Structure to represent Ecc key data (Big endian format)
/// Helper struct for pre_encode_fn and post_decode_fn
#[cfg(feature = "post_decode")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKeyData {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
    pub little_endian: bool,
}

/// Parse DER to create Ecc Public key data
/// Helper function for implementing pre_encode_fn
#[cfg(feature = "pre_encode")]
pub fn ecc_pub_key_der_to_raw(buf: &[u8]) -> Result<EccPublicKeyData, MborEncodeError> {
    let public_key_info = {
        use spki::der::Decode;
        spki::SubjectPublicKeyInfoRef::from_der(buf).map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborEncodeError::DerDecodeFailed
        })?
    };

    let (_alg_oid, param_oid) = public_key_info.algorithm.oids().map_err(|error_stack| {
        tracing::error!(?error_stack);
        MborEncodeError::DerDecodeFailed
    })?;

    match param_oid {
        oid if oid == Some(P256_OID) => {
            let point = sec1::point::EncodedPoint::<sec1::consts::U32>::from_bytes(
                public_key_info.subject_public_key.raw_bytes(),
            )
            .map_err(|sec1_error_stack| {
                tracing::error!(?sec1_error_stack);
                MborEncodeError::DerDecodeFailed
            })?;
            match point.coordinates() {
                sec1::point::Coordinates::Uncompressed { x, y } => {
                    let mut x_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    let mut y_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    x_array[32 - x.len()..32].copy_from_slice(x);
                    y_array[32 - y.len()..32].copy_from_slice(y);
                    Ok(EccPublicKeyData {
                        x: x_array,
                        y: y_array,
                        curve: DdiEccCurve::P256,
                    })
                }
                _unexpected_coordinates => {
                    tracing::error!(
                        "Unexpected coordinates. Only uncompressed coordinates are supported."
                    );
                    Err(MborEncodeError::DerDecodeFailed)?
                }
            }
        }
        oid if oid == Some(P384_OID) => {
            let point = sec1::point::EncodedPoint::<sec1::consts::U48>::from_bytes(
                public_key_info.subject_public_key.raw_bytes(),
            )
            .map_err(|sec1_error_stack| {
                tracing::error!(?sec1_error_stack);
                MborEncodeError::DerDecodeFailed
            })?;
            match point.coordinates() {
                sec1::point::Coordinates::Uncompressed { x, y } => {
                    let mut x_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    let mut y_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    x_array[48 - x.len()..48].copy_from_slice(x);
                    y_array[48 - y.len()..48].copy_from_slice(y);
                    Ok(EccPublicKeyData {
                        x: x_array,
                        y: y_array,
                        curve: DdiEccCurve::P384,
                    })
                }
                _unexpected_coordinates => {
                    tracing::error!(
                        "Unexpected coordinates. Only uncompressed coordinates are supported."
                    );
                    Err(MborEncodeError::DerDecodeFailed)?
                }
            }
        }
        oid if oid == Some(P521_OID) => {
            let point = sec1::point::EncodedPoint::<sec1::consts::U66>::from_bytes(
                public_key_info.subject_public_key.raw_bytes(),
            )
            .map_err(|sec1_error_stack| {
                tracing::error!(?sec1_error_stack);
                MborEncodeError::DerDecodeFailed
            })?;
            match point.coordinates() {
                sec1::point::Coordinates::Uncompressed { x, y } => {
                    let mut x_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    let mut y_array = [0u8; MAX_ECC_DER_COMPONENT_SIZE];
                    x_array[66 - x.len()..66].copy_from_slice(x);
                    y_array[66 - y.len()..66].copy_from_slice(y);
                    Ok(EccPublicKeyData {
                        x: x_array,
                        y: y_array,
                        curve: DdiEccCurve::P521,
                    })
                }
                _unexpected_coordinates => {
                    tracing::error!(
                        "Unexpected coordinates. Only uncompressed coordinates are supported."
                    );
                    Err(MborEncodeError::DerDecodeFailed)?
                }
            }
        }
        oid => {
            tracing::error!("Unexpected algorithm oid {:?}", oid);
            Err(MborEncodeError::DerDecodeFailed)?
        }
    }
}

/// Convert Ecc public key data to DER
/// Helper function for implementing post_decode_fn
#[cfg(feature = "post_decode")]
pub fn ecc_pub_key_raw_to_der(key_data: EccPublicKeyData) -> Result<Vec<u8>, MborDecodeError> {
    use spki::der::Encode;

    let public_key_der = match key_data.curve {
        DdiEccCurve::P256 => {
            let mut x_bytes = [0u8; 32];
            x_bytes.copy_from_slice(&key_data.x[..32]);
            let mut y_bytes = [0u8; 32];
            y_bytes.copy_from_slice(&key_data.y[..32]);

            let point = sec1::point::EncodedPoint::<sec1::consts::U32>::from_affine_coordinates(
                &x_bytes.into(),
                &y_bytes.into(),
                false,
            );
            point.as_bytes().to_vec()
        }
        DdiEccCurve::P384 => {
            let mut x_bytes = [0u8; 48];
            x_bytes.copy_from_slice(&key_data.x[..48]);
            let mut y_bytes = [0u8; 48];
            y_bytes.copy_from_slice(&key_data.y[..48]);

            let point = sec1::point::EncodedPoint::<sec1::consts::U48>::from_affine_coordinates(
                &x_bytes.into(),
                &y_bytes.into(),
                false,
            );
            point.as_bytes().to_vec()
        }
        DdiEccCurve::P521 => {
            let mut x_bytes = [0u8; 66];
            x_bytes.copy_from_slice(&key_data.x[..66]);
            let mut y_bytes = [0u8; 66];
            y_bytes.copy_from_slice(&key_data.y[..66]);

            let point = sec1::point::EncodedPoint::<sec1::consts::U66>::from_affine_coordinates(
                &x_bytes.into(),
                &y_bytes.into(),
                false,
            );
            point.as_bytes().to_vec()
        }
        _ => {
            tracing::error!("Unexpected curve: {:?}", key_data.curve);
            Err(MborDecodeError::InvalidParameter)?
        }
    };

    let public_key_der_bitstring = pkcs1::der::asn1::BitStringRef::from_bytes(&public_key_der)
        .map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;

    let param_oid: spki::der::Any = match key_data.curve {
        DdiEccCurve::P256 => P256_OID.into(),
        DdiEccCurve::P384 => P384_OID.into(),
        DdiEccCurve::P521 => P521_OID.into(),
        _ => Err(MborDecodeError::InvalidParameter)?,
    };

    let alg_id = spki::AlgorithmIdentifier {
        oid: EC_OID,
        parameters: Some(param_oid),
    };

    let subject_public_key_info = spki::SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: public_key_der_bitstring,
    };

    let der = subject_public_key_info.to_der().map_err(|error_stack| {
        tracing::error!(?error_stack);
        MborDecodeError::InvalidParameter
    })?;

    Ok(der)
}

/// Convert RSA public key data to DER
/// Helper function for implementing post_decode_fn
#[cfg(feature = "post_decode")]
pub fn rsa_pub_key_raw_to_der(key_data: RsaPublicKeyData) -> Result<Vec<u8>, MborDecodeError> {
    let mut n_mut_copy = key_data.n.clone();
    let mut e_mut_copy = key_data.e.clone();

    let (modulus, public_exponent) = if key_data.little_endian {
        n_mut_copy.reverse();
        e_mut_copy.reverse();

        let n_uint = pkcs1::UintRef::new(&n_mut_copy).map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;
        let e_uint = pkcs1::UintRef::new(&e_mut_copy).map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;

        (n_uint, e_uint)
    } else {
        let n_uint = pkcs1::UintRef::new(&n_mut_copy).map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;
        let e_uint = pkcs1::UintRef::new(&e_mut_copy).map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;

        (n_uint, e_uint)
    };
    use pkcs1::der::Encode;

    let public_key = pkcs1::RsaPublicKey {
        modulus,
        public_exponent,
    };
    let public_key_der = public_key.to_der().map_err(|error_stack| {
        tracing::error!(?error_stack);
        MborDecodeError::InvalidParameter
    })?;

    let null_param: spki::der::AnyRef<'_> = spki::der::asn1::Null.into(); // This creates a DER-encoded NULL
    let alg_id: spki::AlgorithmIdentifier<pkcs1::der::Any> = spki::AlgorithmIdentifier {
        oid: RSA_OID,
        parameters: Some(null_param.into()),
    };

    let public_key_der_bitstring = pkcs1::der::asn1::BitStringRef::from_bytes(&public_key_der)
        .map_err(|error_stack| {
            tracing::error!(?error_stack);
            MborDecodeError::InvalidParameter
        })?;
    let subject_public_key_info = spki::SubjectPublicKeyInfo {
        algorithm: alg_id,
        subject_public_key: public_key_der_bitstring,
    };

    let der = subject_public_key_info.to_der().map_err(|error_stack| {
        tracing::error!(?error_stack);
        MborDecodeError::InvalidParameter
    })?;

    Ok(der)
}
