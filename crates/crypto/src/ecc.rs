// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for elliptic curve cryptography (ECC).

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl::bn::BigNum;
#[cfg(feature = "use-openssl")]
use openssl::bn::BigNumContext;
#[cfg(feature = "use-openssl")]
use openssl::derive::Deriver;
#[cfg(feature = "use-openssl")]
use openssl::ec::EcGroup;
#[cfg(feature = "use-openssl")]
use openssl::ec::EcKey;
#[cfg(feature = "use-openssl")]
use openssl::ec::EcPoint;
#[cfg(feature = "use-openssl")]
use openssl::ecdsa::EcdsaSig;
#[cfg(feature = "use-openssl")]
use openssl::nid::Nid;
#[cfg(feature = "use-openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "use-openssl")]
use openssl::pkey::Private;
#[cfg(feature = "use-openssl")]
use openssl::pkey::Public;
#[cfg(feature = "use-openssl")]
use openssl::pkey_ctx::PkeyCtx;
#[cfg(feature = "use-symcrypt")]
use symcrypt::ecc;

#[cfg(feature = "use-symcrypt")]
const EC_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
#[cfg(feature = "use-symcrypt")]
const P256_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
#[cfg(feature = "use-symcrypt")]
const P384_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");
#[cfg(feature = "use-symcrypt")]
const P521_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.35");

use crate::CryptoError;
use crate::CryptoKeyKind;

/// ECC Curve enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoEccCurve {
    /// ECC 256
    P256,

    /// ECC 384
    P384,

    /// ECC 521
    P521,
}

/// Trait for ECC common operations.
pub trait EccOp<T> {
    fn generate(curve: CryptoEccCurve) -> Result<T, CryptoError>;
    fn from_der(der: &[u8], expected_type: Option<CryptoKeyKind>) -> Result<T, CryptoError>;
    fn from_raw(raw_key_data: &[u8], key_kind: CryptoKeyKind) -> Result<T, CryptoError>;
    fn to_der(&self) -> Result<Vec<u8>, CryptoError>;
    fn curve(&self) -> Result<CryptoEccCurve, CryptoError>;
    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
}

/// Trait for ECC public key operations.
pub trait EccPublicOp {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// ECC Public Key.
#[derive(Debug)]
pub struct EccPublicKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Public>,

    #[cfg(feature = "use-symcrypt")]
    handle: ecc::EcKey,
}

#[cfg(feature = "use-openssl")]
impl EccOp<EccPublicKey> for EccPublicKey {
    /// Generate an ECC public key.
    fn generate(curve: CryptoEccCurve) -> Result<EccPublicKey, CryptoError> {
        let curve_name = match curve {
            CryptoEccCurve::P256 => Nid::X9_62_PRIME256V1,
            CryptoEccCurve::P384 => Nid::SECP384R1,
            CryptoEccCurve::P521 => Nid::SECP521R1,
        };
        let group =
            openssl::ec::EcGroup::from_curve_name(curve_name).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGenerateError
            })?;
        let ecc_private = openssl::ec::EcKey::generate(&group).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGenerateError
        })?;

        // Derive the public key from the private key
        let ecc_public = openssl::ec::EcKey::from_public_key(&group, ecc_private.public_key())
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGenerateError
            })?;

        // Pack the public key into a `PKey` object
        let pkey_public =
            openssl::pkey::PKey::from_ec_key(ecc_public).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGenerateError
            })?;

        Ok(EccPublicKey {
            handle: pkey_public,
        })
    }

    /// Deserialize an ECC public key from a DER-encoded SubjectPublicKeyInfo format.
    fn from_der(der: &[u8], expected_type: Option<CryptoKeyKind>) -> Result<Self, CryptoError> {
        let ecc = openssl::ec::EcKey::public_key_from_der(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromDerError
        })?;
        let pkey = openssl::pkey::PKey::from_ec_key(ecc).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromDerError
        })?;

        match expected_type {
            Some(CryptoKeyKind::Ecc256Public) => {
                if pkey.bits() != 256 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Ecc384Public) => {
                if pkey.bits() != 384 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Ecc521Public) => {
                if pkey.bits() != 521 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self { handle: pkey })
    }

    /// Serialize the ECC public key to a DER-encoded SubjectPublicKeyInfo format.
    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .handle
            .as_ref()
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccToDerError
            })?;

        Ok(der)
    }

    fn curve(&self) -> Result<CryptoEccCurve, CryptoError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCurveError
        })?;
        let curve_name = ec_key
            .group()
            .curve_name()
            .ok_or(CryptoError::EccGetCurveError)?;

        let curve = match curve_name {
            Nid::X9_62_PRIME256V1 => CryptoEccCurve::P256,
            Nid::SECP384R1 => CryptoEccCurve::P384,
            Nid::SECP521R1 => CryptoEccCurve::P521,
            _ => Err(CryptoError::EccGetCurveError)?,
        };

        Ok(curve)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let group = ec_key.group();
        let mut x = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let mut y = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let mut ctx = BigNumContext::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;

        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGetCoordinatesError
            })?;

        Ok((x.to_vec(), y.to_vec()))
    }

    fn from_raw(_raw_key_data: &[u8], _key_kind: CryptoKeyKind) -> Result<Self, CryptoError> {
        Err(CryptoError::EccFromRawError)
    }
}

#[cfg(feature = "use-openssl")]
impl EccPublicOp for EccPublicKey {
    /// ECDSA signature verification.
    ///
    /// # Arguments
    /// * `digest` - The digest used to generate the signature.
    /// * `signature` - The signature (in raw format) to be verified.
    ///
    /// # Returns
    /// * `()` - If verification succeeds.
    ///
    /// # Errors
    /// * `CryptoError::InvalidParameter` - If the signature is not even.
    /// * `CryptoError::EccVerifyFailed` - If the verification fails.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature_len = signature.len();
        if !signature_len.is_multiple_of(2) {
            Err(CryptoError::InvalidParameter)?
        }

        // Convert the raw signature to DER, which is expected by OpenSSL verify API.
        let (r, s) = signature.split_at(signature_len / 2);
        let r = BigNum::from_slice(r).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;
        let s = BigNum::from_slice(s).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;
        let signature = EcdsaSig::from_private_components(r, s).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;
        let signature = signature.to_der().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;

        ctx.verify_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccVerifyFailed
        })?;

        let result = ctx
            .verify(digest, &signature)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccVerifyFailed
            })?;

        // Return error on verification failure.
        if !result {
            Err(CryptoError::EccVerifyFailed)?
        }

        Ok(())
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccOp<EccPublicKey> for EccPublicKey {
    /// Generate an ECC public key.
    fn generate(curve: CryptoEccCurve) -> Result<EccPublicKey, CryptoError> {
        let curve_type = match curve {
            CryptoEccCurve::P256 => ecc::CurveType::NistP256,
            CryptoEccCurve::P384 => ecc::CurveType::NistP384,
            CryptoEccCurve::P521 => ecc::CurveType::NistP521,
        };
        let key_pair = ecc::EcKey::generate_key_pair(curve_type, ecc::EcKeyUsage::EcDhAndEcDsa)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccGenerateError
            })?;

        // Export the public key information, and re-import it into a new
        // SymCrypt `EcKey` object. (This new key is oblivious to the private
        // key information.)
        let raw_public_key = key_pair
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccGenerateError
            })?;
        let public_key = ecc::EcKey::set_public_key(
            key_pair.get_curve_type(),
            &raw_public_key,
            key_pair.get_ec_curve_usage(),
        )
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            CryptoError::EccGenerateError
        })?;

        Ok(EccPublicKey { handle: public_key })
    }

    fn from_der(der: &[u8], expected_type: Option<CryptoKeyKind>) -> Result<Self, CryptoError> {
        let public_key_info = {
            use spki::der::Decode;
            spki::SubjectPublicKeyInfoRef::from_der(der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccFromDerError
            })?
        };

        let public_key_der = public_key_info.subject_public_key;
        let (_alg_oid, param_oid) = public_key_info.algorithm.oids().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::EccFromDerError
        })?;

        match param_oid {
            oid if oid == Some(P256_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc256Public) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_public_key(
                    ecc::CurveType::NistP256,
                    &public_key_der.raw_bytes()[1..], // Remove the leading SEC1 tag byte
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            oid if oid == Some(P384_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc384Public) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_public_key(
                    ecc::CurveType::NistP384,
                    &public_key_der.raw_bytes()[1..], // Remove the leading SEC1 tag byte
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            oid if oid == Some(P521_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc521Public) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_public_key(
                    ecc::CurveType::NistP521,
                    &public_key_der.raw_bytes()[1..], // Remove the leading SEC1 tag byte
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        use spki::der::Encode;

        let public_key_point = self.handle.export_public_key().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::EccToDerError
        })?;

        let public_key_der = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => {
                let mut untagged_bytes = [0u8; 32 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP384 => {
                let mut untagged_bytes = [0u8; 48 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U48>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP521 => {
                let mut untagged_bytes = [0u8; 66 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U66>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            _ => Err(CryptoError::EccToDerError)?,
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccToDerError
            })?;

        let param_oid: spki::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(CryptoError::EccToDerError)?,
        };

        let alg_id = spki::AlgorithmIdentifier {
            oid: EC_OID,
            parameters: Some(param_oid),
        };

        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = subject_public_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::EccToDerError
        })?;

        Ok(der)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let raw_public_key = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccGetCoordinatesError
            })?;
        let point_size = raw_public_key.len() / 2;
        let x = raw_public_key[..point_size].to_vec();
        let y = raw_public_key[point_size..].to_vec();
        Ok((x, y))
    }

    fn curve(&self) -> Result<CryptoEccCurve, CryptoError> {
        match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => Ok(CryptoEccCurve::P256),
            ecc::CurveType::NistP384 => Ok(CryptoEccCurve::P384),
            ecc::CurveType::NistP521 => Ok(CryptoEccCurve::P521),
            _ => Err(CryptoError::EccGetCurveError)?,
        }
    }

    fn from_raw(raw_key_data: &[u8], key_kind: CryptoKeyKind) -> Result<Self, CryptoError> {
        let curve_type = match key_kind {
            CryptoKeyKind::Ecc256Public => ecc::CurveType::NistP256,
            CryptoKeyKind::Ecc384Public => ecc::CurveType::NistP384,
            CryptoKeyKind::Ecc521Public => ecc::CurveType::NistP521,
            _ => Err(CryptoError::EccFromRawError)?,
        };

        let symcrypt_key =
            ecc::EcKey::set_public_key(curve_type, raw_key_data, ecc::EcKeyUsage::EcDhAndEcDsa)
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromRawError
                })?;
        Ok(Self {
            handle: symcrypt_key,
        })
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccPublicOp for EccPublicKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature_len = signature.len();
        if !signature_len.is_multiple_of(2) {
            Err(CryptoError::InvalidParameter)?
        }
        let result = self
            .handle
            .ecdsa_verify(signature, digest)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccVerifyFailed
            });
        if result.is_err() {
            Err(CryptoError::EccVerifyFailed)?
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct EccPrivateKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Private>,

    #[cfg(feature = "use-symcrypt")]
    handle: ecc::EcKey,
}

/// Trait for ECC private key operations.
pub trait EccPrivateOp {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, CryptoError>;
    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(feature = "use-openssl")]
impl EccOp<EccPrivateKey> for EccPrivateKey {
    /// Generate an ECC private key.
    fn generate(curve: CryptoEccCurve) -> Result<EccPrivateKey, CryptoError> {
        let curve_name = match curve {
            CryptoEccCurve::P256 => Nid::X9_62_PRIME256V1,
            CryptoEccCurve::P384 => Nid::SECP384R1,
            CryptoEccCurve::P521 => Nid::SECP521R1,
        };
        let group =
            openssl::ec::EcGroup::from_curve_name(curve_name).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGenerateError
            })?;
        let ecc_private = openssl::ec::EcKey::generate(&group).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGenerateError
        })?;

        // Pack the private key into a `PKey` object
        let pkey_private =
            openssl::pkey::PKey::from_ec_key(ecc_private).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGenerateError
            })?;

        Ok(EccPrivateKey {
            handle: pkey_private,
        })
    }

    /// Deserialize an ECC private key from a DER-encoded PKCS#8 format.
    fn from_der(der: &[u8], expected_type: Option<CryptoKeyKind>) -> Result<Self, CryptoError> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromDerError
        })?;

        match expected_type {
            Some(CryptoKeyKind::Ecc256Private) => {
                if pkey.bits() != 256 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Ecc384Private) => {
                if pkey.bits() != 384 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Ecc521Private) => {
                if pkey.bits() != 521 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self { handle: pkey })
    }

    /// Convert a raw private key to an ECC private key.
    fn from_raw(raw_key_data: &[u8], expected_type: CryptoKeyKind) -> Result<Self, CryptoError> {
        let curve = match expected_type {
            CryptoKeyKind::Ecc256Private => Nid::X9_62_PRIME256V1,
            CryptoKeyKind::Ecc384Private => Nid::SECP384R1,
            CryptoKeyKind::Ecc521Private => Nid::SECP521R1,
            _ => return Err(CryptoError::EccFromRawError),
        };

        // Create the EC group
        let group = EcGroup::from_curve_name(curve).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromRawError
        })?;
        // Convert the private scalar into a BigNum
        let private_bn = BigNum::from_slice(raw_key_data).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromRawError
        })?;

        // Generate the public key from the private scalar
        let ctx = BigNumContext::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromRawError
        })?;
        let mut pub_key = EcPoint::new(&group).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromRawError
        })?;
        pub_key
            .mul_generator(&group, &private_bn, &ctx)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccFromRawError
            })?;

        // Create the EC key using private and public components
        let ec_key = EcKey::from_private_components(&group, &private_bn, &pub_key).map_err(
            |openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccFromRawError
            },
        )?;

        let pkey = PKey::from_ec_key(ec_key).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccFromRawError
        })?;

        Ok(Self { handle: pkey })
    }

    /// Serialize the ECC private key to a DER-encoded PKCS#8 format.
    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .handle
            .as_ref()
            .private_key_to_pkcs8()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccToDerError
            })?;

        Ok(der)
    }

    fn curve(&self) -> Result<CryptoEccCurve, CryptoError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCurveError
        })?;
        let curve_name = ec_key
            .group()
            .curve_name()
            .ok_or(CryptoError::EccGetCurveError)?;

        let curve = match curve_name {
            Nid::X9_62_PRIME256V1 => CryptoEccCurve::P256,
            Nid::SECP384R1 => CryptoEccCurve::P384,
            Nid::SECP521R1 => CryptoEccCurve::P521,
            _ => Err(CryptoError::EccGetCurveError)?,
        };

        Ok(curve)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let group = ec_key.group();
        let mut x = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let mut y = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;
        let mut ctx = BigNumContext::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccGetCoordinatesError
        })?;

        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccGetCoordinatesError
            })?;

        Ok((x.to_vec(), y.to_vec()))
    }
}

#[cfg(feature = "use-openssl")]
impl EccPrivateOp for EccPrivateKey {
    /// ECDSA signing.
    ///
    /// # Arguments
    /// * `digest` - The digest to be signed
    ///
    /// # Returns
    /// * `Vec<u8>` - ECDSA signature (in raw format).
    ///
    /// # Errors
    /// * `CryptoError::EccSignFailed` - If the signing operation fails.
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccSignFailed
        })?;

        ctx.sign_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccSignFailed
        })?;

        let buffer_len = ctx.sign(digest, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccSignFailed
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let signature_len = ctx
            .sign(digest, Some(&mut buffer))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccSignFailed
            })?;

        let buffer = &buffer[..signature_len];

        // Convert the DER-encoded signature to fixed-size raw signature.
        let signature = EcdsaSig::from_der(buffer).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccSignFailed
        })?;
        let r_raw = signature.r().to_vec();
        let s_raw = signature.s().to_vec();
        // Handle the case where r or s is smaller than key size.
        // Round up division, in case key_size is not divisible (e.g. 521)
        let key_size = (self.handle.bits() as f32 / 8.0).ceil() as usize;
        let mut r = vec![0u8; key_size];
        let mut s = vec![0u8; key_size];

        if r_raw.len() > key_size || s_raw.len() > key_size {
            tracing::error!(
                r_raw_len = r_raw.len(),
                s_raw_len = s_raw.len(),
                key_size,
                "Unexpected parameters for ecc sign"
            );
            return Err(CryptoError::EccSignFailed);
        }

        r[key_size - r_raw.len()..].copy_from_slice(&r_raw);
        s[key_size - s_raw.len()..].copy_from_slice(&s_raw);

        Ok([r, s].concat().to_vec())
    }

    /// ECDH Key exchange.
    ///
    /// # Arguments
    /// * `peer` - The peer ECC public key.
    ///
    /// # Returns
    /// * `Vec<u8>` - The derived secret.
    ///
    /// # Errors
    /// * `CryptoError::EccDeriveError` - If the operation fails.
    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, CryptoError> {
        let mut deriver = Deriver::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccDeriveError
        })?;

        deriver
            .set_peer(&peer.handle)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccDeriveError
            })?;

        let secret = deriver.derive_to_vec().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::EccDeriveError
        })?;

        Ok(secret)
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        self.handle
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::EccToDerError
            })
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccOp<EccPrivateKey> for EccPrivateKey {
    /// Generate an ECC private key.
    fn generate(curve: CryptoEccCurve) -> Result<EccPrivateKey, CryptoError> {
        let curve_type = match curve {
            CryptoEccCurve::P256 => ecc::CurveType::NistP256,
            CryptoEccCurve::P384 => ecc::CurveType::NistP384,
            CryptoEccCurve::P521 => ecc::CurveType::NistP521,
        };
        let key_pair = ecc::EcKey::generate_key_pair(curve_type, ecc::EcKeyUsage::EcDhAndEcDsa)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccGenerateError
            })?;

        Ok(EccPrivateKey { handle: key_pair })
    }

    fn from_der(
        der: &[u8],
        expected_type: Option<CryptoKeyKind>,
    ) -> Result<EccPrivateKey, CryptoError> {
        let private_key_info = {
            use pkcs8::der::Decode;
            pkcs8::PrivateKeyInfo::from_der(der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccFromDerError
            })?
        };
        let (_alg_oid, param_oid) = private_key_info.algorithm.oids().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::EccFromDerError
        })?;

        let private_key = {
            use sec1::der::Decode;
            sec1::EcPrivateKey::from_der(private_key_info.private_key).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccFromDerError
            })?
        };

        match param_oid {
            oid if oid == Some(P256_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc256Private) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    ecc::CurveType::NistP256,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            oid if oid == Some(P384_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc384Private) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    ecc::CurveType::NistP384,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            oid if oid == Some(P521_OID) => {
                if expected_type.is_some() && expected_type != Some(CryptoKeyKind::Ecc521Private) {
                    Err(CryptoError::DerAndKeyTypeMismatch)?;
                }

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    ecc::CurveType::NistP521,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromDerError
                })?;

                Ok(Self {
                    handle: symcrypt_key,
                })
            }
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        let private_key_data =
            self.handle
                .export_private_key()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccToDerError
                })?;

        let public_key_data = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccToDerError
            })?;

        // Validate length is even (X and Y should be equal length)
        if public_key_data.len() % 2 != 0 {
            return Err(CryptoError::EccToDerError);
        }

        // Prepend 0x04 to indicate uncompressed format
        let mut uncompressed = Vec::with_capacity(public_key_data.len() + 1);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&public_key_data);

        let private_key = sec1::EcPrivateKey {
            private_key: &private_key_data,
            parameters: None,
            public_key: Some(&uncompressed),
        };

        let param_oid: pkcs8::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(CryptoError::EccToDerError)?,
        };

        use spki::der::referenced::OwnedToRef;
        let alg_id = spki::AlgorithmIdentifier {
            oid: EC_OID,
            parameters: Some(param_oid.owned_to_ref()),
        };

        let private_key_der = {
            use sec1::der::Encode;
            private_key.to_der().map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccToDerError
            })?
        };
        let private_key_info = pkcs8::PrivateKeyInfo::new(alg_id, &private_key_der);

        let der = {
            use spki::der::Encode;
            private_key_info.to_der().map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccToDerError
            })?
        };
        Ok(der)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let raw_public_key = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccGetCoordinatesError
            })?;
        let point_size = raw_public_key.len() / 2;
        let x = raw_public_key[..point_size].to_vec();
        let y = raw_public_key[point_size..].to_vec();
        Ok((x, y))
    }

    fn curve(&self) -> Result<CryptoEccCurve, CryptoError> {
        match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => Ok(CryptoEccCurve::P256),
            ecc::CurveType::NistP384 => Ok(CryptoEccCurve::P384),
            ecc::CurveType::NistP521 => Ok(CryptoEccCurve::P521),
            _ => Err(CryptoError::EccGetCurveError)?,
        }
    }

    fn from_raw(raw_key_data: &[u8], key_kind: CryptoKeyKind) -> Result<Self, CryptoError> {
        let curve = match key_kind {
            CryptoKeyKind::Ecc256Private => ecc::CurveType::NistP256,
            CryptoKeyKind::Ecc384Private => ecc::CurveType::NistP384,
            CryptoKeyKind::Ecc521Private => ecc::CurveType::NistP521,
            _ => return Err(CryptoError::EccFromRawError),
        };
        let symcrypt_key =
            ecc::EcKey::set_key_pair(curve, raw_key_data, None, ecc::EcKeyUsage::EcDhAndEcDsa)
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::EccFromRawError
                })?;
        Ok(Self {
            handle: symcrypt_key,
        })
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccPrivateOp for EccPrivateKey {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self
            .handle
            .ecdsa_sign(digest)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccSignFailed
            })?;
        Ok(signature)
    }

    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, CryptoError> {
        let raw_public_key = peer
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccDeriveError
            })?;
        let handle = ecc::EcKey::set_public_key(
            peer.handle.get_curve_type(),
            &raw_public_key,
            peer.handle.get_ec_curve_usage(),
        )
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            CryptoError::EccDeriveError
        })?;
        let secret = self
            .handle
            .ecdh_secret_agreement(handle)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::EccDeriveError
            })?;
        Ok(secret)
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        let public_key_point = self.handle.export_public_key().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::EccToDerError
        })?;

        let public_key_der = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => {
                let mut untagged_bytes = [0u8; 32 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP384 => {
                let mut untagged_bytes = [0u8; 48 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U48>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP521 => {
                let mut untagged_bytes = [0u8; 66 * 2];
                untagged_bytes.copy_from_slice(&public_key_point);
                let point = sec1::EncodedPoint::<sec1::consts::U66>::from_untagged_bytes(
                    &untagged_bytes.into(),
                );
                point.as_bytes().to_vec()
            }
            _ => Err(CryptoError::EccToDerError)?,
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccToDerError
            })?;

        let param_oid: spki::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(CryptoError::EccToDerError)?,
        };

        let alg_id = spki::AlgorithmIdentifier {
            oid: EC_OID,
            parameters: Some(param_oid),
        };

        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = {
            use spki::der::Encode;
            subject_public_key_info.to_der().map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::EccToDerError
            })?
        };

        Ok(der)
    }
}

/// Generate an ECC key pair (using OpenSSL on Linux, and SymCrypt on Windows).
///
/// # Arguments
/// * `curve` - The ECC curve of the key pair to generate (p256/ p384/ p521).
///
/// # Returns
/// * `(EccPrivateKey, EccPublicKey)` - Generated ECC key pair.
///
/// # Errors
/// * `CryptoError::EccGenerateError` - If the ECC key pair generation fails.
pub fn generate_ecc(curve: CryptoEccCurve) -> Result<(EccPrivateKey, EccPublicKey), CryptoError> {
    EccPrivateKey::generate(curve).and_then(|private_key| {
        let public_key_der = private_key.extract_pub_key_der()?;
        EccPublicKey::from_der(&public_key_der, None).map(|public_key| (private_key, public_key))
    })
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::*;

    #[test]
    fn test_ecc_private() {
        let data = [1u8; 1024];

        // Generate the key pair
        let keypair = generate_ecc(CryptoEccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();
        // Convert the key to der
        let result = ecc_private.to_der();
        assert!(result.is_ok());

        // Convert der back to the key
        let result = EccPrivateKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Ecc384Private));
        assert!(result.is_ok());
        let ecc_private = result.unwrap();

        // Sign the data with the key
        let result = ecc_private.sign(&data);
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Verify the signature with the key
        let result = ecc_public.verify(&data, &signature);
        assert!(result.is_ok());

        // Extract public key in der
        let result = ecc_private.extract_pub_key_der();
        assert!(result.is_ok());

        // Convert the der back to the key
        let result = EccPublicKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Ecc384Public));
        assert!(result.is_ok());
        let ecc_public = result.unwrap();

        // Verify the signature with the key
        let result = ecc_public.verify(&data, &signature);
        assert!(result.is_ok());

        // Test from_der with SEC1 format
        const DER_SEC1: [u8; 121] = [
            0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x02, 0x0c, 0xb7, 0x68, 0xa5, 0x0d, 0x4e,
            0xa9, 0x6b, 0x77, 0xdd, 0xfe, 0x8f, 0x4d, 0x8e, 0x25, 0xb6, 0x74, 0x5d, 0xd2, 0xc9,
            0x11, 0x58, 0xbd, 0x98, 0x28, 0x41, 0x81, 0x47, 0x90, 0x05, 0x32, 0xa0, 0x0a, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00,
            0x04, 0xc9, 0x1e, 0xfc, 0xc8, 0x2f, 0x8d, 0x56, 0xbf, 0x1f, 0x9f, 0x87, 0x40, 0x34,
            0x6d, 0x40, 0x00, 0x9f, 0xd3, 0xec, 0x8d, 0xa2, 0x44, 0x48, 0x51, 0xc2, 0x57, 0xc9,
            0xfc, 0xa1, 0x07, 0x45, 0x9b, 0x36, 0x17, 0x17, 0x3e, 0x7a, 0x49, 0xdf, 0xfc, 0x6a,
            0xe8, 0x3b, 0x49, 0xae, 0xc2, 0xbb, 0x3c, 0x58, 0x3e, 0xd6, 0xd1, 0x0d, 0xa8, 0x17,
            0xcb, 0x47, 0x2b, 0x04, 0xa8, 0x40, 0xa5, 0x8c, 0x05,
        ];

        let result = EccPrivateKey::from_der(&DER_SEC1, Some(CryptoKeyKind::Ecc256Private));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::EccFromDerError);
        }

        // Test from_der with PKCS8 format
        const DER_PKCS8: [u8; 138] = [
            0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
            0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x02, 0x0c, 0xb7, 0x68, 0xa5, 0x0d,
            0x4e, 0xa9, 0x6b, 0x77, 0xdd, 0xfe, 0x8f, 0x4d, 0x8e, 0x25, 0xb6, 0x74, 0x5d, 0xd2,
            0xc9, 0x11, 0x58, 0xbd, 0x98, 0x28, 0x41, 0x81, 0x47, 0x90, 0x05, 0x32, 0xa1, 0x44,
            0x03, 0x42, 0x00, 0x04, 0xc9, 0x1e, 0xfc, 0xc8, 0x2f, 0x8d, 0x56, 0xbf, 0x1f, 0x9f,
            0x87, 0x40, 0x34, 0x6d, 0x40, 0x00, 0x9f, 0xd3, 0xec, 0x8d, 0xa2, 0x44, 0x48, 0x51,
            0xc2, 0x57, 0xc9, 0xfc, 0xa1, 0x07, 0x45, 0x9b, 0x36, 0x17, 0x17, 0x3e, 0x7a, 0x49,
            0xdf, 0xfc, 0x6a, 0xe8, 0x3b, 0x49, 0xae, 0xc2, 0xbb, 0x3c, 0x58, 0x3e, 0xd6, 0xd1,
            0x0d, 0xa8, 0x17, 0xcb, 0x47, 0x2b, 0x04, 0xa8, 0x40, 0xa5, 0x8c, 0x05,
        ];

        let result = EccPrivateKey::from_der(&DER_PKCS8, Some(CryptoKeyKind::Ecc256Private));
        assert!(result.is_ok());

        let result = EccPublicKey::from_der(&DER_PKCS8, Some(CryptoKeyKind::Ecc256Public));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::EccFromDerError);
        }
    }

    #[test]
    fn test_ecc_public() {
        let data = [1u8; 1024];

        // Generate the key pair
        let keypair = generate_ecc(CryptoEccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        // Sign the data with the key
        let result = ecc_private.sign(&data);
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Convert the key to der
        let result = ecc_public.to_der();
        assert!(result.is_ok());

        // Convert the der back to key
        let result = EccPublicKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Ecc384Public));
        assert!(result.is_ok());
        let ecc_public = result.unwrap();

        // Verify the signature with the key
        let result = ecc_public.verify(&data, &signature);
        assert!(result.is_ok());

        // Test from_der with SubjectPublicKeyInfo format
        const DER_SUBJECT_PUBLIC_KEY_INFO: [u8; 91] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc9,
            0x1e, 0xfc, 0xc8, 0x2f, 0x8d, 0x56, 0xbf, 0x1f, 0x9f, 0x87, 0x40, 0x34, 0x6d, 0x40,
            0x00, 0x9f, 0xd3, 0xec, 0x8d, 0xa2, 0x44, 0x48, 0x51, 0xc2, 0x57, 0xc9, 0xfc, 0xa1,
            0x07, 0x45, 0x9b, 0x36, 0x17, 0x17, 0x3e, 0x7a, 0x49, 0xdf, 0xfc, 0x6a, 0xe8, 0x3b,
            0x49, 0xae, 0xc2, 0xbb, 0x3c, 0x58, 0x3e, 0xd6, 0xd1, 0x0d, 0xa8, 0x17, 0xcb, 0x47,
            0x2b, 0x04, 0xa8, 0x40, 0xa5, 0x8c, 0x05,
        ];

        let result = EccPublicKey::from_der(
            &DER_SUBJECT_PUBLIC_KEY_INFO,
            Some(CryptoKeyKind::Ecc256Public),
        );
        assert!(result.is_ok());

        let result = EccPrivateKey::from_der(
            &DER_SUBJECT_PUBLIC_KEY_INFO,
            Some(CryptoKeyKind::Ecc256Private),
        );
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::EccFromDerError);
        }
    }

    #[test]
    fn test_ecc_derive() {
        // Generate the key pair a
        let keypair = generate_ecc(CryptoEccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private_a, ecc_public_a) = keypair.unwrap();

        // Generate the key pair b
        let keypair = generate_ecc(CryptoEccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private_b, ecc_public_b) = keypair.unwrap();

        let result = ecc_private_a.derive(&ecc_public_b);
        assert!(result.is_ok());
        let shared_a = result.unwrap();

        let result = ecc_private_b.derive(&ecc_public_a);
        assert!(result.is_ok());
        let shared_b = result.unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_ecc_parameters() {
        // Generate the key pair
        let keypair = generate_ecc(CryptoEccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        let result = ecc_private.curve();
        assert!(result.is_ok());
        assert!(result.unwrap() == CryptoEccCurve::P384);

        let result = ecc_public.curve();
        assert!(result.is_ok());
        assert!(result.unwrap() == CryptoEccCurve::P384);

        let result = ecc_private.coordinates();
        assert!(result.is_ok());
        let (x_from_private, y_from_private) = result.unwrap();

        let result = ecc_public.coordinates();
        assert!(result.is_ok());
        let (x_from_public, y_from_public) = result.unwrap();

        assert_eq!(x_from_private, x_from_public);
        assert_eq!(y_from_private, y_from_public);
    }

    #[test]
    fn test_ecc_from_raw_key() {
        // Hardcoded raw private key (32 bytes for P-256)
        let raw_private_key: [u8; 32] = [
            0x1f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
            0xdc, 0xed, 0xfe, 0x01,
        ];

        // Convert raw private key into an ECC private key using `from_raw`
        let result = EccPrivateKey::from_raw(&raw_private_key, CryptoKeyKind::Ecc256Private);
        assert!(result.is_ok(), "Failed to create ECC private key from raw");
        let ecc_private = result.unwrap();

        // Extract the public key from the private key
        let public_key_result = ecc_private.extract_pub_key_der();
        assert!(
            public_key_result.is_ok(),
            "Failed to extract public key from private key"
        );
        let extracted_public_key = public_key_result.unwrap();

        // Use the private key to sign data
        let data = [1u8; 32];
        let result = ecc_private.sign(&data);
        assert!(result.is_ok(), "Failed to sign data with private key");
        let signature = result.unwrap();

        // Verify the signature using the extracted public key
        let ecc_public =
            EccPublicKey::from_der(&extracted_public_key, Some(CryptoKeyKind::Ecc256Public))
                .expect("Failed to create ECC public key");
        let result = ecc_public.verify(&data, &signature);
        assert!(
            result.is_ok(),
            "Signature verification failed with public key"
        );
    }
}
