// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for elliptic curve cryptography (ECC).

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and non-OpenSSL cannot be enabled at the same time.");

#[cfg(feature = "use-symcrypt")]
use std::time::Duration;

#[cfg(feature = "use-symcrypt")]
use der::Decode;
#[cfg(feature = "use-symcrypt")]
use generic_array;
use mcr_ddi_types::DdiEccCurve;
#[cfg(feature = "use-openssl")]
use openssl;
#[cfg(feature = "use-openssl")]
use openssl::bn::BigNum;
#[cfg(feature = "use-openssl")]
use openssl::bn::BigNumContext;
#[cfg(feature = "use-openssl")]
use openssl::derive::Deriver;
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
#[cfg(feature = "use-openssl")]
use openssl::x509::X509NameBuilder;
#[cfg(feature = "use-openssl")]
use openssl::x509::X509;
#[cfg(feature = "use-symcrypt")]
use spki::SubjectPublicKeyInfo;
#[cfg(feature = "use-symcrypt")]
use symcrypt::ecc;
#[cfg(feature = "use-symcrypt")]
use symcrypt::errors::SymCryptError;
#[cfg(feature = "use-symcrypt")]
use x509_cert::builder::Builder;
#[cfg(feature = "use-symcrypt")]
use x509_cert::builder::CertificateBuilder;
#[cfg(feature = "use-symcrypt")]
use x509_cert::builder::Profile;
#[cfg(feature = "use-symcrypt")]
use x509_cert::name::Name;
#[cfg(feature = "use-symcrypt")]
use x509_cert::serial_number::SerialNumber;
#[cfg(feature = "use-symcrypt")]
use x509_cert::time::Validity;

#[cfg(feature = "use-openssl")]
use crate::crypto::ecc::openssl::asn1::Asn1Time;
use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

#[cfg(feature = "use-symcrypt")]
const EC_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
#[cfg(feature = "use-symcrypt")]
const P256_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
#[cfg(feature = "use-symcrypt")]
const P384_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");
#[cfg(feature = "use-symcrypt")]
const P521_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// Trait for ECC common operations.
pub trait EccOp<T> {
    /// Create an ECC key from DER encoded bytes.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<T, ManticoreError>;

    /// Encode the ECC key to DER format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Get the ECC curve type.
    fn curve(&self) -> Result<EccCurve, ManticoreError>;

    /// Get the ECC key coordinates (x, y).
    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError>;

    /// Get the ECC key size.
    fn size(&self) -> EccKeySize;
}

/// Trait for ECC private key operations.
pub trait EccPrivateOp {
    /// Sign a digest using the ECC private key.
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, ManticoreError>;

    /// Derive a shared secret using the ECC private key and a peer's public key.
    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, ManticoreError>;

    /// Get the ECC public key associated with this private key.
    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Create public key certificate.
    fn create_pub_key_cert(&self) -> Result<Vec<u8>, ManticoreError>;
}

/// Trait for ECC public key operations.
#[cfg(test)]
pub trait EccPublicOp {
    /// Verify a signature against a digest using the ECC public key.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), ManticoreError>;
}

/// Supported ECC curve.
#[derive(Debug, PartialEq)]
pub enum EccCurve {
    /// P-256
    P256,

    /// P-384
    P384,

    /// P-521
    P521,
}

impl TryFrom<DdiEccCurve> for EccCurve {
    type Error = ManticoreError;

    fn try_from(value: DdiEccCurve) -> Result<Self, Self::Error> {
        match value {
            DdiEccCurve::P256 => Ok(EccCurve::P256),
            DdiEccCurve::P384 => Ok(EccCurve::P384),
            DdiEccCurve::P521 => Ok(EccCurve::P521),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

/// Size of ECC key in bits.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EccKeySize {
    /// 256-bit key.
    Ecc256,

    /// 384-bit key.
    Ecc384,

    /// 521-bit key.
    Ecc521,
}

impl TryFrom<u32> for EccKeySize {
    type Error = ManticoreError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            256 => Ok(Self::Ecc256),
            384 => Ok(Self::Ecc384),
            521 => Ok(Self::Ecc521),
            _ => Err(ManticoreError::EccInvalidKeyLength),
        }
    }
}

/// Generate an ECC key pair using openssl.
///
/// # Arguments
/// * `curve` - The ECC curve of the key pair to generate (p256/ p384/ p521).
///
/// # Returns
/// * `(EccPrivateKey, EccPublicKey)` - Generated ECC key pair.
///
/// # Errors
/// * `ManticoreError::EccGenerateError` - If the ECC key pair generation fails.
#[cfg(feature = "use-openssl")]
pub fn generate_ecc(curve: EccCurve) -> Result<(EccPrivateKey, EccPublicKey), ManticoreError> {
    let curve_name = match curve {
        EccCurve::P256 => Nid::X9_62_PRIME256V1,
        EccCurve::P384 => Nid::SECP384R1,
        EccCurve::P521 => Nid::SECP521R1,
    };
    let group =
        openssl::ec::EcGroup::from_curve_name(curve_name).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGenerateError
        })?;
    let ecc_private = openssl::ec::EcKey::generate(&group).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::EccGenerateError
    })?;
    let ecc_public = openssl::ec::EcKey::from_public_key(&group, ecc_private.public_key())
        .map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGenerateError
        })?;

    let pkey_private =
        openssl::pkey::PKey::from_ec_key(ecc_private).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGenerateError
        })?;
    let pkey_public =
        openssl::pkey::PKey::from_ec_key(ecc_public).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGenerateError
        })?;

    Ok((
        EccPrivateKey {
            handle: pkey_private.clone(),
            size: pkey_private.bits().try_into()?,
        },
        EccPublicKey {
            handle: pkey_public.clone(),
            size: pkey_public.bits().try_into()?,
        },
    ))
}

/// Generate an ECC key pair.
#[cfg(feature = "use-symcrypt")]
pub fn generate_ecc(curve: EccCurve) -> Result<(EccPrivateKey, EccPublicKey), ManticoreError> {
    let (curve_type, size) = match curve {
        EccCurve::P256 => (ecc::CurveType::NistP256, EccKeySize::Ecc256),
        EccCurve::P384 => (ecc::CurveType::NistP384, EccKeySize::Ecc384),
        EccCurve::P521 => (ecc::CurveType::NistP521, EccKeySize::Ecc521),
    };
    let key_pair = ecc::EcKey::generate_key_pair(curve_type, ecc::EcKeyUsage::EcDhAndEcDsa)
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::EccGenerateError
        })?;
    let raw_public_key = key_pair
        .export_public_key()
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::EccGenerateError
        })?;
    let raw_private_key = key_pair
        .export_private_key()
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::EccGenerateError
        })?;
    Ok((
        EccPrivateKey {
            handle: EccKeyContainer {
                curve_type,
                ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                has_private_key: true,
                public_key: raw_public_key.clone(),
                private_key: raw_private_key,
            },
            size,
        },
        EccPublicKey {
            handle: EccKeyContainer {
                curve_type,
                ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                has_private_key: false,
                public_key: raw_public_key,
                private_key: vec![],
            },
            size,
        },
    ))
}

#[cfg(feature = "use-symcrypt")]
#[derive(Debug, Clone)]
struct EccKeyContainer {
    curve_type: ecc::CurveType,
    ec_key_usage: ecc::EcKeyUsage,
    has_private_key: bool,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}
#[cfg(feature = "use-symcrypt")]
impl EccKeyContainer {
    fn get_curve_type(&self) -> ecc::CurveType {
        self.curve_type
    }

    fn export_private_key(&self) -> Result<Vec<u8>, SymCryptError> {
        if self.has_private_key {
            Ok(self.private_key.clone())
        } else {
            Err(SymCryptError::InvalidBlob)
        }
    }

    fn export_public_key(&self) -> Result<Vec<u8>, SymCryptError> {
        Ok(self.public_key.clone())
    }

    fn ecdsa_sign(&self, digest: &[u8]) -> Result<Vec<u8>, SymCryptError> {
        let handle = ecc::EcKey::set_key_pair(
            self.curve_type,
            self.private_key.as_slice(),
            Some(self.public_key.as_slice()),
            self.ec_key_usage,
        )?;
        handle.ecdsa_sign(digest)
    }

    pub fn ecdh_secret_agreement(&self, public_key: ecc::EcKey) -> Result<Vec<u8>, SymCryptError> {
        let handle = ecc::EcKey::set_key_pair(
            self.curve_type,
            self.private_key.as_slice(),
            Some(self.public_key.as_slice()),
            self.ec_key_usage,
        )?;
        handle.ecdh_secret_agreement(public_key)
    }

    fn get_ec_curve_usage(&self) -> ecc::EcKeyUsage {
        self.ec_key_usage
    }

    #[cfg(test)]
    fn ecdsa_verify(&self, signature: &[u8], hashed_message: &[u8]) -> Result<(), SymCryptError> {
        let handle = ecc::EcKey::set_public_key(
            self.curve_type,
            self.public_key.as_slice(),
            self.ec_key_usage,
        )?;

        handle.ecdsa_verify(signature, hashed_message)
    }
}

/// ECC Private Key.
#[derive(Debug, Clone)]
pub struct EccPrivateKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Private>,

    #[cfg(feature = "use-symcrypt")]
    handle: EccKeyContainer,
    size: EccKeySize,
}

impl KeySerialization<EccPrivateKey> for EccPrivateKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        self.to_der()
    }

    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<EccPrivateKey, ManticoreError> {
        EccPrivateKey::from_der(raw, Some(expected_type))
    }
}

#[cfg(feature = "use-openssl")]
impl EccOp<EccPrivateKey> for EccPrivateKey {
    /// Deserialize an ECC private key from a DER-encoded PKCS#8 format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<Self, ManticoreError> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccFromDerError
        })?;

        let key_size = pkey.bits().try_into()?;
        match expected_type {
            Some(Kind::Ecc256Private) => {
                if key_size != EccKeySize::Ecc256 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Ecc384Private) => {
                if key_size != EccKeySize::Ecc384 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Ecc521Private) => {
                if key_size != EccKeySize::Ecc521 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            None => {
                // Key size has been validated during `EccKeySize` conversion.
                // Do nothing here.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self {
            handle: pkey,
            size: key_size,
        })
    }

    /// Serialize the ECC private key to a DER-encoded PKCS#8 format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let der = self
            .handle
            .as_ref()
            .private_key_to_pkcs8()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccToDerError
            })?;

        Ok(der)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCurveError
        })?;
        let curve_name = ec_key
            .group()
            .curve_name()
            .ok_or(ManticoreError::EccGetCurveError)?;

        let curve = match curve_name {
            Nid::X9_62_PRIME256V1 => EccCurve::P256,
            Nid::SECP384R1 => EccCurve::P384,
            Nid::SECP521R1 => EccCurve::P521,
            _ => Err(ManticoreError::EccGetCurveError)?,
        };

        Ok(curve)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let group = ec_key.group();
        let mut x = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let mut y = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let mut ctx = BigNumContext::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;

        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccGetCoordinatesError
            })?;

        Ok((x.to_vec(), y.to_vec()))
    }

    /// Get Key Size
    fn size(&self) -> EccKeySize {
        self.size
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccOp<EccPrivateKey> for EccPrivateKey {
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<EccPrivateKey, ManticoreError> {
        use sec1::der::Decode;

        let private_key_info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccFromDerError
        })?;
        let (_alg_oid, param_oid) = private_key_info.algorithm.oids().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccFromDerError
        })?;

        let private_key =
            sec1::EcPrivateKey::from_der(private_key_info.private_key).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccFromDerError
            })?;

        let (curve_type, symcrypt_key) = match param_oid {
            oid if oid == Some(P256_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc256Private) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }
                let curve_type = ecc::CurveType::NistP256;

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    curve_type,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::EccFromDerError
                })?;

                (curve_type, symcrypt_key)
            }
            oid if oid == Some(P384_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc384Private) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }
                let curve_type = ecc::CurveType::NistP384;

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    curve_type,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::EccFromDerError
                })?;

                (curve_type, symcrypt_key)
            }
            oid if oid == Some(P521_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc521Private) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }
                let curve_type = ecc::CurveType::NistP521;

                let symcrypt_key = ecc::EcKey::set_key_pair(
                    curve_type,
                    private_key.private_key,
                    None,
                    ecc::EcKeyUsage::EcDhAndEcDsa,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::EccFromDerError
                })?;

                (curve_type, symcrypt_key)
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        };

        let public_key = symcrypt_key
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccFromDerError
            })?;

        let size = match curve_type {
            ecc::CurveType::NistP256 => EccKeySize::Ecc256,
            ecc::CurveType::NistP384 => EccKeySize::Ecc384,
            ecc::CurveType::NistP521 => EccKeySize::Ecc521,
            _ => Err(ManticoreError::EccFromDerError)?,
        };

        Ok(Self {
            handle: EccKeyContainer {
                curve_type,
                ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                has_private_key: true,
                public_key,
                private_key: private_key.private_key.to_vec(),
            },
            size,
        })
    }

    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use sec1::der::Encode;

        let private_key_data =
            self.handle
                .export_private_key()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::EccFromDerError
                })?;
        let public_key_data = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccFromDerError
            })?;

        // Validate length is even (X and Y should be equal length)
        if public_key_data.len() % 2 != 0 {
            return Err(ManticoreError::EccFromDerError);
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

        let param_oid: sec1::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(ManticoreError::EccToDerError)?,
        };

        use spki::der::referenced::OwnedToRef;
        let alg_id = spki::AlgorithmIdentifier {
            oid: EC_OID,
            parameters: Some(param_oid.owned_to_ref()),
        };

        let private_key_der = private_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccToDerError
        })?;
        let private_key_info = pkcs8::PrivateKeyInfo::new(alg_id, &private_key_der);

        let der = private_key_info.to_der().map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::EccFromDerError
        })?;
        Ok(der)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => Ok(EccCurve::P256),
            ecc::CurveType::NistP384 => Ok(EccCurve::P384),
            ecc::CurveType::NistP521 => Ok(EccCurve::P521),
            _ => Err(ManticoreError::EccGetCurveError)?,
        }
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let raw_public_key = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccGetCoordinatesError
            })?;
        let point_size = raw_public_key.len() / 2;
        let x = raw_public_key[..point_size].to_vec();
        let y = raw_public_key[point_size..].to_vec();
        Ok((x, y))
    }

    fn size(&self) -> EccKeySize {
        self.size
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
    /// * `ManticoreError::EccSignError` - If the signing operation fails.
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccSignError
        })?;

        ctx.sign_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccSignError
        })?;

        let buffer_len = ctx.sign(digest, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccSignError
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let signature_len = ctx
            .sign(digest, Some(&mut buffer))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccSignError
            })?;

        let buffer = &buffer[..signature_len];

        // Convert the DER-encoded signature to fixed-size raw signature.
        let signature = EcdsaSig::from_der(buffer).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccSignError
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
            return Err(ManticoreError::InternalError);
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
    /// * `ManticoreError::EccDeriveError` - If the operation fails.
    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, ManticoreError> {
        let mut deriver = Deriver::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccDeriveError
        })?;

        deriver
            .set_peer(&peer.handle)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccDeriveError
            })?;

        let secret = deriver.derive_to_vec().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccDeriveError
        })?;

        Ok(secret)
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError> {
        self.handle
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccToDerError
            })
    }

    /// TEST_ONLY: This function is for testing purposes only.
    /// We don't need to generate the certificate in production.
    #[cfg(feature = "use-openssl")]
    fn create_pub_key_cert(&self) -> Result<Vec<u8>, ManticoreError> {
        let pkey = self.handle.clone();

        // Create a new X509 certificate builder
        let mut builder = X509::builder().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        // Set the version of the certificate (v3)
        builder.set_version(2).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        // Generate a X509 name and set it as the issuer and subject of the certificate
        let mut name_builder = X509NameBuilder::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, "example.com")
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        let name = name_builder.build();
        builder
            .set_subject_name(&name)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        builder
            .set_issuer_name(&name)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        // Set the public key of the certificate
        builder.set_pubkey(&pkey).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        // Set the validity period of the certificate
        let not_before = Asn1Time::days_from_now(0).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        let not_after = Asn1Time::days_from_now(365).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        builder
            .set_not_before(&not_before)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        builder
            .set_not_after(&not_after)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        // Sign the certificate with the private key
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        // Build the certificate
        let certificate = builder.build();

        // Serialize the certificate to DER format
        let cert_der = certificate.to_der().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        Ok(cert_der.as_slice().to_vec())
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccPrivateOp for EccPrivateKey {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        let signature = self
            .handle
            .ecdsa_sign(digest)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccSignError
            })?;
        Ok(signature)
    }

    fn derive(&self, peer: &EccPublicKey) -> Result<Vec<u8>, ManticoreError> {
        let raw_public_key = peer
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccDeriveError
            })?;
        let handle = ecc::EcKey::set_public_key(
            peer.handle.get_curve_type(),
            &raw_public_key,
            peer.handle.get_ec_curve_usage(),
        )
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::EccDeriveError
        })?;
        let secret = self
            .handle
            .ecdh_secret_agreement(handle)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccDeriveError
            })?;
        Ok(secret)
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use sec1::der::Encode;

        let public_key_point = self.handle.export_public_key().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccToDerError
        })?;

        let public_key_der = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP384 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U48>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP521 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U66>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            _ => Err(ManticoreError::EccToDerError)?,
        };

        let public_key_der_bitstring =
            der::asn1::BitString::from_bytes(&public_key_der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccToDerError
            })?;

        let param_oid: sec1::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(ManticoreError::EccToDerError)?,
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
            ManticoreError::EccToDerError
        })?;

        Ok(der)
    }

    fn create_pub_key_cert(&self) -> Result<Vec<u8>, ManticoreError> {
        use std::str::FromStr;

        use der::Encode;

        let der = self.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        let public_key_der = self.extract_pub_key_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        let public_key =
            SubjectPublicKeyInfo::from_der(&public_key_der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;

        let profile = Profile::Root;
        let serial_number = SerialNumber::from(1u32);
        let validity =
            Validity::from_now(Duration::new(365 * 24 * 60 * 60, 0)).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccPubKeyCertGenerateError
            })?;
        let subject = Name::from_str("CN=example.com").unwrap();

        let cert = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => {
                use p256::ecdsa::DerSignature;
                use p256::pkcs8::DecodePrivateKey;
                let ec_key_p256 = p256::SecretKey::from_pkcs8_der(&der).map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })?;

                let signer = p256::ecdsa::SigningKey::from(ec_key_p256);

                let builder = CertificateBuilder::new(
                    profile,
                    serial_number,
                    validity,
                    subject,
                    public_key,
                    &signer,
                )
                .map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })?;

                builder.build::<DerSignature>().map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })
            }

            ecc::CurveType::NistP384 => {
                use p384::ecdsa::DerSignature;
                use p384::pkcs8::DecodePrivateKey;
                let ec_key_p384 = p384::SecretKey::from_pkcs8_der(&der).map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })?;
                let signer = p384::ecdsa::SigningKey::from(ec_key_p384);

                let builder = CertificateBuilder::new(
                    profile,
                    serial_number,
                    validity,
                    subject,
                    public_key,
                    &signer,
                )
                .map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })?;

                builder.build::<DerSignature>().map_err(|error_stack| {
                    tracing::error!(?error_stack);
                    ManticoreError::EccPubKeyCertGenerateError
                })
            }
            ecc::CurveType::NistP521 => {
                // p521 does not implement the KeyPairRef trait required by CertificateBuilder.
                // Returning an error until the dependency is updated.
                Err(ManticoreError::EccPubKeyCertGenerateError)
            }
            _ => Err(ManticoreError::EccPubKeyCertGenerateError),
        }?;

        let der = cert.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        Ok(der)
    }
}

/// ECC Public Key.
#[derive(Debug, Clone)]
pub struct EccPublicKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Public>,

    #[cfg(feature = "use-symcrypt")]
    handle: EccKeyContainer,

    #[allow(unused)]
    size: EccKeySize,
}

#[cfg(feature = "use-openssl")]
impl EccOp<EccPublicKey> for EccPublicKey {
    /// Deserialize an ECC public key from a DER-encoded SubjectPublicKeyInfo format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<Self, ManticoreError> {
        let ecc = openssl::ec::EcKey::public_key_from_der(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccFromDerError
        })?;
        let pkey = openssl::pkey::PKey::from_ec_key(ecc).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccFromDerError
        })?;

        let key_size = pkey.bits().try_into()?;
        match expected_type {
            Some(Kind::Ecc256Public) => {
                if key_size != EccKeySize::Ecc256 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Ecc384Public) => {
                if key_size != EccKeySize::Ecc384 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Ecc521Public) => {
                if key_size != EccKeySize::Ecc521 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            None => {
                // Key size has been validated during `EccKeySize` conversion.
                // Do nothing here.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self {
            handle: pkey,
            size: key_size,
        })
    }

    /// Serialize the ECC public key to a DER-encoded SubjectPublicKeyInfo format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let der = self
            .handle
            .as_ref()
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccToDerError
            })?;

        Ok(der)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCurveError
        })?;
        let curve_name = ec_key
            .group()
            .curve_name()
            .ok_or(ManticoreError::EccGetCurveError)?;

        let curve = match curve_name {
            Nid::X9_62_PRIME256V1 => EccCurve::P256,
            Nid::SECP384R1 => EccCurve::P384,
            Nid::SECP521R1 => EccCurve::P521,
            _ => Err(ManticoreError::EccGetCurveError)?,
        };

        Ok(curve)
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let ec_key = self.handle.ec_key().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let group = ec_key.group();
        let mut x = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let mut y = BigNum::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;
        let mut ctx = BigNumContext::new().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccGetCoordinatesError
        })?;

        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccGetCoordinatesError
            })?;

        Ok((x.to_vec(), y.to_vec()))
    }

    /// Get Key Size
    fn size(&self) -> EccKeySize {
        self.size
    }
}

#[cfg(feature = "use-symcrypt")]
impl EccOp<EccPublicKey> for EccPublicKey {
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<EccPublicKey, ManticoreError> {
        use sec1::der::Decode;

        let public_key_info =
            spki::SubjectPublicKeyInfoRef::from_der(der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccFromDerError
            })?;

        let public_key_der = public_key_info.subject_public_key;
        let (_alg_oid, param_oid) = public_key_info.algorithm.oids().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccFromDerError
        })?;

        match param_oid {
            oid if oid == Some(P256_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc256Public) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }

                Ok(Self {
                    handle: EccKeyContainer {
                        curve_type: ecc::CurveType::NistP256,
                        ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                        has_private_key: false,
                        public_key: public_key_der.raw_bytes()[1..].to_vec(), // Remove the leading SEC1 tag byte
                        private_key: vec![],
                    },
                    size: EccKeySize::Ecc256,
                })
            }
            oid if oid == Some(P384_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc384Public) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }

                Ok(Self {
                    handle: EccKeyContainer {
                        curve_type: ecc::CurveType::NistP384,
                        ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                        has_private_key: false,
                        public_key: public_key_der.raw_bytes()[1..].to_vec(), // Remove the leading SEC1 tag byte
                        private_key: vec![],
                    },
                    size: EccKeySize::Ecc384,
                })
            }
            oid if oid == Some(P521_OID) => {
                if expected_type.is_some() && expected_type != Some(Kind::Ecc521Public) {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?;
                }

                Ok(Self {
                    handle: EccKeyContainer {
                        curve_type: ecc::CurveType::NistP521,
                        ec_key_usage: ecc::EcKeyUsage::EcDhAndEcDsa,
                        has_private_key: false,
                        public_key: public_key_der.raw_bytes()[1..].to_vec(), // Remove the leading SEC1 tag byte
                        private_key: vec![],
                    },
                    size: EccKeySize::Ecc521,
                })
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }
    }

    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use sec1::der::Encode;

        let public_key_point = self.handle.export_public_key().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccToDerError
        })?;

        let public_key_der = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U32>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP384 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U48>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            ecc::CurveType::NistP521 => {
                let generic_array = generic_array::GenericArray::from_slice(&public_key_point);
                let point =
                    sec1::EncodedPoint::<sec1::consts::U66>::from_untagged_bytes(generic_array);
                point.as_bytes().to_vec()
            }
            _ => Err(ManticoreError::EccToDerError)?,
        };

        let public_key_der_bitstring =
            der::asn1::BitString::from_bytes(&public_key_der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::EccToDerError
            })?;

        let param_oid: sec1::der::Any = match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => P256_OID.into(),
            ecc::CurveType::NistP384 => P384_OID.into(),
            ecc::CurveType::NistP521 => P521_OID.into(),
            _ => Err(ManticoreError::EccToDerError)?,
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
            ManticoreError::EccToDerError
        })?;

        Ok(der)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        match self.handle.get_curve_type() {
            ecc::CurveType::NistP256 => Ok(EccCurve::P256),
            ecc::CurveType::NistP384 => Ok(EccCurve::P384),
            ecc::CurveType::NistP521 => Ok(EccCurve::P521),
            _ => Err(ManticoreError::EccGetCurveError)?,
        }
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let raw_public_key = self
            .handle
            .export_public_key()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccGetCoordinatesError
            })?;
        let point_size = raw_public_key.len() / 2;
        let x = raw_public_key[..point_size].to_vec();
        let y = raw_public_key[point_size..].to_vec();
        Ok((x, y))
    }

    fn size(&self) -> EccKeySize {
        self.size
    }
}

#[cfg(test)]
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
    /// * `ManticoreError::InvalidArgument` - If the signature is not even.
    /// * `ManticoreError::EccVerifyError` - If the verification fails.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), ManticoreError> {
        let signature_len = signature.len();
        if signature_len % 2 != 0 {
            Err(ManticoreError::InvalidArgument)?
        }

        // Convert the raw signature to DER, which is expected by OpenSSL verify API.
        let (r, s) = signature.split_at(signature_len / 2);
        let r = BigNum::from_slice(r).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;
        let s = BigNum::from_slice(s).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;
        let signature = EcdsaSig::from_private_components(r, s).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;
        let signature = signature.to_der().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;

        ctx.verify_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::EccVerifyError
        })?;

        let result = ctx
            .verify(digest, &signature)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::EccVerifyError
            })?;

        // Return error on verification failure.
        if !result {
            Err(ManticoreError::EccVerifyError)?
        }

        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "use-symcrypt")]
impl EccPublicOp for EccPublicKey {
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), ManticoreError> {
        let signature_len = signature.len();
        if signature_len % 2 != 0 {
            Err(ManticoreError::InvalidArgument)?
        }
        let result = self
            .handle
            .ecdsa_verify(signature, digest)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::EccVerifyError
            });
        if result.is_err() {
            Err(ManticoreError::EccVerifyError)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::*;

    #[test]
    fn test_ecc_private() {
        let data = [1u8; 1024];

        // Generate the key pair
        let keypair = generate_ecc(EccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        // Convert the key to der
        let result = ecc_private.to_der();
        assert!(result.is_ok());

        // Convert der back to the key
        let result = EccPrivateKey::from_der(&result.unwrap(), Some(Kind::Ecc384Private));
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
        let result = EccPublicKey::from_der(&result.unwrap(), Some(Kind::Ecc384Public));
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

        let result = EccPrivateKey::from_der(&DER_SEC1, Some(Kind::Ecc256Private));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::EccFromDerError);
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

        let result = EccPrivateKey::from_der(&DER_PKCS8, Some(Kind::Ecc256Private));
        assert!(result.is_ok());

        let result = EccPublicKey::from_der(&DER_PKCS8, Some(Kind::Ecc256Public));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::EccFromDerError);
        }
    }

    #[test]
    fn test_ecc_public() {
        let data = [1u8; 1024];

        // Generate the key pair
        let keypair = generate_ecc(EccCurve::P384);
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
        let result = EccPublicKey::from_der(&result.unwrap(), Some(Kind::Ecc384Public));
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

        let result = EccPublicKey::from_der(&DER_SUBJECT_PUBLIC_KEY_INFO, Some(Kind::Ecc256Public));
        assert!(result.is_ok());

        let result =
            EccPrivateKey::from_der(&DER_SUBJECT_PUBLIC_KEY_INFO, Some(Kind::Ecc256Private));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::EccFromDerError);
        }
    }

    #[test]
    fn test_ecc_derive() {
        // Generate the key pair a
        let keypair = generate_ecc(EccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private_a, ecc_public_a) = keypair.unwrap();

        // Generate the key pair b
        let keypair = generate_ecc(EccCurve::P384);
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
        let keypair = generate_ecc(EccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        let result = ecc_private.curve();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EccCurve::P384);

        let result = ecc_public.curve();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EccCurve::P384);

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
    #[cfg(feature = "use-openssl")]
    fn test_ecc_create_pub_key_cert() {
        // Generate the key pair
        let keypair = generate_ecc(EccCurve::P384);
        assert!(keypair.is_ok());
        let (ecc_private, ecc_public) = keypair.unwrap();

        let result = ecc_private.create_pub_key_cert();
        assert!(result.is_ok());

        // validate the x509 certificate
        let result = X509::from_der(&result.unwrap());
        assert!(result.is_ok());

        let cert = result.unwrap();
        let result = cert.verify(&ecc_public.handle);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(feature = "use-symcrypt")]
    fn test_ecc_create_pub_key_cert() {
        // TODO: This test on Windows needs to be implemented
        // without dependency on OpenSSL.
    }
}
