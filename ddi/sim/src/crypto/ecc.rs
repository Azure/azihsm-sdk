// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for elliptic curve cryptography (ECC).

use azihsm_crypto as crypto;
use azihsm_ddi_types::DdiEccCurve;
use crypto::DeriveOp;
use crypto::EccKeyOp;
use crypto::ExportableKey;
use crypto::ImportableKey;
use crypto::PrivateKey;
use crypto::SignOp;
use crypto::VerifyOp;

use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

/// Implementation of conversion from CryptoError to ManticoreError
impl From<crypto::CryptoError> for ManticoreError {
    fn from(err: crypto::CryptoError) -> Self {
        match err {
            crypto::CryptoError::EccKeyGenError => ManticoreError::EccGenerateError,
            crypto::CryptoError::EccKeyImportError => ManticoreError::EccFromDerError,
            crypto::CryptoError::EccKeyExportError => ManticoreError::EccToDerError,
            crypto::CryptoError::EccSignError => ManticoreError::EccSignError,
            crypto::CryptoError::EccVerifyError => ManticoreError::EccVerifyError,
            crypto::CryptoError::EccError => ManticoreError::EccGetCurveError,
            crypto::CryptoError::DerAsn1DecodeError => ManticoreError::EccFromDerError,
            crypto::CryptoError::EcdhError | crypto::CryptoError::EcdhDeriveError => {
                ManticoreError::EccDeriveError
            }
            crypto::CryptoError::EccBufferTooSmall => ManticoreError::EccGetCoordinatesError,
            _ => ManticoreError::InternalError,
        }
    }
}

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

impl From<EccCurve> for crypto::EccCurve {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::P256 => crypto::EccCurve::P256,
            EccCurve::P384 => crypto::EccCurve::P384,
            EccCurve::P521 => crypto::EccCurve::P521,
        }
    }
}

impl From<crypto::EccCurve> for EccCurve {
    fn from(curve: crypto::EccCurve) -> Self {
        match curve {
            crypto::EccCurve::P256 => EccCurve::P256,
            crypto::EccCurve::P384 => EccCurve::P384,
            crypto::EccCurve::P521 => EccCurve::P521,
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

impl From<crypto::EccCurve> for EccKeySize {
    fn from(curve: crypto::EccCurve) -> Self {
        match curve {
            crypto::EccCurve::P256 => EccKeySize::Ecc256,
            crypto::EccCurve::P384 => EccKeySize::Ecc384,
            crypto::EccCurve::P521 => EccKeySize::Ecc521,
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
/// # Errors
/// * `ManticoreError::EccGenerateError` - If the ECC key pair generation fails.
pub fn generate_ecc(curve: EccCurve) -> Result<(EccPrivateKey, EccPublicKey), ManticoreError> {
    let crypto_curve: crypto::EccCurve = curve.into();
    let private_key = crypto::EccPrivateKey::from_curve(crypto_curve)?;
    let public_key = private_key.public_key()?;

    Ok((
        EccPrivateKey { key: private_key },
        EccPublicKey { key: public_key },
    ))
}

/// ECC Private Key.
#[derive(Debug, Clone)]
pub struct EccPrivateKey {
    key: crypto::EccPrivateKey,
}

impl KeySerialization<EccPrivateKey> for EccPrivateKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        self.to_der()
    }

    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<EccPrivateKey, ManticoreError> {
        EccPrivateKey::from_der(raw, Some(expected_type))
    }
}

impl EccOp<EccPrivateKey> for EccPrivateKey {
    /// Deserialize an ECC private key from a DER-encoded PKCS#8 format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<Self, ManticoreError> {
        let key = crypto::EccPrivateKey::from_bytes(der)?;
        let key_size: EccKeySize = key.curve().into();

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
                // Key size has been validated during EccKeySize conversion.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self { key })
    }

    /// Serialize the ECC private key to a DER-encoded PKCS#8 format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let size = self.key.to_bytes(None)?;
        let mut buffer = vec![0u8; size];
        self.key.to_bytes(Some(&mut buffer))?;
        Ok(buffer)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        Ok(self.key.curve().into())
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let coords = self.key.coord_vec()?;
        Ok(coords)
    }

    /// Get Key Size
    fn size(&self) -> EccKeySize {
        self.key.curve().into()
    }
}

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
        let mut algo = crypto::EccAlgo::default();
        let size = algo.sign(&self.key, digest, None)?;
        let mut signature = vec![0u8; size];
        algo.sign(&self.key, digest, Some(&mut signature))?;
        Ok(signature)
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
        let algo = crypto::EcdhAlgo::new(&peer.key);
        let secret = algo.derive(&self.key, self.key.curve().point_size())?;
        Ok(secret.to_vec()?)
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let public_key = self.key.public_key()?;
        let size = public_key.to_bytes(None)?;
        let mut buffer = vec![0u8; size];
        public_key.to_bytes(Some(&mut buffer))?;
        Ok(buffer)
    }

    fn create_pub_key_cert(&self) -> Result<Vec<u8>, ManticoreError> {
        let der = self.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        let public_key_der = self.extract_pub_key_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::EccPubKeyCertGenerateError
        })?;

        let cert = match self.key.curve() {
            crypto::EccCurve::P384 => {
                use crate::crypto::cert::recreate_cert;

                recreate_cert(&public_key_der, &der)
            }
            _ => Err(ManticoreError::EccPubKeyCertGenerateError),
        }?;

        Ok(cert)
    }
}

/// ECC Public Key.
#[derive(Debug, Clone)]
pub struct EccPublicKey {
    key: crypto::EccPublicKey,
}

impl EccOp<EccPublicKey> for EccPublicKey {
    /// Deserialize an ECC public key from a DER-encoded SubjectPublicKeyInfo format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<Self, ManticoreError> {
        let key = crypto::EccPublicKey::from_bytes(der)?;
        let key_size: EccKeySize = key.curve().into();

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
                // Key size has been validated during EccKeySize conversion.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(Self { key })
    }

    /// Serialize the ECC public key to a DER-encoded SubjectPublicKeyInfo format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let size = self.key.to_bytes(None)?;
        let mut buffer = vec![0u8; size];
        self.key.to_bytes(Some(&mut buffer))?;
        Ok(buffer)
    }

    fn curve(&self) -> Result<EccCurve, ManticoreError> {
        Ok(self.key.curve().into())
    }

    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let coords = self.key.coord_vec()?;
        Ok(coords)
    }

    fn size(&self) -> EccKeySize {
        self.key.curve().into()
    }
}

impl KeySerialization<EccPublicKey> for EccPublicKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        self.to_der()
    }

    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<EccPublicKey, ManticoreError> {
        EccPublicKey::from_der(raw, Some(expected_type))
    }
}

impl EccPublicOp for EccPublicKey {
    /// Verify an ECDSA signature.
    ///
    /// # Arguments
    /// * `digest` - The digest that was signed.
    /// * `signature` - The signature to verify (in raw format).
    ///
    /// # Returns
    /// * `Ok(())` - If the signature is valid.
    ///
    /// # Errors
    /// * `ManticoreError::EccVerifyError` - If the signature verification fails.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), ManticoreError> {
        let mut algo = crypto::EccAlgo::default();
        algo.verify(&self.key, digest, signature)?;
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
}
