// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for RSA Cryptographic Keys.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and non-OpenSSL cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl;
#[cfg(feature = "use-openssl")]
use openssl::bn::BigNum;
#[cfg(feature = "use-openssl")]
use openssl::md::Md;
#[cfg(feature = "use-openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "use-openssl")]
use openssl::pkey::Private;
#[cfg(feature = "use-openssl")]
use openssl::pkey::Public;
#[cfg(feature = "use-openssl")]
use openssl::pkey_ctx::PkeyCtx;
#[cfg(feature = "use-openssl")]
use openssl::rsa::RsaPrivateKeyBuilder;
#[cfg(feature = "use-openssl")]
use openssl::sign::RsaPssSaltlen;
#[cfg(feature = "use-symcrypt")]
use rand::rngs::OsRng;
#[cfg(feature = "use-symcrypt")]
use rsa;
#[cfg(feature = "use-symcrypt")]
use rsa::hazmat::rsa_decrypt;
#[cfg(feature = "use-symcrypt")]
use rsa::hazmat::rsa_encrypt;
#[cfg(feature = "use-symcrypt")]
use rsa::BigUint;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hash::HashAlgorithm as SymcryptHashAlgorithm;
#[cfg(feature = "use-symcrypt")]
use symcrypt::rsa::RsaKey;
#[cfg(feature = "use-symcrypt")]
use symcrypt::rsa::RsaKeyUsage;

use crate::crypto::sha::HashAlgorithm;
use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

#[cfg(feature = "use-symcrypt")]
const RSA_OID: pkcs1::ObjectIdentifier =
    pkcs1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Support padding schemes for RSA encrypt/ decrypt operations.
pub enum RsaCryptoPadding {
    /// No padding.
    None,

    /// OAEP padding scheme.
    Oaep,
}

/// Support padding schemes for RSA sign/ verify operations.
pub enum RsaSignaturePadding {
    /// No padding.
    None,

    /// PSS padding scheme.
    Pss,

    /// PKCS1.5 padding scheme.
    Pkcs1_5,
}

/// Size of RSA modulus in bits.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RsaKeySize {
    /// RSA with 2048-bit modulus.
    Rsa2048,

    /// RSA with 3072-bit modulus.
    Rsa3072,

    /// RSA with 4096-bit modulus.
    Rsa4096,
}

impl TryFrom<u32> for RsaKeySize {
    type Error = ManticoreError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Rsa2048),
            3072 => Ok(Self::Rsa3072),
            4096 => Ok(Self::Rsa4096),
            _ => Err(ManticoreError::RsaInvalidKeyLength),
        }
    }
}

/// Trait for RSA Operations.
pub trait RsaOp<T> {
    /// Deserialize an RSA key from a DER-encoded format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<T, ManticoreError>;

    /// Serialize the RSA key to a DER-encoded format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, ManticoreError>;

    /// Get Key Size
    fn size(&self) -> RsaKeySize;
}

/// Trait for RSA Private Key Operations.
pub trait RsaPrivateOp {
    /// Perform a private key operation.
    fn operate(&self, data: &[u8]) -> Result<Vec<u8>, ManticoreError>;

    /// Decrypt data using the RSA private key.
    fn decrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError>;

    #[cfg(test)]
    #[allow(unused)]
    /// Sign a digest using the RSA private key.
    fn sign(
        &self,
        digest: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, ManticoreError>;

    /// Extract the public key in DER format from the private key.
    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError>;
}

/// Trait for RSA Public Key Operations.
pub trait RsaPublicOp {
    /// Encrypt data using the RSA public key.
    fn encrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError>;
    #[allow(unused)]
    /// Verify a signature using the RSA public key.
    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), ManticoreError>;
}

/// Generate a RSA key pair using openssl.
///
/// # Arguments
/// * `size` - Size of the RSA key pair to generate (2048/ 3072/ 4096 etc).
///
/// # Returns
/// * `(RsaPrivateKey, RsaPublicKey)` - Generated RSA key pair.
///
/// # Errors
/// * `ManticoreError::RsaGenerateError` - If the RSA key pair generation fails.
#[cfg(feature = "use-openssl")]
pub fn generate_rsa(size: u32) -> Result<(RsaPrivateKey, RsaPublicKey), ManticoreError> {
    // Rsa::generate() uses 65537 as public exponent
    let rsa_private = openssl::rsa::Rsa::generate(size).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::RsaGenerateError
    })?;

    // Derive the public key
    let n = rsa_private.n().to_owned().map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::RsaGenerateError
    })?;
    let e = rsa_private.e().to_owned().map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::RsaGenerateError
    })?;
    let rsa_public =
        openssl::rsa::Rsa::from_public_components(n, e).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGenerateError
        })?;

    let pkey_private =
        openssl::pkey::PKey::from_rsa(rsa_private).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGenerateError
        })?;
    let pkey_public = openssl::pkey::PKey::from_rsa(rsa_public).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::RsaGenerateError
    })?;

    Ok((
        RsaPrivateKey {
            handle: pkey_private.clone(),
            size: pkey_private.bits().try_into()?,
        },
        RsaPublicKey {
            handle: pkey_public.clone(),
            size: pkey_public.bits().try_into()?,
        },
    ))
}

/// Generate a RSA key pair using symcrypt.
#[cfg(feature = "use-symcrypt")]
pub fn generate_rsa(size: u32) -> Result<(RsaPrivateKey, RsaPublicKey), ManticoreError> {
    let key_pair = RsaKey::generate_key_pair(size, None, RsaKeyUsage::SignAndEncrypt).map_err(
        |symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::RsaGenerateError
        },
    )?;
    let blob = key_pair
        .export_key_pair_blob()
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::RsaGenerateError
        })?;
    let public_key =
        RsaKey::set_public_key(&blob.modulus, &blob.pub_exp, key_pair.get_rsa_key_usage())
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::RsaGenerateError
            })?;
    let private_key = RsaKey::set_key_pair(
        &blob.modulus,
        &blob.pub_exp,
        &blob.p,
        &blob.q,
        key_pair.get_rsa_key_usage(),
    )
    .map_err(|symcrypt_error_stack| {
        tracing::error!(?symcrypt_error_stack);
        ManticoreError::RsaGenerateError
    })?;
    let size = RsaKeySize::try_from(size)?;
    Ok((
        RsaPrivateKey {
            handle: private_key,
            size,
        },
        RsaPublicKey {
            handle: public_key,
            size,
        },
    ))
}

#[cfg(feature = "use-symcrypt")]
fn create_rsa_public_key_from_symcrypt(
    symcrypt_key: &RsaKey,
) -> Result<rsa::RsaPublicKey, ManticoreError> {
    // Export the public key components from SymCrypt
    let blob = symcrypt_key
        .export_public_key_blob()
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::RsaInvalidKeyType //Todo: Define a more specific error
        })?;

    // Convert byte arrays to BigUint
    let n = BigUint::from_bytes_be(&blob.modulus);
    let e = BigUint::from_bytes_be(&blob.pub_exp);

    // Create the rsa crate's RsaPublicKey
    let rsa_public_key = rsa::RsaPublicKey::new(n, e).map_err(|rsa_error| {
        tracing::error!(?rsa_error);
        ManticoreError::RsaInvalidKeyType
    })?;

    Ok(rsa_public_key)
}

#[cfg(feature = "use-symcrypt")]
fn create_rsa_private_key_from_symcrypt(
    symcrypt_key: &RsaKey,
) -> Result<rsa::RsaPrivateKey, ManticoreError> {
    // Export the private key components from SymCrypt
    let key_pair_blob = symcrypt_key
        .export_key_pair_blob()
        .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::RsaInvalidKeyType
        })?;

    let private_key = rsa::RsaPrivateKey::from_components(
        BigUint::from_bytes_be(&key_pair_blob.modulus),
        BigUint::from_bytes_be(&key_pair_blob.pub_exp),
        BigUint::from_bytes_be(&key_pair_blob.private_exp),
        vec![],
    )
    .map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::RsaInvalidKeyType
    })?;

    Ok(private_key)
}

/// RSA Private Key.
#[derive(Debug)]
pub struct RsaPrivateKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Private>,

    #[cfg(feature = "use-symcrypt")]
    handle: RsaKey,

    size: RsaKeySize,
}

/// RSA Public Key.
#[derive(Debug)]
pub struct RsaPublicKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Public>,

    #[cfg(feature = "use-symcrypt")]
    handle: RsaKey,

    #[allow(unused)]
    size: RsaKeySize,
}

#[cfg(feature = "use-symcrypt")]
impl Clone for RsaPrivateKey {
    fn clone(&self) -> Self {
        // Export the key components
        let blob = self
            .handle
            .export_key_pair_blob()
            .expect("Failed to export key pair blob for cloning");

        // Recreate the private key from components
        let cloned_key = RsaKey::set_key_pair(
            &blob.modulus,
            &blob.pub_exp,
            &blob.p,
            &blob.q,
            self.handle.get_rsa_key_usage(),
        )
        .expect("Failed to recreate private key for cloning");

        RsaPrivateKey {
            handle: cloned_key,
            size: self.size,
        }
    }
}

/// For serializing RSA private key
/// We use BCrypt format: BCRYPT_RSAKEY_BLOB as the output to reduce output size
/// See https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
const BCRYPT_RSAKEY_BLOB_MAGIC: u32 = 843141970;

impl KeySerialization<RsaPrivateKey> for RsaPrivateKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        let bit_length: u32 = match self.size() {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        };
        let public_exp = self.public_exponent()?;
        let modulus = self.modulus()?;
        let primes = self.primes()?;

        // Size = header size + sum of element sizes
        let total_size = 24 + public_exp.len() + modulus.len() + primes.0.len() + primes.1.len();

        let mut buffer = vec![0u8; total_size];

        // Populate header fields
        // Use native endianness
        buffer[0..4].copy_from_slice(&BCRYPT_RSAKEY_BLOB_MAGIC.to_ne_bytes());
        buffer[4..8].copy_from_slice(&bit_length.to_ne_bytes());
        buffer[8..12].copy_from_slice(&(public_exp.len() as u32).to_ne_bytes());
        buffer[12..16].copy_from_slice(&(modulus.len() as u32).to_ne_bytes());
        buffer[16..20].copy_from_slice(&(primes.0.len() as u32).to_ne_bytes());
        buffer[20..24].copy_from_slice(&(primes.1.len() as u32).to_ne_bytes());

        // Populate data
        // Assume big endianness
        let mut idx = 24;
        buffer[idx..idx + public_exp.len()].copy_from_slice(&public_exp);
        idx += public_exp.len();
        buffer[idx..idx + modulus.len()].copy_from_slice(&modulus);
        idx += modulus.len();
        buffer[idx..idx + primes.0.len()].copy_from_slice(&primes.0);
        idx += primes.0.len();
        buffer[idx..idx + primes.1.len()].copy_from_slice(&primes.1);

        Ok(buffer)
    }

    fn deserialize(blob: &[u8], expected_type: Kind) -> Result<RsaPrivateKey, ManticoreError> {
        const ERR: ManticoreError = ManticoreError::RsaFromDerError;

        // Parse u32 from 4 bytes
        fn parse_u32(data: &[u8]) -> Result<u32, ManticoreError> {
            // Assume native endianness
            Ok(u32::from_ne_bytes(data.try_into().map_err(|_| ERR)?))
        }

        let size = blob.len();
        if size <= 24 {
            tracing::debug!(err = ?ERR, size, "header size mismatch");
            Err(ERR)?
        }

        // Check magic
        let actual_magic = parse_u32(&blob[..4])?;
        if actual_magic != BCRYPT_RSAKEY_BLOB_MAGIC {
            tracing::debug!(err = ?ERR, actual_magic, "magic mismatch");
            Err(ERR)?
        }

        // Extract header
        let bit_length = parse_u32(&blob[4..8])?;

        // Check expected type
        match (bit_length, expected_type) {
            (2048, Kind::Rsa2kPrivate | Kind::Rsa2kPrivateCrt)
            | (3072, Kind::Rsa3kPrivate | Kind::Rsa3kPrivateCrt)
            | (4096, Kind::Rsa4kPrivate | Kind::Rsa4kPrivateCrt) => {}
            _ => {
                tracing::debug!(err = ?ERR, bit_length, ?expected_type, "type mismatch");
                Err(ManticoreError::DerAndKeyTypeMismatch)?
            }
        }

        let len_public_exp = parse_u32(&blob[8..12])?;
        let len_modulus = parse_u32(&blob[12..16])?;
        let len_prime1 = parse_u32(&blob[16..20])?;
        let len_prime2 = parse_u32(&blob[20..24])?;

        let expected_size = 24 + len_public_exp + len_modulus + len_prime1 + len_prime2;
        if (expected_size as usize) != size {
            tracing::debug!(err = ?ERR, expected_size, size, "data size mismatch");
            Err(ERR)?
        }

        // Extract data
        let idx = 24;
        let public_exp = &blob[idx..idx + len_public_exp as usize];
        let idx = idx + len_public_exp as usize;

        let modulus = &blob[idx..idx + len_modulus as usize];
        let idx = idx + len_modulus as usize;

        let prime1 = &blob[idx..idx + len_prime1 as usize];
        let idx = idx + len_prime1 as usize;

        let prime2 = &blob[idx..idx + len_prime2 as usize];

        RsaPrivateKey::create_key(public_exp, modulus, prime1, prime2, expected_type)
    }
}

#[cfg(feature = "use-symcrypt")]
impl Clone for RsaPublicKey {
    fn clone(&self) -> Self {
        // Export the public key components
        let blob = self
            .handle
            .export_public_key_blob()
            .expect("Failed to export public key blob for cloning");

        // Recreate the public key from components
        let cloned_key = RsaKey::set_public_key(
            &blob.modulus,
            &blob.pub_exp,
            self.handle.get_rsa_key_usage(),
        )
        .expect("Failed to recreate public key for cloning");

        RsaPublicKey {
            handle: cloned_key,
            size: self.size,
        }
    }
}

// For OpenSSL, the existing Clone derive should work since PKey implements Clone
#[cfg(feature = "use-openssl")]
impl Clone for RsaPrivateKey {
    fn clone(&self) -> Self {
        RsaPrivateKey {
            handle: self.handle.clone(),
            size: self.size,
        }
    }
}

#[cfg(feature = "use-openssl")]
impl Clone for RsaPublicKey {
    fn clone(&self) -> Self {
        RsaPublicKey {
            handle: self.handle.clone(),
            size: self.size,
        }
    }
}

#[cfg(feature = "use-openssl")]
impl RsaOp<RsaPrivateKey> for RsaPrivateKey {
    /// Deserialize an RSA private key from a DER-encoded PKCS#8 format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<RsaPrivateKey, ManticoreError> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaFromDerError
        })?;

        let key_size = pkey.bits().try_into()?;
        match expected_type {
            Some(Kind::Rsa2kPrivate) | Some(Kind::Rsa2kPrivateCrt) => {
                if key_size != RsaKeySize::Rsa2048 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa3kPrivate) | Some(Kind::Rsa3kPrivateCrt) => {
                if key_size != RsaKeySize::Rsa3072 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa4kPrivate) | Some(Kind::Rsa4kPrivateCrt) => {
                if key_size != RsaKeySize::Rsa4096 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            None => {
                // Key size has been validated during `RsaKeySize` conversion.
                // Do nothing here.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPrivateKey {
            handle: pkey,
            size: key_size,
        })
    }

    /// Serialize the RSA private key to a DER-encoded PKCS#8 format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let der = self
            .handle
            .as_ref()
            .private_key_to_pkcs8()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaToDerError
            })?;

        Ok(der)
    }

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, ManticoreError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetModulusError
        })?;
        let modulus = rsa.n().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetModulusError
        })?;

        Ok(modulus.to_vec())
    }

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, ManticoreError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetPublicExponentError
        })?;
        let public_exponent = rsa.e().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetPublicExponentError
        })?;

        Ok(public_exponent.to_vec())
    }

    /// Get Key Size
    fn size(&self) -> RsaKeySize {
        self.size
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaOp<RsaPrivateKey> for RsaPrivateKey {
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<RsaPrivateKey, ManticoreError> {
        use pkcs1::der::Decode;

        let private_key_info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaFromDerError
        })?;

        let private_key = pkcs1::RsaPrivateKey::from_der(private_key_info.private_key).map_err(
            |error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaFromDerError
            },
        )?;

        let symcrypt_key = RsaKey::set_key_pair(
            private_key.modulus.as_bytes(),
            private_key.public_exponent.as_bytes(),
            private_key.prime1.as_bytes(),
            private_key.prime2.as_bytes(),
            RsaKeyUsage::SignAndEncrypt,
        )
        .map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaFromDerError
        })?;

        match expected_type {
            Some(Kind::Rsa2kPrivate) | Some(Kind::Rsa2kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 256 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa3kPrivate) | Some(Kind::Rsa3kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 384 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa4kPrivate) | Some(Kind::Rsa4kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 512 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }
        let key_size = match symcrypt_key.get_size_of_modulus() {
            256 => RsaKeySize::Rsa2048,
            384 => RsaKeySize::Rsa3072,
            512 => RsaKeySize::Rsa4096,
            _ => Err(ManticoreError::RsaInvalidKeyLength)?,
        };

        Ok(RsaPrivateKey {
            handle: symcrypt_key,
            size: key_size,
        })
    }

    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use pkcs1::der::Encode;

        let private_key_blob =
            self.handle
                .export_key_pair_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaToDerError
                })?;

        let modulus = pkcs1::UintRef::new(&private_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&private_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let private_exponent =
            pkcs1::UintRef::new(&private_key_blob.private_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let prime1 = pkcs1::UintRef::new(&private_key_blob.p).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let prime2 = pkcs1::UintRef::new(&private_key_blob.q).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let exponent1 = pkcs1::UintRef::new(&private_key_blob.d_p).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let exponent2 = pkcs1::UintRef::new(&private_key_blob.d_q).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let coefficient =
            pkcs1::UintRef::new(&private_key_blob.crt_coefficient).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let private_key = pkcs1::RsaPrivateKey {
            modulus,
            public_exponent,
            private_exponent,
            prime1,
            prime2,
            exponent1,
            exponent2,
            coefficient,
            other_prime_infos: None,
        };

        let private_key_der = private_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        let null_param: pkcs8::der::AnyRef<'_> = pkcs8::der::asn1::Null.into(); // This creates a DER-encoded NULL
        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: Some(null_param),
        };

        let private_key_info = pkcs8::PrivateKeyInfo::new(alg_id, &private_key_der);
        let der = private_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        Ok(der)
    }

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, ManticoreError> {
        let blob = self
            .handle
            .export_key_pair_blob()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::RsaGetModulusError
            })?;
        Ok(blob.modulus)
    }

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, ManticoreError> {
        let blob = self
            .handle
            .export_key_pair_blob()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::RsaGetPublicExponentError
            })?;
        Ok(blob.pub_exp)
    }

    fn size(&self) -> RsaKeySize {
        self.size
    }
}

#[cfg(feature = "use-openssl")]
impl RsaPrivateKey {
    /// Export the Prime1 and Prime2 of the RSA Private key
    fn primes(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetPublicExponentError
        })?;
        let prime1 = rsa.p().ok_or(ManticoreError::RsaGetPublicExponentError)?;
        let prime2 = rsa.q().ok_or(ManticoreError::RsaGetPublicExponentError)?;

        Ok((prime1.to_vec(), prime2.to_vec()))
    }

    // Create RSA Private key using OpenSSL
    // All numbers assume big endian
    fn create_key(
        public_exp: &[u8],
        modulus: &[u8],
        prime1: &[u8],
        prime2: &[u8],
        expected_type: Kind,
    ) -> Result<Self, ManticoreError> {
        fn wrapper(
            public_exp: &[u8],
            modulus: &[u8],
            prime1: &[u8],
            prime2: &[u8],
        ) -> Result<PKey<Private>, openssl::error::ErrorStack> {
            let public_exp = BigNum::from_slice(public_exp)?;
            let modulus = BigNum::from_slice(modulus)?;
            let p = BigNum::from_slice(prime1)?;
            let q = BigNum::from_slice(prime2)?;

            // Compute private exponent d
            // d = e^(-1) mod ((p-1)*(q-1))
            let d = {
                let mut ctx = openssl::bn::BigNumContext::new()?;
                let one = BigNum::from_u32(1)?;

                let mut p1 = BigNum::new()?;
                p1.checked_sub(&p, &one)?;

                let mut p2 = BigNum::new()?;
                p2.checked_sub(&q, &one)?;

                let mut phi = BigNum::new()?;
                phi.checked_mul(&p1, &p2, &mut ctx)?;

                let mut d = BigNum::new()?;
                d.mod_inverse(&public_exp, &phi, &mut ctx)?;

                d
            };

            let rsa_key = RsaPrivateKeyBuilder::new(modulus, public_exp, d)?
                .set_factors(p, q)?
                .build();

            let pkey = PKey::from_rsa(rsa_key)?;
            Ok(pkey)
        }

        let pkey = wrapper(public_exp, modulus, prime1, prime2).map_err(|error| {
            tracing::error!(
                ?error,
                "Failed to create RsaPrivateKey from raw components."
            );
            ManticoreError::RsaFromDerError
        })?;

        let key_size = pkey.bits().try_into()?;
        match expected_type {
            Kind::Rsa2kPrivate | Kind::Rsa2kPrivateCrt => {
                if key_size != RsaKeySize::Rsa2048 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Kind::Rsa3kPrivate | Kind::Rsa3kPrivateCrt => {
                if key_size != RsaKeySize::Rsa3072 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Kind::Rsa4kPrivate | Kind::Rsa4kPrivateCrt => {
                if key_size != RsaKeySize::Rsa4096 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPrivateKey {
            handle: pkey,
            size: key_size,
        })
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaPrivateKey {
    /// Export the Prime1 and Prime2 of the RSA Private key
    fn primes(&self) -> Result<(Vec<u8>, Vec<u8>), ManticoreError> {
        let blob = self
            .handle
            .export_key_pair_blob()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::RsaGetPublicExponentError
            })?;
        Ok((blob.p, blob.q))
    }

    fn create_key(
        public_exp: &[u8],
        modulus: &[u8],
        prime1: &[u8],
        prime2: &[u8],
        expected_type: Kind,
    ) -> Result<Self, ManticoreError> {
        // Assume big endian
        let symcrypt_key = RsaKey::set_key_pair(
            modulus,
            public_exp,
            prime1,
            prime2,
            RsaKeyUsage::SignAndEncrypt,
        )
        .map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaFromDerError
        })?;

        match expected_type {
            Kind::Rsa2kPrivate | Kind::Rsa2kPrivateCrt => {
                if symcrypt_key.get_size_of_modulus() != 256 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Kind::Rsa3kPrivate | Kind::Rsa3kPrivateCrt => {
                if symcrypt_key.get_size_of_modulus() != 384 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Kind::Rsa4kPrivate | Kind::Rsa4kPrivateCrt => {
                if symcrypt_key.get_size_of_modulus() != 512 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }
        let key_size = match symcrypt_key.get_size_of_modulus() {
            256 => RsaKeySize::Rsa2048,
            384 => RsaKeySize::Rsa3072,
            512 => RsaKeySize::Rsa4096,
            _ => Err(ManticoreError::RsaInvalidKeyLength)?,
        };

        Ok(RsaPrivateKey {
            handle: symcrypt_key,
            size: key_size,
        })
    }
}

#[cfg(feature = "use-openssl")]
impl RsaPrivateOp for RsaPrivateKey {
    // Private key operation (modular exponentiation)
    fn operate(&self, data: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        self.decrypt(data, RsaCryptoPadding::None, None)
    }

    // Decryption
    fn decrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        let padding = match padding {
            RsaCryptoPadding::None => openssl::rsa::Padding::NONE,
            RsaCryptoPadding::Oaep => openssl::rsa::Padding::PKCS1_OAEP,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaDecryptError
        })?;

        ctx.decrypt_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaDecryptError
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaDecryptError
            })?;

        if padding == openssl::rsa::Padding::PKCS1_OAEP {
            let algo = match hash_algorithm.unwrap_or(HashAlgorithm::Sha256) {
                HashAlgorithm::Sha1 => Md::sha1(),
                HashAlgorithm::Sha256 => Md::sha256(),
                HashAlgorithm::Sha384 => Md::sha384(),
                HashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_rsa_oaep_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaDecryptError
            })?;
        }

        let buffer_len = ctx.decrypt(data, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaDecryptError
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let decrypted_len =
            ctx.decrypt(data, Some(&mut buffer))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::RsaDecryptError
                })?;

        let buffer = &buffer[..decrypted_len];

        Ok(buffer.to_vec())
    }

    // Sign
    #[cfg(test)]
    fn sign(
        &self,
        digest: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, ManticoreError> {
        let padding = match padding {
            RsaSignaturePadding::None => openssl::rsa::Padding::NONE,
            RsaSignaturePadding::Pss => openssl::rsa::Padding::PKCS1_PSS,
            RsaSignaturePadding::Pkcs1_5 => openssl::rsa::Padding::PKCS1,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaSignError
        })?;

        ctx.sign_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaSignError
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaSignError
            })?;

        if let Some(salt_len) = salt_len {
            ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len.into()))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::RsaSignError
                })?;
        }

        if let Some(algo) = hash_algorithm {
            let algo = match algo {
                HashAlgorithm::Sha1 => Md::sha1(),
                HashAlgorithm::Sha256 => Md::sha256(),
                HashAlgorithm::Sha384 => Md::sha384(),
                HashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_signature_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaSignError
            })?;
        }

        let buffer_len = ctx.sign(digest, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaSignError
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let signature_len = ctx
            .sign(digest, Some(&mut buffer))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaSignError
            })?;

        let buffer = &buffer[..signature_len];

        Ok(buffer.to_vec())
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError> {
        self.handle
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaToDerError
            })
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaPrivateOp for RsaPrivateKey {
    fn operate(&self, data: &[u8]) -> Result<Vec<u8>, ManticoreError> {
        self.decrypt(data, RsaCryptoPadding::None, None)
    }

    fn decrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        match padding {
            RsaCryptoPadding::None => {
                let private_key = create_rsa_private_key_from_symcrypt(&self.handle).map_err(
                    |symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        ManticoreError::RsaDecryptError
                    },
                )?;
                let mut rng = OsRng;
                let plaintext =
                    rsa_decrypt(Some(&mut rng), &private_key, &BigUint::from_bytes_be(data))
                        .map_err(|symcrypt_error_stack| {
                            tracing::error!(?symcrypt_error_stack);
                            ManticoreError::RsaDecryptError
                        })?;

                let buffer_len = match self.size {
                    RsaKeySize::Rsa2048 => 256,
                    RsaKeySize::Rsa3072 => 384,
                    RsaKeySize::Rsa4096 => 512,
                };

                let mut buffer = vec![0; buffer_len];
                let plaintext = plaintext.to_bytes_be();
                let start = buffer.len().saturating_sub(plaintext.len());
                buffer[start..].copy_from_slice(&plaintext);
                Ok(buffer)
            }
            RsaCryptoPadding::Oaep => {
                let hash_algo = match hash_algorithm.unwrap_or(HashAlgorithm::Sha256) {
                    HashAlgorithm::Sha1 => SymcryptHashAlgorithm::Sha1,
                    HashAlgorithm::Sha256 => SymcryptHashAlgorithm::Sha256,
                    HashAlgorithm::Sha384 => SymcryptHashAlgorithm::Sha384,
                    HashAlgorithm::Sha512 => SymcryptHashAlgorithm::Sha512,
                };
                let label_param = b""; // Empty label for OAEP
                let message = self
                    .handle
                    .oaep_decrypt(data, hash_algo, label_param)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        ManticoreError::RsaDecryptError
                    })?;
                Ok(message)
            }
        }
    }

    #[cfg(test)]
    fn sign(
        &self,
        digest: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, ManticoreError> {
        let hash_algo = match hash_algorithm {
            Some(HashAlgorithm::Sha1) => SymcryptHashAlgorithm::Sha1,
            Some(HashAlgorithm::Sha256) => SymcryptHashAlgorithm::Sha256,
            Some(HashAlgorithm::Sha384) => SymcryptHashAlgorithm::Sha384,
            Some(HashAlgorithm::Sha512) => SymcryptHashAlgorithm::Sha512,
            None => match digest.len() {
                20 => SymcryptHashAlgorithm::Sha1,
                32 => SymcryptHashAlgorithm::Sha256,
                48 => SymcryptHashAlgorithm::Sha384,
                64 => SymcryptHashAlgorithm::Sha512,
                _ => return Err(ManticoreError::RsaSignError),
            },
        };
        match padding {
            RsaSignaturePadding::None => {
                let key_blob =
                    self.handle
                        .export_key_pair_blob()
                        .map_err(|symcrypt_error_stack| {
                            tracing::error!(?symcrypt_error_stack);
                            ManticoreError::RsaSignError
                        })?;

                // Convert to BigUint for mathematical operations
                let digest_int = BigUint::from_bytes_be(digest);
                let private_exp_int = BigUint::from_bytes_be(&key_blob.private_exp); // Changed from key_blob.d
                let modulus_int = BigUint::from_bytes_be(&key_blob.modulus);

                // Perform RSA signature: signature = digest^d mod n
                let signature_int = digest_int.modpow(&private_exp_int, &modulus_int);

                // Convert back to bytes with proper padding
                let signature_bytes = signature_int.to_bytes_be();

                // Ensure the signature has the correct length (same as modulus size)
                let modulus_size = key_blob.modulus.len();
                let mut padded_signature = vec![0u8; modulus_size];
                let start = modulus_size.saturating_sub(signature_bytes.len());
                padded_signature[start..].copy_from_slice(&signature_bytes);

                Ok(padded_signature)
            }
            RsaSignaturePadding::Pss => {
                let salt_len = salt_len.unwrap_or(digest.len() as u16);
                let signature = self
                    .handle
                    .pss_sign(digest, hash_algo, salt_len as usize)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        ManticoreError::RsaSignError
                    })?;
                Ok(signature)
            }
            RsaSignaturePadding::Pkcs1_5 => {
                let signature =
                    self.handle
                        .pkcs1_sign(digest, hash_algo)
                        .map_err(|symcrypt_error_stack| {
                            tracing::error!(?symcrypt_error_stack);
                            ManticoreError::RsaSignError
                        })?;
                Ok(signature)
            }
        }
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use pkcs1::der::Encode;

        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaToDerError
                })?;

        let modulus = pkcs1::UintRef::new(&public_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&public_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;

        let public_key = pkcs1::RsaPublicKey {
            modulus,
            public_exponent,
        };
        let public_key_der = public_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: Some(pkcs8::der::asn1::Null.into()),
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = subject_public_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        Ok(der)
    }
}

#[cfg(feature = "use-openssl")]
impl RsaOp<RsaPublicKey> for RsaPublicKey {
    /// Deserialize an RSA public key from a DER-encoded SubjectPublicKeyInfo format.
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<RsaPublicKey, ManticoreError> {
        let rsa = openssl::rsa::Rsa::public_key_from_der(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaFromDerError
        })?;
        let pkey = openssl::pkey::PKey::from_rsa(rsa).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaFromDerError
        })?;

        let key_size = pkey.bits().try_into()?;
        match expected_type {
            Some(Kind::Rsa2kPublic) => {
                if key_size != RsaKeySize::Rsa2048 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa3kPublic) => {
                if key_size != RsaKeySize::Rsa3072 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            Some(Kind::Rsa4kPublic) => {
                if key_size != RsaKeySize::Rsa4096 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
            }
            None => {
                // Key size has been validated during `RsaKeySize` conversion.
                // Do nothing here.
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPublicKey {
            handle: pkey,
            size: key_size,
        })
    }

    /// Serialize the RSA public key to a DER-encoded SubjectPublicKeyInfo format.
    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        let der = self
            .handle
            .as_ref()
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaToDerError
            })?;

        Ok(der)
    }

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, ManticoreError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetModulusError
        })?;
        let modulus = rsa.n().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetModulusError
        })?;

        Ok(modulus.to_vec())
    }

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, ManticoreError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetPublicExponentError
        })?;
        let public_exponent = rsa.e().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaGetPublicExponentError
        })?;

        Ok(public_exponent.to_vec())
    }

    /// Get Key Size
    fn size(&self) -> RsaKeySize {
        self.size
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaOp<RsaPublicKey> for RsaPublicKey {
    fn from_der(der: &[u8], expected_type: Option<Kind>) -> Result<RsaPublicKey, ManticoreError> {
        use pkcs1::der::Decode;

        let public_key_info =
            spki::SubjectPublicKeyInfoRef::from_der(der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaFromDerError
            })?;
        let public_key_der = public_key_info.subject_public_key;

        let public_key =
            pkcs1::RsaPublicKey::from_der(public_key_der.raw_bytes()).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaFromDerError
            })?;

        let modulus = public_key.modulus.as_bytes();
        let exponent = public_key.public_exponent.as_bytes();

        let symcrypt_key = RsaKey::set_public_key(modulus, exponent, RsaKeyUsage::SignAndEncrypt)
            .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            ManticoreError::RsaFromDerError
        })?;

        let expected_type = match expected_type {
            Some(unwrapped_type) => unwrapped_type,
            None => match symcrypt_key.get_size_of_modulus() {
                256 => Kind::Rsa2kPublic,
                384 => Kind::Rsa3kPublic,
                512 => Kind::Rsa4kPublic,
                _ => return Err(ManticoreError::RsaFromDerError),
            },
        };

        let mut key_size = RsaKeySize::Rsa2048; // Default to 2048 bits

        match expected_type {
            Kind::Rsa2kPublic => {
                if symcrypt_key.get_size_of_modulus() != 256 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
                key_size = RsaKeySize::Rsa2048;
            }
            Kind::Rsa3kPublic => {
                if symcrypt_key.get_size_of_modulus() != 384 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
                key_size = RsaKeySize::Rsa3072;
            }
            Kind::Rsa4kPublic => {
                if symcrypt_key.get_size_of_modulus() != 512 {
                    Err(ManticoreError::DerAndKeyTypeMismatch)?
                }
                key_size = RsaKeySize::Rsa4096;
            }
            _ => Err(ManticoreError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPublicKey {
            handle: symcrypt_key,
            size: key_size,
        })
    }

    fn to_der(&self) -> Result<Vec<u8>, ManticoreError> {
        use pkcs1::der::Encode;

        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaToDerError
                })?;
        let modulus = pkcs1::UintRef::new(&public_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&public_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let public_key = pkcs1::RsaPublicKey {
            modulus,
            public_exponent,
        };
        let public_key_der = public_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: Some(pkcs8::der::asn1::Null.into()),
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                ManticoreError::RsaToDerError
            })?;
        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = subject_public_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            ManticoreError::RsaToDerError
        })?;

        Ok(der)
    }

    fn modulus(&self) -> Result<Vec<u8>, ManticoreError> {
        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaToDerError
                })?;
        Ok(public_key_blob.modulus)
    }

    fn public_exponent(&self) -> Result<Vec<u8>, ManticoreError> {
        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaToDerError
                })?;
        Ok(public_key_blob.pub_exp)
    }

    fn size(&self) -> RsaKeySize {
        self.size
    }
}

#[cfg(feature = "use-openssl")]
impl RsaPublicOp for RsaPublicKey {
    // Encryption
    fn encrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        let padding = match padding {
            RsaCryptoPadding::None => openssl::rsa::Padding::NONE,
            RsaCryptoPadding::Oaep => openssl::rsa::Padding::PKCS1_OAEP,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaEncryptError
        })?;

        ctx.encrypt_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaEncryptError
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaEncryptError
            })?;

        if padding == openssl::rsa::Padding::PKCS1_OAEP {
            // If a hash algorithm was provided, set the OAEP algorithm
            let algo = match hash_algorithm.unwrap_or(HashAlgorithm::Sha256) {
                // Allow Sha-1 for tests
                HashAlgorithm::Sha1 => Md::sha1(),
                HashAlgorithm::Sha256 => Md::sha256(),
                HashAlgorithm::Sha384 => Md::sha384(),
                HashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_rsa_oaep_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaEncryptError
            })?;
        }

        let buffer_len = ctx.encrypt(data, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaEncryptError
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let encrypted_len =
            ctx.encrypt(data, Some(&mut buffer))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::RsaEncryptError
                })?;

        let buffer = &buffer[..encrypted_len];

        Ok(buffer.to_vec())
    }

    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), ManticoreError> {
        let padding = match padding {
            RsaSignaturePadding::None => openssl::rsa::Padding::NONE,
            RsaSignaturePadding::Pss => openssl::rsa::Padding::PKCS1_PSS,
            RsaSignaturePadding::Pkcs1_5 => openssl::rsa::Padding::PKCS1,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaVerifyError
        })?;

        ctx.verify_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::RsaVerifyError
        })?;
        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaVerifyError
            })?;

        if let Some(salt_len) = salt_len {
            ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len.into()))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    ManticoreError::RsaVerifyError
                })?;
        }

        if let Some(algo) = hash_algorithm {
            let algo = match algo {
                HashAlgorithm::Sha1 => Md::sha1(),
                HashAlgorithm::Sha256 => Md::sha256(),
                HashAlgorithm::Sha384 => Md::sha384(),
                HashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_signature_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaVerifyError
            })?;
        }

        let result = ctx
            .verify(digest, signature)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::RsaVerifyError
            })?;

        // Return error on verification failure
        if !result {
            Err(ManticoreError::RsaVerifyError)?
        }

        Ok(())
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaPublicOp for RsaPublicKey {
    fn encrypt(
        &self,
        data: &[u8],
        padding: RsaCryptoPadding,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> Result<Vec<u8>, ManticoreError> {
        match padding {
            RsaCryptoPadding::None => {
                let rsa_pub_key: rsa::RsaPublicKey = create_rsa_public_key_from_symcrypt(
                    &self.handle,
                )
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    ManticoreError::RsaEncryptError
                })?;
                let ciphertext = rsa_encrypt(&rsa_pub_key, &BigUint::from_bytes_be(data)).map_err(
                    |symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        ManticoreError::RsaEncryptError
                    },
                )?;
                Ok(ciphertext.to_bytes_be())
            }
            RsaCryptoPadding::Oaep => {
                let hash_algo = match hash_algorithm.unwrap_or(HashAlgorithm::Sha256) {
                    HashAlgorithm::Sha1 => SymcryptHashAlgorithm::Sha1,
                    HashAlgorithm::Sha256 => SymcryptHashAlgorithm::Sha256,
                    HashAlgorithm::Sha384 => SymcryptHashAlgorithm::Sha384,
                    HashAlgorithm::Sha512 => SymcryptHashAlgorithm::Sha512,
                };
                let label_param = b"";
                let ciphertext = self
                    .handle
                    .oaep_encrypt(data, hash_algo, label_param)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        ManticoreError::RsaEncryptError
                    })?;
                Ok(ciphertext)
            }
        }
    }

    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: RsaSignaturePadding,
        hash_algorithm: Option<HashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), ManticoreError> {
        let hash_algo = match hash_algorithm {
            Some(HashAlgorithm::Sha1) => SymcryptHashAlgorithm::Sha1,
            Some(HashAlgorithm::Sha256) => SymcryptHashAlgorithm::Sha256,
            Some(HashAlgorithm::Sha384) => SymcryptHashAlgorithm::Sha384,
            Some(HashAlgorithm::Sha512) => SymcryptHashAlgorithm::Sha512,
            None => match digest.len() {
                20 => SymcryptHashAlgorithm::Sha1,
                32 => SymcryptHashAlgorithm::Sha256,
                48 => SymcryptHashAlgorithm::Sha384,
                64 => SymcryptHashAlgorithm::Sha512,
                _ => return Err(ManticoreError::RsaVerifyError),
            },
        };
        match padding {
            RsaSignaturePadding::Pkcs1_5 => {
                let result = self.handle.pkcs1_verify(digest, signature, hash_algo);
                if result.is_err() {
                    Err(ManticoreError::RsaVerifyError)?
                }
            }
            RsaSignaturePadding::Pss => {
                let salt_len = salt_len.unwrap_or(digest.len() as u16);
                let result =
                    self.handle
                        .pss_verify(digest, signature, hash_algo, salt_len as usize);
                if result.is_err() {
                    return Err(ManticoreError::RsaVerifyError);
                }
            }
            RsaSignaturePadding::None => {
                let digest_biguint = BigUint::from_bytes_be(digest);
                let key_blob =
                    self.handle
                        .export_public_key_blob()
                        .map_err(|symcrypt_error_stack| {
                            tracing::error!(?symcrypt_error_stack);
                            ManticoreError::RsaVerifyError
                        })?;
                // Convert to BigUint
                let e = BigUint::from_bytes_be(&key_blob.pub_exp);
                let n = BigUint::from_bytes_be(&key_blob.modulus);
                let signature_biguint = BigUint::from_bytes_be(signature);
                let decrypted_digest = signature_biguint.modpow(&e, &n);
                if decrypted_digest != digest_biguint {
                    return Err(ManticoreError::RsaVerifyError);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::*;

    #[test]
    fn test_rsa_private_der() {
        let data = [1u8; 256];

        // Generate the key
        let keypair = generate_rsa(2048);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        // Encrypt data with the key
        let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Convert the key to der
        let result = rsa_private.to_der();
        assert!(result.is_ok());

        // Convert the der back to key
        let result = RsaPrivateKey::from_der(&result.unwrap(), Some(Kind::Rsa2kPrivate));
        assert!(result.is_ok());
        let rsa_private = result.unwrap();

        // Decrypt data with the key
        let result = rsa_private.decrypt(&encrypted, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let decrypted = result.unwrap();

        assert_eq!(data.to_vec(), decrypted);

        // Test from_der with rsa public key
        let result = rsa_public.to_der();
        assert!(result.is_ok());

        let result = RsaPrivateKey::from_der(&result.unwrap(), Some(Kind::Rsa2kPrivate));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::RsaFromDerError);
        }

        // Test from_der with PKCS1 format
        const DER_PKCS1: [u8; 1193] = [
            0x30, 0x82, 0x04, 0xa5, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdd, 0xaa,
            0xfb, 0x74, 0xca, 0xbe, 0x1f, 0x4d, 0x83, 0x75, 0x8a, 0xd3, 0xda, 0x11, 0x8a, 0xfb,
            0x9e, 0xd5, 0x56, 0x66, 0xc1, 0x3c, 0x0a, 0x4b, 0xbf, 0x39, 0xb0, 0x67, 0xb7, 0xca,
            0x2d, 0x7a, 0xb7, 0x0d, 0x53, 0x1c, 0x94, 0xe7, 0x8f, 0xec, 0xc6, 0xc4, 0xee, 0x66,
            0x45, 0x39, 0x3c, 0x95, 0x51, 0x12, 0x9c, 0xf3, 0xb5, 0x92, 0x63, 0x1a, 0x54, 0xc0,
            0x5f, 0xb7, 0xaa, 0x42, 0x7b, 0x7d, 0xfb, 0x1b, 0x94, 0xff, 0xae, 0x16, 0x57, 0xde,
            0xd4, 0x65, 0xc8, 0xd7, 0x73, 0x94, 0xed, 0xc6, 0x1b, 0x62, 0x73, 0xfa, 0xba, 0x00,
            0x34, 0xc1, 0x4d, 0xac, 0x1c, 0xab, 0x7e, 0xbd, 0x79, 0x7f, 0x5b, 0xf3, 0x03, 0x97,
            0x6a, 0x5c, 0x9e, 0x80, 0xb8, 0x48, 0x71, 0xbd, 0xb6, 0x34, 0x3c, 0xc7, 0xe0, 0xf7,
            0x79, 0x2c, 0x80, 0x90, 0xc1, 0x6e, 0x46, 0xd7, 0x01, 0x32, 0x5e, 0x7f, 0x88, 0xcb,
            0x73, 0x11, 0x82, 0x18, 0x2b, 0xd5, 0xcc, 0x1c, 0x20, 0x76, 0xaf, 0x7e, 0x39, 0xdc,
            0x3f, 0x73, 0x67, 0xa1, 0x0e, 0x09, 0xce, 0x17, 0x1a, 0x65, 0xe6, 0x38, 0x7f, 0x17,
            0xe9, 0xef, 0xfe, 0xa9, 0x3a, 0xf0, 0xec, 0x1c, 0x8f, 0xaf, 0xa7, 0xcd, 0x3b, 0xd5,
            0xec, 0xbd, 0x3c, 0xae, 0xd7, 0x9e, 0xb3, 0xcc, 0x78, 0xf9, 0x89, 0x27, 0x64, 0x0a,
            0xbd, 0x79, 0x30, 0xfa, 0x29, 0xe7, 0x2f, 0xe2, 0x10, 0x4a, 0x3f, 0xe6, 0xc8, 0xf5,
            0xfb, 0x66, 0x65, 0x68, 0x4d, 0x5d, 0xe5, 0x76, 0x30, 0xf5, 0x85, 0xef, 0x6d, 0xa5,
            0xa3, 0x55, 0xd4, 0x79, 0x25, 0x21, 0xfb, 0xb9, 0xc8, 0xfe, 0x44, 0x45, 0x79, 0xb9,
            0x32, 0xf3, 0x49, 0x6a, 0x84, 0x5b, 0x49, 0xe5, 0x4e, 0xd5, 0xaf, 0x7c, 0x8a, 0xef,
            0x39, 0x7a, 0x82, 0xe4, 0x42, 0x79, 0xf0, 0x9c, 0xd9, 0x90, 0x2f, 0x5a, 0x43, 0x98,
            0xf7, 0x29, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x05, 0x77, 0x2f,
            0x63, 0x37, 0x92, 0xdd, 0x02, 0xe4, 0x59, 0xd1, 0x58, 0xbc, 0x66, 0x2a, 0xd5, 0xb3,
            0x45, 0x4c, 0xda, 0x54, 0x96, 0x3b, 0xa5, 0xc1, 0xa5, 0xb5, 0x3f, 0x0a, 0xc5, 0xd2,
            0x28, 0x6b, 0x5b, 0x89, 0x7f, 0xfe, 0xa9, 0x95, 0x54, 0xfa, 0xa8, 0xaf, 0xe7, 0xcc,
            0x79, 0xfc, 0x65, 0x02, 0x73, 0xa6, 0xf4, 0x39, 0x0c, 0x4e, 0x8e, 0x6a, 0x11, 0x0d,
            0x3b, 0x22, 0x2d, 0xa8, 0xa3, 0x02, 0xfe, 0x46, 0x31, 0x50, 0xb4, 0x4d, 0xd4, 0x84,
            0x20, 0x57, 0x5a, 0xfd, 0x47, 0x55, 0x33, 0xde, 0xdd, 0xd1, 0xab, 0x6e, 0x0b, 0x23,
            0xc1, 0xdc, 0x13, 0x01, 0x3e, 0x4c, 0x43, 0x75, 0x3b, 0xb4, 0x98, 0xc7, 0x19, 0xa4,
            0x69, 0x26, 0x0d, 0x03, 0xf3, 0x8b, 0x54, 0x68, 0xbf, 0x47, 0x26, 0xb6, 0xda, 0x10,
            0x93, 0x8e, 0x3e, 0xf8, 0xcf, 0x54, 0x86, 0xa8, 0x1e, 0xfb, 0x11, 0x57, 0x73, 0x80,
            0x57, 0xbc, 0xc5, 0x0e, 0x1c, 0x09, 0x5e, 0x36, 0x8b, 0x2d, 0x9b, 0xb7, 0x93, 0xa5,
            0xea, 0xe2, 0x32, 0x32, 0x41, 0x29, 0xd2, 0x0c, 0xb6, 0x7b, 0x9d, 0xf0, 0x4e, 0x0c,
            0xc2, 0xce, 0x0b, 0x72, 0xb3, 0x4e, 0x1b, 0xe0, 0xdd, 0x76, 0xea, 0x33, 0xae, 0x3a,
            0x4f, 0xfd, 0x23, 0x32, 0x15, 0xdf, 0xb8, 0x1b, 0xf9, 0x84, 0xc1, 0x59, 0xd1, 0x76,
            0x3c, 0x9d, 0xc2, 0x41, 0x3b, 0x66, 0xc0, 0x9e, 0xab, 0x78, 0x57, 0x95, 0x96, 0x31,
            0xc7, 0xd5, 0x58, 0x77, 0x20, 0x43, 0x95, 0xcc, 0x1b, 0x8a, 0x45, 0x54, 0x60, 0x9d,
            0x73, 0xf8, 0xf2, 0xb1, 0x7f, 0x18, 0x9b, 0x22, 0x81, 0x2d, 0x24, 0x77, 0x27, 0x4a,
            0xae, 0x7d, 0x15, 0x47, 0xad, 0x3d, 0x1a, 0xd9, 0x67, 0xc1, 0x54, 0x3f, 0x53, 0xed,
            0x35, 0x8d, 0xbe, 0x2c, 0xf9, 0x48, 0x93, 0xdc, 0x70, 0x26, 0x85, 0x0e, 0xf1, 0x6b,
            0xe5, 0x02, 0x81, 0x81, 0x00, 0xeb, 0x97, 0x58, 0x1b, 0x77, 0x60, 0x47, 0x4b, 0x98,
            0xb3, 0xa7, 0xdc, 0x93, 0x99, 0x5a, 0x6a, 0xa1, 0xc0, 0x43, 0x06, 0x30, 0xcc, 0x64,
            0xcc, 0xa5, 0xf0, 0x02, 0xc4, 0xa2, 0x06, 0xa9, 0xe4, 0x39, 0xd1, 0xf4, 0x5b, 0xcc,
            0xf6, 0xe8, 0x61, 0x56, 0xb4, 0x6b, 0x5d, 0x8d, 0x1a, 0x1f, 0x21, 0x26, 0xa8, 0xae,
            0xb0, 0x3e, 0x4e, 0xf1, 0x01, 0xef, 0x26, 0xd6, 0x31, 0x17, 0xa5, 0x80, 0x02, 0x99,
            0xac, 0x8d, 0xa6, 0xd2, 0xc0, 0x2a, 0x65, 0xd1, 0xd7, 0xac, 0xa4, 0x25, 0x66, 0xc2,
            0x06, 0x26, 0x79, 0xe8, 0x94, 0xc5, 0x34, 0x54, 0xb3, 0xb1, 0x69, 0x90, 0x5a, 0x5a,
            0xbf, 0xc1, 0xa3, 0xb0, 0x90, 0x4d, 0x55, 0xe6, 0x80, 0xd0, 0x6f, 0x6b, 0xcf, 0x28,
            0x09, 0x40, 0xb2, 0x14, 0x29, 0xaf, 0xe8, 0x42, 0x28, 0x27, 0xe3, 0x1b, 0xc4, 0xd6,
            0x94, 0x66, 0x94, 0xb9, 0x7c, 0xdd, 0xb5, 0x02, 0x81, 0x81, 0x00, 0xf0, 0xde, 0xdd,
            0x40, 0x18, 0x06, 0xf8, 0x03, 0xe9, 0xcd, 0xce, 0x12, 0xf8, 0xf7, 0x7f, 0xba, 0xf4,
            0xa0, 0x7e, 0x70, 0x37, 0x23, 0xfe, 0xee, 0x3b, 0xa2, 0xa0, 0xca, 0x82, 0xcd, 0x5c,
            0x47, 0xf1, 0x4d, 0xf1, 0xbe, 0x4f, 0x26, 0x5b, 0xf5, 0x27, 0x82, 0x2b, 0xe8, 0xc8,
            0x8b, 0x08, 0xe1, 0x2d, 0x9c, 0xdf, 0xe7, 0x74, 0x9c, 0x65, 0x1f, 0x6c, 0xeb, 0x0c,
            0xb7, 0x4d, 0x89, 0x05, 0x16, 0xa5, 0x96, 0x72, 0x4d, 0xcf, 0x09, 0x0b, 0x05, 0x48,
            0x62, 0x92, 0x0f, 0xba, 0x52, 0x26, 0xf1, 0xa2, 0xf1, 0x22, 0x0f, 0x45, 0x4d, 0xc7,
            0xf5, 0xc0, 0xf5, 0x83, 0xe7, 0xb5, 0xe8, 0x7d, 0x39, 0x1c, 0xf0, 0x42, 0x94, 0x16,
            0xff, 0x9a, 0x77, 0x06, 0x5a, 0x16, 0x62, 0x98, 0x45, 0x6a, 0x6d, 0x35, 0xcb, 0x66,
            0x12, 0xc4, 0x5f, 0x96, 0x0b, 0x9d, 0xa4, 0xa5, 0x00, 0x30, 0x4c, 0xbc, 0x25, 0x02,
            0x81, 0x81, 0x00, 0xcc, 0xc9, 0x9a, 0x05, 0x06, 0x17, 0xe2, 0xe1, 0x8b, 0xb3, 0x5f,
            0x4f, 0x15, 0xde, 0x50, 0x02, 0x30, 0xe8, 0x77, 0x5a, 0x82, 0x40, 0xa9, 0xbe, 0x5a,
            0xdf, 0xef, 0x08, 0x0d, 0xef, 0xcc, 0xee, 0x5e, 0x74, 0x6a, 0xfd, 0x01, 0x85, 0xff,
            0x29, 0xdd, 0xbc, 0xa7, 0x37, 0x82, 0xd8, 0x1a, 0x07, 0x2f, 0x1b, 0xa1, 0xfe, 0x01,
            0xab, 0x8d, 0x44, 0x29, 0x26, 0x91, 0x39, 0xcb, 0x5c, 0x49, 0x91, 0xf9, 0x13, 0x4d,
            0x6e, 0x9d, 0xf3, 0xfc, 0xe6, 0xd5, 0x29, 0xad, 0x20, 0x62, 0x82, 0x98, 0x55, 0xd0,
            0x4c, 0x58, 0x28, 0x39, 0xe3, 0xeb, 0x5c, 0xe7, 0xf2, 0xe3, 0x50, 0x27, 0x62, 0x58,
            0x68, 0x79, 0xaa, 0x76, 0x0f, 0x1d, 0x77, 0x0b, 0xb8, 0x4e, 0xf6, 0x9b, 0xce, 0xaf,
            0x36, 0x1c, 0xe0, 0xbf, 0xd0, 0x1c, 0xf1, 0xda, 0xfa, 0x47, 0xc1, 0x2a, 0xe5, 0x84,
            0xe5, 0xf2, 0xf6, 0xdf, 0xa1, 0x02, 0x81, 0x81, 0x00, 0xb0, 0xae, 0x49, 0x0c, 0x62,
            0x93, 0x7a, 0x09, 0x24, 0xce, 0xd9, 0x82, 0x01, 0x2d, 0x4a, 0x7c, 0x10, 0x44, 0x49,
            0x7a, 0x76, 0x77, 0xe8, 0xdf, 0x46, 0xcf, 0x1b, 0xb2, 0x70, 0x0f, 0xc2, 0xc8, 0xe2,
            0xaf, 0x91, 0xcb, 0x4e, 0xb3, 0x8c, 0x70, 0x5e, 0xf2, 0x94, 0xd2, 0xc3, 0x87, 0x78,
            0x93, 0xf3, 0xa9, 0x46, 0x73, 0xb8, 0x8d, 0x9f, 0x7f, 0x55, 0x9d, 0x74, 0x4e, 0x60,
            0x89, 0x49, 0x3a, 0x3b, 0x6c, 0x07, 0x9c, 0x1b, 0x69, 0x3e, 0xb4, 0x39, 0x4c, 0x54,
            0x67, 0x44, 0xfc, 0x4d, 0xa4, 0xa1, 0x28, 0xcf, 0x1a, 0xf4, 0x73, 0x01, 0x61, 0xba,
            0x90, 0x5c, 0x98, 0xf2, 0x4d, 0xfe, 0xcc, 0x8d, 0xf5, 0x8e, 0x60, 0xa2, 0x1e, 0x0b,
            0x67, 0x93, 0x39, 0x31, 0x82, 0x50, 0xbf, 0x5a, 0x39, 0x91, 0x64, 0x09, 0x13, 0x6b,
            0x07, 0xd2, 0x3f, 0xe2, 0xfa, 0x8a, 0x2d, 0x81, 0x40, 0x48, 0x21, 0x02, 0x81, 0x81,
            0x00, 0xe9, 0xfb, 0xb3, 0x01, 0xb7, 0x09, 0xc0, 0xf2, 0x71, 0x2e, 0x68, 0x63, 0xac,
            0x1a, 0x05, 0x05, 0x7b, 0x84, 0xc5, 0xa2, 0x1c, 0xcb, 0xfa, 0x62, 0x43, 0xb0, 0xaa,
            0x46, 0x86, 0x93, 0x53, 0x55, 0x10, 0xd1, 0xba, 0x23, 0xc8, 0xf1, 0x3c, 0xe5, 0x7c,
            0xf7, 0x6e, 0x17, 0x60, 0x5f, 0xb0, 0x14, 0xd7, 0xc0, 0x6b, 0xa0, 0x7f, 0x45, 0xb0,
            0x37, 0x94, 0x56, 0x19, 0xe3, 0x9f, 0x81, 0x5a, 0xfb, 0x64, 0x01, 0x2c, 0x5a, 0xd4,
            0x04, 0x07, 0xb1, 0x73, 0x95, 0x16, 0x9e, 0x18, 0xd6, 0xd9, 0xe5, 0xa7, 0xb1, 0x7a,
            0xe2, 0x46, 0x70, 0xd8, 0x8b, 0x4e, 0xac, 0xc7, 0xc4, 0x29, 0x10, 0x21, 0x0b, 0xbf,
            0x23, 0x6e, 0x54, 0x2b, 0xa4, 0xfc, 0x85, 0xa2, 0x5f, 0x7e, 0x7d, 0x9a, 0xd4, 0x83,
            0x7a, 0x18, 0x97, 0xc4, 0xd0, 0x83, 0xb1, 0xf6, 0xf1, 0x70, 0xa8, 0x55, 0x17, 0x07,
            0x8c, 0x01, 0x91,
        ];

        let result = RsaPrivateKey::from_der(&DER_PKCS1, Some(Kind::Rsa2kPrivate));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::RsaFromDerError);
        }
    }

    #[test]
    fn rsa_encrypt_decrypt() {
        let mut data = [1u8; 256];
        data[0] = 0;
        data[1] = 2;
        data[255] = 0;
        pub const TEST_RSA_2K_PRIVATE_KEY: [u8; 1214] = [
            0x30, 0x82, 0x04, 0xba, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa4, 0x30, 0x82,
            0x04, 0xa0, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe1, 0x60, 0x77, 0xe2,
            0x62, 0x3f, 0x84, 0x56, 0xc9, 0x2a, 0xc1, 0xf2, 0x09, 0x9e, 0x97, 0x22, 0x88, 0x68,
            0x47, 0xa4, 0x94, 0x35, 0x6e, 0x81, 0x85, 0xc6, 0xe6, 0x1e, 0xa8, 0x59, 0xb8, 0x69,
            0x6f, 0xfe, 0x29, 0x31, 0x96, 0xac, 0x68, 0x8a, 0x09, 0x39, 0x3b, 0x89, 0x9b, 0x96,
            0xbf, 0x8f, 0x23, 0x12, 0x61, 0xbf, 0x46, 0x69, 0x6d, 0x67, 0x28, 0x56, 0xab, 0xdf,
            0x41, 0xc9, 0x5e, 0x80, 0x0b, 0x73, 0xac, 0xbe, 0x50, 0x08, 0xe0, 0x29, 0x12, 0x71,
            0xce, 0xd0, 0x8e, 0xff, 0x3e, 0x90, 0x3d, 0x5a, 0xcc, 0x14, 0x7f, 0xa9, 0xf0, 0x68,
            0xdc, 0x1c, 0xd8, 0xaf, 0x64, 0xcc, 0x0b, 0x43, 0xb1, 0xa9, 0x3d, 0xfb, 0xe8, 0xbc,
            0x90, 0x1a, 0x45, 0xd2, 0xdb, 0x17, 0xf5, 0x7a, 0xb5, 0xb3, 0x9e, 0x64, 0x31, 0xa5,
            0x43, 0xb7, 0x94, 0xa7, 0x31, 0x29, 0x79, 0x41, 0x69, 0x14, 0xdd, 0x6d, 0x67, 0x68,
            0x0a, 0x36, 0x38, 0x0e, 0x35, 0xc6, 0x62, 0xcf, 0x38, 0xcc, 0x52, 0x64, 0x8d, 0xa6,
            0x7e, 0x7e, 0x70, 0x60, 0x46, 0x29, 0x68, 0x3c, 0x42, 0x2e, 0xe2, 0xd8, 0x21, 0x6d,
            0x01, 0x65, 0xc5, 0x86, 0x36, 0xeb, 0x0f, 0x1e, 0x6d, 0xf1, 0xd8, 0x7b, 0xe0, 0x4d,
            0xce, 0x71, 0xc8, 0x35, 0x5c, 0x6f, 0x0c, 0x4a, 0x8b, 0xf8, 0x07, 0x23, 0x6b, 0xfe,
            0x47, 0xdc, 0xbd, 0x02, 0xf2, 0xff, 0xb0, 0xdf, 0xcf, 0x02, 0xf6, 0xa1, 0x4b, 0x6b,
            0x99, 0xcc, 0xc6, 0x76, 0x30, 0xc5, 0xe4, 0x02, 0xf4, 0xa2, 0x02, 0xbf, 0x71, 0x31,
            0x3d, 0x80, 0x70, 0x60, 0x23, 0x12, 0xad, 0x2f, 0x02, 0x20, 0x42, 0x67, 0x15, 0x7a,
            0x6d, 0xf4, 0x58, 0x2a, 0x8a, 0x1d, 0x25, 0x1d, 0xfd, 0x01, 0x3f, 0x83, 0x5f, 0x5a,
            0xfb, 0x11, 0x98, 0xda, 0x55, 0x96, 0x8f, 0x26, 0x61, 0x25, 0x8b, 0xdb, 0xfc, 0xc9,
            0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0xff, 0x7b, 0x8b, 0x66, 0x2c, 0x5d, 0xaf,
            0x1e, 0x87, 0x1f, 0x14, 0xa6, 0x91, 0xb2, 0x09, 0x92, 0xcf, 0xb0, 0xa1, 0x79, 0x4f,
            0x13, 0xef, 0x8b, 0xa4, 0x1f, 0x5b, 0xe8, 0xc9, 0x90, 0x2a, 0x49, 0x42, 0x2d, 0xcc,
            0xd0, 0x1d, 0x5e, 0xd0, 0x79, 0x28, 0x87, 0x3b, 0x2d, 0xbd, 0x41, 0x37, 0xb7, 0x1f,
            0xbf, 0xc4, 0xa9, 0x25, 0xdb, 0xc8, 0x99, 0xda, 0xf2, 0x97, 0x3a, 0xf5, 0x7c, 0xc5,
            0x3b, 0x5d, 0xa0, 0x3e, 0xc8, 0xc8, 0x35, 0x17, 0x53, 0x1f, 0x30, 0xa7, 0xdd, 0x0c,
            0x76, 0xac, 0x1f, 0x4a, 0x47, 0xad, 0x28, 0xdc, 0xbe, 0x74, 0x14, 0x55, 0x66, 0xfe,
            0x69, 0x1f, 0x11, 0xcc, 0xc8, 0x5f, 0xfe, 0x03, 0xc8, 0x4b, 0xf9, 0x9e, 0x0e, 0xb5,
            0xad, 0x90, 0xe8, 0x89, 0x39, 0xb2, 0x5f, 0xe8, 0x6b, 0xeb, 0x2b, 0x4b, 0xc2, 0x28,
            0x8a, 0xff, 0x1b, 0x9e, 0xa0, 0x84, 0x3a, 0xc0, 0xdf, 0xf5, 0x11, 0x6e, 0xa5, 0x93,
            0xd3, 0x05, 0x13, 0x6b, 0x98, 0x70, 0x1d, 0xa8, 0x8d, 0xda, 0x2d, 0xcd, 0xcb, 0x11,
            0x48, 0x59, 0xf4, 0xaa, 0xa9, 0x8a, 0xb0, 0x8a, 0xf4, 0x8d, 0xb4, 0x00, 0x35, 0x9f,
            0x2b, 0x44, 0x99, 0x06, 0x41, 0x99, 0xcb, 0xe4, 0x24, 0xc1, 0xfa, 0xb4, 0x2b, 0x42,
            0xc7, 0xbe, 0x50, 0xd1, 0xca, 0x16, 0xed, 0x69, 0x68, 0xfe, 0xcc, 0x13, 0xd0, 0x6b,
            0x8c, 0xa2, 0xfd, 0x97, 0x37, 0xf4, 0xdc, 0x2b, 0x59, 0x63, 0xf0, 0x4f, 0x15, 0x1e,
            0x6d, 0x4a, 0xed, 0x16, 0x4f, 0xff, 0xc8, 0x73, 0x79, 0x8f, 0x4c, 0x3f, 0x29, 0xfa,
            0x00, 0x8d, 0xc1, 0xf2, 0xe9, 0x32, 0x46, 0xae, 0x68, 0x9d, 0x64, 0xe1, 0xbe, 0x0e,
            0x3d, 0xad, 0x31, 0xa4, 0x1f, 0x16, 0x58, 0x73, 0x5d, 0x89, 0x70, 0xd9, 0xdb, 0xf4,
            0x91, 0xab, 0x6d, 0x71, 0xf0, 0x2b, 0x8d, 0xf9, 0x59, 0xd7, 0x1d, 0x02, 0x81, 0x81,
            0x00, 0xfb, 0x9c, 0x2b, 0xde, 0xb2, 0xda, 0x0d, 0xc7, 0x16, 0xd4, 0x69, 0xb7, 0xca,
            0xb1, 0x2d, 0x3d, 0x4b, 0xd0, 0x4a, 0x9c, 0xbb, 0xc6, 0x99, 0x7d, 0xfe, 0x50, 0xb2,
            0xde, 0x84, 0x64, 0xef, 0xbd, 0xf8, 0x72, 0x9e, 0x55, 0x4e, 0xb6, 0xa6, 0xa1, 0x68,
            0x47, 0xb0, 0x69, 0x77, 0x1a, 0x7b, 0x63, 0x4a, 0x05, 0xc1, 0xfa, 0xce, 0x10, 0x9c,
            0x1f, 0x18, 0x1a, 0x46, 0xb9, 0xb5, 0x66, 0xef, 0xfc, 0x04, 0x29, 0x27, 0xb9, 0x3d,
            0xa4, 0x85, 0x78, 0x99, 0xe4, 0x6e, 0x2e, 0xb0, 0x42, 0xbb, 0x95, 0x93, 0x46, 0xf9,
            0x70, 0x91, 0x1b, 0xf3, 0x9a, 0xfb, 0xaa, 0x96, 0x7c, 0x82, 0x77, 0x33, 0xb9, 0x98,
            0x2f, 0xa3, 0xd4, 0x24, 0x82, 0xca, 0x57, 0x74, 0xde, 0x19, 0x38, 0x3e, 0xc2, 0xda,
            0x31, 0x03, 0xf9, 0x6d, 0xcb, 0x7f, 0x5c, 0x90, 0xc8, 0x0d, 0x62, 0x31, 0xab, 0xb3,
            0xde, 0x84, 0x9b, 0x02, 0x81, 0x81, 0x00, 0xe5, 0x4f, 0x1f, 0xff, 0x19, 0x17, 0xc2,
            0x40, 0xf5, 0xe4, 0x3a, 0x88, 0xaa, 0xa5, 0x45, 0x11, 0x13, 0xe7, 0x2b, 0x14, 0x96,
            0x83, 0xbb, 0x83, 0x3f, 0x75, 0x07, 0xaa, 0x94, 0x1d, 0x82, 0xd6, 0x8a, 0x63, 0xad,
            0xf1, 0x3a, 0xb4, 0x4c, 0xcd, 0x34, 0x09, 0x65, 0xc6, 0xe2, 0x0b, 0xfd, 0xc3, 0x4d,
            0x95, 0x7c, 0xf2, 0x9d, 0x5e, 0x97, 0xe1, 0x4a, 0x07, 0x5f, 0xb2, 0x7b, 0x0a, 0x4e,
            0x00, 0x40, 0xb1, 0xa5, 0x3b, 0xf6, 0x99, 0x21, 0xb5, 0x8b, 0x97, 0xc1, 0xf1, 0x1e,
            0x86, 0xfa, 0xaa, 0x03, 0x7f, 0xa8, 0x9a, 0xb1, 0x01, 0x98, 0x89, 0xf1, 0x01, 0x63,
            0x89, 0x64, 0xd4, 0x0b, 0x6e, 0x89, 0x72, 0xc9, 0x85, 0xcf, 0x55, 0x9c, 0xe8, 0x2e,
            0x34, 0xbd, 0xf3, 0x7c, 0x32, 0xc2, 0xfc, 0xf8, 0xc5, 0xf1, 0xf5, 0xa9, 0x12, 0xc0,
            0xf2, 0xee, 0xb4, 0xb1, 0x57, 0x5b, 0x10, 0xb0, 0x6b, 0x02, 0x81, 0x80, 0x74, 0xd2,
            0xbd, 0x37, 0xc8, 0x79, 0x20, 0x1e, 0x89, 0x46, 0x14, 0xd3, 0xe6, 0x43, 0xbf, 0x8a,
            0x8f, 0x51, 0xe5, 0xe2, 0xc1, 0xf8, 0xe3, 0x39, 0xb1, 0xc4, 0x0c, 0x58, 0xee, 0xc5,
            0xe2, 0xde, 0xa4, 0xa5, 0xab, 0x48, 0x56, 0xa4, 0xcd, 0xd7, 0x71, 0x90, 0x9f, 0xa3,
            0x48, 0x4e, 0xbe, 0x6d, 0x8a, 0x68, 0x03, 0xfa, 0x0c, 0x85, 0x7f, 0xc7, 0x9c, 0x2c,
            0x4f, 0x1c, 0x58, 0xd2, 0xb3, 0xa8, 0xa2, 0xd1, 0xed, 0x04, 0xc0, 0x4f, 0x4c, 0x3d,
            0x83, 0xce, 0xa1, 0x2e, 0x02, 0x5e, 0xe9, 0xb3, 0xf8, 0x4e, 0xe2, 0xf0, 0x56, 0x1f,
            0xd1, 0x4a, 0xeb, 0x80, 0xf8, 0x20, 0x55, 0x7f, 0x3d, 0x3f, 0xf6, 0x1e, 0x60, 0x85,
            0xd6, 0x71, 0xf7, 0xbb, 0x05, 0xa3, 0x3d, 0xb8, 0x74, 0xc3, 0x8a, 0x05, 0x6a, 0x1f,
            0xfc, 0xcf, 0x98, 0x92, 0x05, 0x13, 0x2d, 0xcb, 0xa2, 0xde, 0x63, 0x44, 0x74, 0xf3,
            0x02, 0x81, 0x80, 0x6c, 0x0b, 0xfc, 0x67, 0x96, 0xcb, 0x3b, 0x1c, 0xa0, 0xc0, 0x09,
            0x54, 0x9c, 0x13, 0x83, 0x97, 0xa8, 0x69, 0x24, 0x43, 0x6f, 0x28, 0x63, 0x12, 0x54,
            0xb4, 0x30, 0x08, 0x90, 0x01, 0xd7, 0xc4, 0x7f, 0x30, 0xb8, 0xa5, 0x11, 0xa4, 0x23,
            0x0c, 0x0d, 0x98, 0xdf, 0xfb, 0xf6, 0x46, 0xf0, 0x2b, 0x36, 0x43, 0x59, 0xbc, 0x77,
            0xaa, 0x3a, 0xa6, 0x4c, 0xdb, 0x6c, 0x9c, 0x0c, 0x9d, 0xae, 0x63, 0x30, 0x18, 0x84,
            0x62, 0xdc, 0xaf, 0x0a, 0xd3, 0x20, 0x13, 0x41, 0xae, 0xfb, 0x53, 0x5e, 0x88, 0xfd,
            0x5d, 0x09, 0x74, 0xda, 0x32, 0x86, 0x4d, 0x78, 0xe1, 0xce, 0xa4, 0xce, 0x7d, 0x9b,
            0x65, 0x5a, 0x1e, 0x5c, 0x16, 0x50, 0xbb, 0x66, 0x53, 0x80, 0x72, 0x19, 0x8e, 0xc0,
            0xd6, 0xaa, 0x49, 0xc8, 0x6e, 0x7c, 0xb3, 0xe4, 0x16, 0x92, 0x13, 0xe5, 0xa5, 0xfe,
            0x69, 0xca, 0xde, 0xf2, 0x41, 0x02, 0x81, 0x80, 0x24, 0xf0, 0x01, 0x0f, 0x34, 0xc7,
            0x27, 0x2b, 0x7a, 0xf1, 0x4e, 0x04, 0x50, 0xd3, 0x18, 0x2b, 0x9c, 0x75, 0x10, 0x22,
            0x1c, 0xaa, 0x63, 0xb9, 0x7a, 0x52, 0xd3, 0x15, 0x91, 0xa6, 0xf4, 0xd4, 0xa4, 0x27,
            0x51, 0x17, 0x10, 0x01, 0xac, 0x83, 0xf7, 0x95, 0x58, 0xf4, 0x70, 0x29, 0x37, 0x65,
            0x63, 0x0f, 0x5e, 0x77, 0x75, 0xd3, 0x44, 0x83, 0xa1, 0xf0, 0x4e, 0x9b, 0x66, 0xfd,
            0x4b, 0x38, 0x65, 0x2b, 0x5d, 0x9f, 0x4d, 0x3c, 0x2e, 0xb6, 0xc9, 0xe3, 0x10, 0x3f,
            0xd4, 0x14, 0x2e, 0x6f, 0x20, 0xe5, 0x77, 0x1f, 0x92, 0x41, 0xc2, 0x60, 0x23, 0x4a,
            0x98, 0xbd, 0x2b, 0x24, 0x3c, 0x23, 0x02, 0xa9, 0x32, 0x5e, 0x21, 0xe7, 0xbe, 0x2e,
            0x56, 0x90, 0xab, 0x49, 0x73, 0x49, 0x7c, 0xf9, 0xd9, 0x8c, 0x6f, 0x46, 0xb1, 0x13,
            0x32, 0x5c, 0x5e, 0x07, 0xea, 0x74, 0x02, 0x45, 0xce, 0x87,
        ];

        #[allow(dead_code)]
        pub const TEST_RSA_2K_PUBLIC_KEY: [u8; 294] = [
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
            0x02, 0x82, 0x01, 0x01, 0x00, 0xe1, 0x60, 0x77, 0xe2, 0x62, 0x3f, 0x84, 0x56, 0xc9,
            0x2a, 0xc1, 0xf2, 0x09, 0x9e, 0x97, 0x22, 0x88, 0x68, 0x47, 0xa4, 0x94, 0x35, 0x6e,
            0x81, 0x85, 0xc6, 0xe6, 0x1e, 0xa8, 0x59, 0xb8, 0x69, 0x6f, 0xfe, 0x29, 0x31, 0x96,
            0xac, 0x68, 0x8a, 0x09, 0x39, 0x3b, 0x89, 0x9b, 0x96, 0xbf, 0x8f, 0x23, 0x12, 0x61,
            0xbf, 0x46, 0x69, 0x6d, 0x67, 0x28, 0x56, 0xab, 0xdf, 0x41, 0xc9, 0x5e, 0x80, 0x0b,
            0x73, 0xac, 0xbe, 0x50, 0x08, 0xe0, 0x29, 0x12, 0x71, 0xce, 0xd0, 0x8e, 0xff, 0x3e,
            0x90, 0x3d, 0x5a, 0xcc, 0x14, 0x7f, 0xa9, 0xf0, 0x68, 0xdc, 0x1c, 0xd8, 0xaf, 0x64,
            0xcc, 0x0b, 0x43, 0xb1, 0xa9, 0x3d, 0xfb, 0xe8, 0xbc, 0x90, 0x1a, 0x45, 0xd2, 0xdb,
            0x17, 0xf5, 0x7a, 0xb5, 0xb3, 0x9e, 0x64, 0x31, 0xa5, 0x43, 0xb7, 0x94, 0xa7, 0x31,
            0x29, 0x79, 0x41, 0x69, 0x14, 0xdd, 0x6d, 0x67, 0x68, 0x0a, 0x36, 0x38, 0x0e, 0x35,
            0xc6, 0x62, 0xcf, 0x38, 0xcc, 0x52, 0x64, 0x8d, 0xa6, 0x7e, 0x7e, 0x70, 0x60, 0x46,
            0x29, 0x68, 0x3c, 0x42, 0x2e, 0xe2, 0xd8, 0x21, 0x6d, 0x01, 0x65, 0xc5, 0x86, 0x36,
            0xeb, 0x0f, 0x1e, 0x6d, 0xf1, 0xd8, 0x7b, 0xe0, 0x4d, 0xce, 0x71, 0xc8, 0x35, 0x5c,
            0x6f, 0x0c, 0x4a, 0x8b, 0xf8, 0x07, 0x23, 0x6b, 0xfe, 0x47, 0xdc, 0xbd, 0x02, 0xf2,
            0xff, 0xb0, 0xdf, 0xcf, 0x02, 0xf6, 0xa1, 0x4b, 0x6b, 0x99, 0xcc, 0xc6, 0x76, 0x30,
            0xc5, 0xe4, 0x02, 0xf4, 0xa2, 0x02, 0xbf, 0x71, 0x31, 0x3d, 0x80, 0x70, 0x60, 0x23,
            0x12, 0xad, 0x2f, 0x02, 0x20, 0x42, 0x67, 0x15, 0x7a, 0x6d, 0xf4, 0x58, 0x2a, 0x8a,
            0x1d, 0x25, 0x1d, 0xfd, 0x01, 0x3f, 0x83, 0x5f, 0x5a, 0xfb, 0x11, 0x98, 0xda, 0x55,
            0x96, 0x8f, 0x26, 0x61, 0x25, 0x8b, 0xdb, 0xfc, 0xc9, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        let rsa_private =
            RsaPrivateKey::from_der(&TEST_RSA_2K_PRIVATE_KEY, Some(Kind::Rsa2kPrivate)).unwrap();
        let rsa_public =
            RsaPublicKey::from_der(&TEST_RSA_2K_PUBLIC_KEY, Some(Kind::Rsa2kPublic)).unwrap();

        let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        let result = rsa_private.decrypt(&encrypted, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let decrypted = result.unwrap();
        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_rsa_public_der() {
        let data = [1u8; 256];

        // Generate the key
        let keypair = generate_rsa(2048);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        let result = rsa_public.to_der();
        assert!(result.is_ok());

        let result = RsaPublicKey::from_der(&result.unwrap(), Some(Kind::Rsa2kPublic));
        assert!(result.is_ok());
        let rsa_public = result.unwrap();

        // Encrypt data with the key
        let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Decrypt data with the key
        let result = rsa_private.decrypt(&encrypted, RsaCryptoPadding::None, None);
        assert!(result.is_ok());
        let decrypted = result.unwrap();

        assert_eq!(data.to_vec(), decrypted);

        // Test from_der with rsa private key
        let result = rsa_private.to_der();
        assert!(result.is_ok());

        let result = RsaPublicKey::from_der(&result.unwrap(), Some(Kind::Rsa2kPublic));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::RsaFromDerError);
        }

        // Test from_der with PKCS1 format
        const DER_PKCS1: [u8; 270] = [
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbf, 0x32, 0x5e, 0xc1, 0x46,
            0x95, 0x05, 0x33, 0xda, 0x60, 0x95, 0x99, 0x62, 0x30, 0x41, 0x18, 0x5f, 0x5a, 0xc8,
            0xd8, 0x52, 0x12, 0x07, 0xc5, 0xef, 0xe3, 0x28, 0x76, 0xed, 0x1c, 0x6f, 0x2f, 0xba,
            0x19, 0x70, 0x6d, 0x05, 0x3e, 0x2e, 0xa4, 0x9a, 0x4e, 0x64, 0xd7, 0x01, 0x84, 0x2b,
            0x87, 0x96, 0x4a, 0xc3, 0xe2, 0x3f, 0x10, 0x5b, 0xd5, 0xbf, 0x75, 0x10, 0xe4, 0xdd,
            0x34, 0x6c, 0x1f, 0xc4, 0x13, 0xd2, 0x72, 0x7c, 0x33, 0xe2, 0x15, 0x5a, 0x67, 0xf6,
            0x18, 0x11, 0x59, 0x54, 0x70, 0x61, 0xd9, 0xd5, 0x25, 0xe4, 0xef, 0xf0, 0xde, 0xfc,
            0xf5, 0x24, 0x11, 0xb9, 0xa0, 0xe9, 0x3c, 0x6c, 0x0e, 0x7c, 0x6e, 0xa5, 0xc1, 0x0d,
            0xab, 0xaa, 0xad, 0xc9, 0x70, 0x2f, 0xc1, 0xee, 0x3f, 0xb6, 0x29, 0xe0, 0xfe, 0x45,
            0x9f, 0xe8, 0x2d, 0x7f, 0x18, 0xce, 0x41, 0x08, 0xd1, 0x1d, 0x0c, 0x2b, 0x89, 0x33,
            0x5c, 0xa9, 0xef, 0x76, 0xb6, 0x56, 0xe6, 0xd4, 0x90, 0x62, 0x37, 0x22, 0xea, 0xaa,
            0x0d, 0x42, 0xbf, 0x62, 0x77, 0xc7, 0x06, 0xa9, 0xe9, 0x3d, 0xc3, 0xd7, 0xdb, 0x97,
            0x7e, 0x87, 0x08, 0xde, 0x57, 0xb1, 0x0f, 0xab, 0xce, 0x5a, 0x34, 0x4a, 0xc4, 0x77,
            0x1d, 0x4e, 0x50, 0xf5, 0x4f, 0xba, 0x30, 0x90, 0x78, 0x4f, 0xe0, 0x9a, 0x75, 0x62,
            0x41, 0xcb, 0xdf, 0x19, 0xe3, 0x27, 0x43, 0x0e, 0x96, 0xb8, 0x9e, 0xd3, 0x30, 0xdb,
            0x49, 0xe9, 0x9c, 0xc9, 0x1d, 0x54, 0x03, 0x94, 0xec, 0xa2, 0x03, 0xa3, 0x04, 0x1c,
            0xb5, 0x94, 0xe0, 0x76, 0x16, 0xb0, 0x64, 0xf5, 0x61, 0x3f, 0x26, 0x80, 0xfe, 0x7a,
            0xaa, 0x6f, 0x51, 0xa0, 0x48, 0xb3, 0x57, 0x82, 0x52, 0x8b, 0x91, 0x65, 0x5b, 0xd9,
            0xa9, 0xbd, 0xee, 0x1f, 0xbe, 0x78, 0xf9, 0x4b, 0xea, 0xc5, 0xde, 0xc0, 0x9f, 0x02,
            0x03, 0x01, 0x00, 0x01,
        ];

        let result = RsaPublicKey::from_der(&DER_PKCS1, Some(Kind::Rsa2kPublic));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, ManticoreError::RsaFromDerError);
        }
    }

    // [TODO] [FIXME]
    // #[test]
    // fn test_operations() {
    //     const KEY_SIZE: usize = 256;
    //     let data = [1u8; KEY_SIZE];

    //     // Generate the key
    //     let keypair = generate_rsa((KEY_SIZE * 8) as u32);
    //     assert!(keypair.is_ok());
    //     let (rsa_private, rsa_public) = keypair.unwrap();

    //     // Encrypt data without padding
    //     let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
    //     assert!(result.is_ok());
    //     let encrypted = result.unwrap();

    //     // Decrypt data without padding
    //     let result = rsa_private.decrypt(&encrypted, RsaCryptoPadding::None, None);
    //     assert!(result.is_ok());
    //     let decrypted = result.unwrap();
    //     assert_eq!(data.to_vec(), decrypted);

    //     // Encrypt data with padding
    //     const SHA256_SIZE: usize = 32;
    //     const PADDING_SIZE: usize = (SHA256_SIZE + 1) * 2;
    //     let data = [1u8; KEY_SIZE - PADDING_SIZE];
    //     let result = rsa_public.encrypt(&data, RsaCryptoPadding::Oaep, Some(HashAlgorithm::Sha256));
    //     assert!(result.is_ok());
    //     let encrypted = result.unwrap();

    //     // Decrypt data with padding
    //     let result = rsa_private.decrypt(
    //         &encrypted,
    //         RsaCryptoPadding::Oaep,
    //         Some(HashAlgorithm::Sha256),
    //     );
    //     assert!(result.is_ok());
    //     let decrypted = result.unwrap();
    //     assert_eq!(data.to_vec(), decrypted);

    //     // Sign the digest with the key
    //     const DIGEST_SIZE: usize = 20;
    //     let digest = [1u8; DIGEST_SIZE];
    //     let result = rsa_private.sign(&digest, RsaSignaturePadding::Pss, None, None);
    //     assert!(result.is_ok());
    //     let signature = result.unwrap();

    //     // Verify the signature against the correct digest with the key
    //     let result = rsa_public.verify(&digest, &signature, RsaSignaturePadding::Pss, None, None);
    //     assert!(result.is_ok());

    //     // Verify the signature against the wrong digest with the key
    //     let digest = [2u8; DIGEST_SIZE];
    //     let result = rsa_public.verify(&digest, &signature, RsaSignaturePadding::Pss, None, None);
    //     assert_eq!(result, Err(ManticoreError::RsaVerifyError));

    //     // Expect to fail with input size that is not equal to the key size
    //     let data = [1u8; KEY_SIZE - 1];
    //     let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
    //     assert_eq!(result, Err(ManticoreError::RsaEncryptError));

    //     let data = [1u8; KEY_SIZE + 1];
    //     let result = rsa_public.encrypt(&data, RsaCryptoPadding::None, None);
    //     assert_eq!(result, Err(ManticoreError::RsaEncryptError));

    //     let digest = [1u8; DIGEST_SIZE - 1];
    //     let result = rsa_private.sign(&digest, RsaSignaturePadding::Pss, None, None);
    //     assert_eq!(result, Err(ManticoreError::RsaSignError));

    //     let digest = [1u8; DIGEST_SIZE + 1];
    //     let result = rsa_private.sign(&digest, RsaSignaturePadding::Pss, None, None);
    //     assert_eq!(result, Err(ManticoreError::RsaSignError));
    // }

    #[allow(unused)]
    fn rsa_pss_with_parameters(
        rsa_private: &RsaPrivateKey,
        rsa_public: &RsaPublicKey,
        digest_size: usize,
        hash_algorithm: HashAlgorithm,
        salt_len: u16,
    ) {
        let digest = vec![1u8; digest_size];

        let result = rsa_private.sign(
            &digest,
            RsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Verify the signature against the correct digest with the key
        let result = rsa_public.verify(
            &digest,
            &signature,
            RsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert!(result.is_ok());

        // Verify the signature with the wrong salt length
        let result = rsa_public.verify(
            &digest,
            &signature,
            RsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len + 1),
        );
        assert_eq!(result, Err(ManticoreError::RsaVerifyError));

        // Verify the signature with the wrong hash algorithm
        let wrong_hash_algorithm = if hash_algorithm == HashAlgorithm::Sha1 {
            HashAlgorithm::Sha256
        } else {
            HashAlgorithm::Sha1
        };
        let result = rsa_public.verify(
            &digest,
            &signature,
            RsaSignaturePadding::Pss,
            Some(wrong_hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(ManticoreError::RsaVerifyError));

        // Verify the signature against the wrong digest with the key
        let wrong_digest = vec![2u8; digest_size];
        let result = rsa_public.verify(
            &wrong_digest,
            &signature,
            RsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(ManticoreError::RsaVerifyError));

        // Verify the signature against the wrong signature
        let mut wrong_signature = signature;
        wrong_signature[5] = wrong_signature[5].wrapping_add(1);
        let result = rsa_public.verify(
            &digest,
            &wrong_signature,
            RsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(ManticoreError::RsaVerifyError));
    }

    // [TODO] [FIXME]
    // #[test]
    // fn test_rsa_pss_with_parameters() {
    //     const KEY_SIZE: usize = 256;

    //     // Generate the key
    //     let keypair = generate_rsa((KEY_SIZE * 8) as u32);
    //     assert!(keypair.is_ok());
    //     let (rsa_private, rsa_public) = keypair.unwrap();

    //     let salt_lens = [0u16, 20, 32, 64, 128];

    //     for salt_len in salt_lens {
    //         rsa_pss_with_parameters(&rsa_private, &rsa_public, 20, HashAlgorithm::Sha1, salt_len);
    //         rsa_pss_with_parameters(
    //             &rsa_private,
    //             &rsa_public,
    //             32,
    //             HashAlgorithm::Sha256,
    //             salt_len,
    //         );
    //         rsa_pss_with_parameters(
    //             &rsa_private,
    //             &rsa_public,
    //             48,
    //             HashAlgorithm::Sha384,
    //             salt_len,
    //         );
    //         rsa_pss_with_parameters(
    //             &rsa_private,
    //             &rsa_public,
    //             64,
    //             HashAlgorithm::Sha512,
    //             salt_len,
    //         );
    //     }
    // }

    #[test]
    fn test_get_parameters() {
        const KEY_SIZE: usize = 256;

        // Generate the key
        let keypair = generate_rsa((KEY_SIZE * 8) as u32);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        let modulus_from_private = rsa_private.modulus();
        assert!(modulus_from_private.is_ok());
        let modulus_from_private = modulus_from_private.unwrap();

        let public_exponent_from_private = rsa_private.public_exponent();
        assert!(public_exponent_from_private.is_ok());
        let public_exponent_from_private = public_exponent_from_private.unwrap();

        let modulus_from_public = rsa_public.modulus();
        assert!(modulus_from_public.is_ok());
        let modulus_from_public = modulus_from_public.unwrap();

        let public_exponent_from_public = rsa_public.public_exponent();
        assert!(public_exponent_from_public.is_ok());
        let public_exponent_from_public = public_exponent_from_public.unwrap();

        assert_eq!(modulus_from_private, modulus_from_public);
        assert_eq!(public_exponent_from_private, public_exponent_from_public);
    }
}
