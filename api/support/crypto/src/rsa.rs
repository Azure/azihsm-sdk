// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for RSA Cryptographic Keys.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

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
use openssl::sign::RsaPssSaltlen;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hash::HashAlgorithm;
#[cfg(feature = "use-symcrypt")]
use symcrypt::rsa::RsaKey;
#[cfg(feature = "use-symcrypt")]
use symcrypt::rsa::RsaKeyUsage;

use crate::CryptoError;
use crate::CryptoHashAlgorithm;
use crate::CryptoKeyKind;
use crate::CryptoRsaCryptoPadding;
use crate::CryptoRsaSignaturePadding;

#[cfg(feature = "use-symcrypt")]
const RSA_OID: pkcs1::ObjectIdentifier =
    pkcs1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Trait for RSA Operations.
pub trait RsaOp<T> {
    fn generate(size: u32) -> Result<T, CryptoError>;
    fn from_der(der: &[u8], expected_type: Option<CryptoKeyKind>) -> Result<T, CryptoError>;
    fn to_der(&self) -> Result<Vec<u8>, CryptoError>;
    fn modulus(&self) -> Result<Vec<u8>, CryptoError>;
    fn public_exponent(&self) -> Result<Vec<u8>, CryptoError>;
    fn bits(&self) -> u32;
}

pub trait RsaPublicOp {
    fn from_raw(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, CryptoError>;
    fn encrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), CryptoError>;
}

/// RSA Public Key.
#[derive(Debug)]
pub struct RsaPublicKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Public>,

    #[cfg(feature = "use-symcrypt")]
    handle: RsaKey,
}

#[cfg(feature = "use-openssl")]
impl RsaOp<RsaPublicKey> for RsaPublicKey {
    /// Generate an RSA public key.
    fn generate(size: u32) -> Result<RsaPublicKey, CryptoError> {
        // Rsa::generate() uses 65537 as public exponent
        let rsa_private = openssl::rsa::Rsa::generate(size).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGenerateError
        })?;

        // Derive the public key
        let n = rsa_private.n().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGenerateError
        })?;
        let e = rsa_private.e().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGenerateError
        })?;
        let rsa_public =
            openssl::rsa::Rsa::from_public_components(n, e).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaGenerateError
            })?;

        // Wrap the public key in a `PKey` object
        let pkey_public =
            openssl::pkey::PKey::from_rsa(rsa_public).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaGenerateError
            })?;

        Ok(RsaPublicKey {
            handle: pkey_public,
        })
    }

    /// Deserialize an RSA public key from a DER-encoded SubjectPublicKeyInfo format.
    fn from_der(
        der: &[u8],
        expected_type: Option<CryptoKeyKind>,
    ) -> Result<RsaPublicKey, CryptoError> {
        let rsa = openssl::rsa::Rsa::public_key_from_der(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromDerError
        })?;
        let pkey = openssl::pkey::PKey::from_rsa(rsa).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromDerError
        })?;

        match expected_type {
            Some(CryptoKeyKind::Rsa2kPublic) => {
                if pkey.bits() != 2048 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa3kPublic) => {
                if pkey.bits() != 3072 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa4kPublic) => {
                if pkey.bits() != 4096 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPublicKey { handle: pkey })
    }

    /// Serialize the RSA public key to a DER-encoded SubjectPublicKeyInfo format.
    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .handle
            .as_ref()
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaToDerError
            })?;

        Ok(der)
    }

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetModulusError
        })?;
        let modulus = rsa.n().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetModulusError
        })?;

        Ok(modulus.to_vec())
    }

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetPublicExponentError
        })?;
        let public_exponent = rsa.e().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetPublicExponentError
        })?;

        Ok(public_exponent.to_vec())
    }

    /// Get the number of bits of the RSA key.
    fn bits(&self) -> u32 {
        self.handle.bits()
    }
}

#[cfg(feature = "use-openssl")]
impl RsaPublicOp for RsaPublicKey {
    // Create from raw modulus and exponent
    fn from_raw(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, CryptoError> {
        // Construct OpenSSL `BigNum` objects from the modulus and public
        // exponent. These are needed to create an OpenSSL RSA object.
        let n = openssl::bn::BigNum::from_slice(modulus).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromRawError
        })?;
        let e = openssl::bn::BigNum::from_slice(exponent).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromRawError
        })?;

        // Create an OpenSSL `Rsa` object
        let rsa =
            openssl::rsa::Rsa::from_public_components(n, e).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaFromRawError
            })?;

        // Wrap it in a `PKey` object
        let pkey = openssl::pkey::PKey::from_rsa(rsa).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromRawError
        })?;

        Ok(RsaPublicKey { handle: pkey })
    }

    // Encryption
    fn encrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let padding = match padding {
            CryptoRsaCryptoPadding::None => openssl::rsa::Padding::NONE,
            CryptoRsaCryptoPadding::Oaep => openssl::rsa::Padding::PKCS1_OAEP,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaEncryptFailed
        })?;

        ctx.encrypt_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaEncryptFailed
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaEncryptFailed
            })?;

        if padding == openssl::rsa::Padding::PKCS1_OAEP {
            // If padding is OAEP, set the OAEP algorithm and the OAEP
            // label (but only if a label was provided)
            let algo = match hash_algorithm.unwrap_or(CryptoHashAlgorithm::Sha256) {
                CryptoHashAlgorithm::Sha1 => {
                    tracing::error!("SHA-1 is not supported for RSA Encrypt with OAEP.");
                    Err(CryptoError::InvalidParameter)?
                }
                CryptoHashAlgorithm::Sha256 => Md::sha256(),
                CryptoHashAlgorithm::Sha384 => Md::sha384(),
                CryptoHashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_rsa_oaep_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaEncryptFailed
            })?;

            if let Some(label_buffer) = label {
                ctx.set_rsa_oaep_label(label_buffer)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::RsaEncryptFailed
                    })?;
            }
        }

        let buffer_len = ctx.encrypt(data, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaEncryptFailed
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let encrypted_len =
            ctx.encrypt(data, Some(&mut buffer))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::RsaEncryptFailed
                })?;

        let buffer = &buffer[..encrypted_len];

        Ok(buffer.to_vec())
    }

    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), CryptoError> {
        let padding = match padding {
            CryptoRsaSignaturePadding::Pss => openssl::rsa::Padding::PKCS1_PSS,
            CryptoRsaSignaturePadding::Pkcs1_5 => openssl::rsa::Padding::PKCS1,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaVerifyFailed
        })?;

        ctx.verify_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaVerifyFailed
        })?;
        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaVerifyFailed
            })?;

        if let Some(salt_len) = salt_len {
            ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len.into()))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::RsaVerifyFailed
                })?;
        }

        let hash_algo = match hash_algorithm {
            Some(CryptoHashAlgorithm::Sha1) => Md::sha1(),
            Some(CryptoHashAlgorithm::Sha256) => Md::sha256(),
            Some(CryptoHashAlgorithm::Sha384) => Md::sha384(),
            Some(CryptoHashAlgorithm::Sha512) => Md::sha512(),
            None => match digest.len() {
                20 => Md::sha1(),
                32 => Md::sha256(),
                48 => Md::sha384(),
                64 => Md::sha512(),
                _ => return Err(CryptoError::RsaSignFailed),
            },
        };

        ctx.set_signature_md(hash_algo)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaVerifyFailed
            })?;

        let result = ctx
            .verify(digest, signature)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaVerifyFailed
            })?;

        // Return error on verification failure
        if !result {
            Err(CryptoError::RsaVerifyFailed)?
        }

        Ok(())
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaOp<RsaPublicKey> for RsaPublicKey {
    /// Generate an RSA public key.
    fn generate(size: u32) -> Result<RsaPublicKey, CryptoError> {
        // Use SymCrypt to generate an RSA public/private key pair
        let key = RsaKey::generate_key_pair(size, None, RsaKeyUsage::SignAndEncrypt).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::RsaGenerateError
            },
        )?;

        Ok(RsaPublicKey { handle: key })
    }

    fn from_der(
        der: &[u8],
        expected_type: Option<CryptoKeyKind>,
    ) -> Result<RsaPublicKey, CryptoError> {
        use pkcs1::der::Decode;

        let public_key_info =
            spki::SubjectPublicKeyInfoRef::from_der(der).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaFromDerError
            })?;
        let public_key_der = public_key_info.subject_public_key;

        let public_key =
            pkcs1::RsaPublicKey::from_der(public_key_der.raw_bytes()).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaFromDerError
            })?;

        let modulus = public_key.modulus.as_bytes();
        let exponent = public_key.public_exponent.as_bytes();

        let symcrypt_key = RsaKey::set_public_key(modulus, exponent, RsaKeyUsage::SignAndEncrypt)
            .map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            CryptoError::RsaFromDerError
        })?;

        let expected_type = match expected_type {
            Some(unwrapped_type) => unwrapped_type,
            None => match symcrypt_key.get_size_of_modulus() {
                256 => CryptoKeyKind::Rsa2kPublic,
                384 => CryptoKeyKind::Rsa3kPublic,
                512 => CryptoKeyKind::Rsa4kPublic,
                _ => return Err(CryptoError::RsaFromDerError),
            },
        };

        match expected_type {
            CryptoKeyKind::Rsa2kPublic => {
                if symcrypt_key.get_size_of_modulus() != 256 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            CryptoKeyKind::Rsa3kPublic => {
                if symcrypt_key.get_size_of_modulus() != 384 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            CryptoKeyKind::Rsa4kPublic => {
                if symcrypt_key.get_size_of_modulus() != 512 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPublicKey {
            handle: symcrypt_key,
        })
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        use pkcs1::der::Encode;

        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::RsaToDerError
                })?;
        let modulus = pkcs1::UintRef::new(&public_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&public_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;
        let public_key = pkcs1::RsaPublicKey {
            modulus,
            public_exponent,
        };
        let public_key_der = public_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;

        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: None,
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;
        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = subject_public_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;

        Ok(der)
    }

    fn modulus(&self) -> Result<Vec<u8>, CryptoError> {
        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::RsaToDerError
                })?;
        Ok(public_key_blob.modulus)
    }

    fn public_exponent(&self) -> Result<Vec<u8>, CryptoError> {
        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::RsaToDerError
                })?;
        Ok(public_key_blob.pub_exp)
    }

    fn bits(&self) -> u32 {
        self.handle.get_size_of_modulus() * 8
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaPublicOp for RsaPublicKey {
    // Create from raw modulus and exponent
    fn from_raw(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, CryptoError> {
        let handle = RsaKey::set_public_key(modulus, exponent, RsaKeyUsage::SignAndEncrypt)
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::RsaFromRawError
            })?;
        Ok(RsaPublicKey { handle })
    }

    fn encrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        match padding {
            CryptoRsaCryptoPadding::None => Err(CryptoError::RsaEncryptFailed),
            CryptoRsaCryptoPadding::Oaep => {
                let hash_algo = match hash_algorithm.unwrap_or(CryptoHashAlgorithm::Sha256) {
                    CryptoHashAlgorithm::Sha1 => {
                        tracing::error!("SHA-1 is not supported for RSA Encrypt with OAEP.");
                        Err(CryptoError::InvalidParameter)?
                    }
                    CryptoHashAlgorithm::Sha256 => HashAlgorithm::Sha256,
                    CryptoHashAlgorithm::Sha384 => HashAlgorithm::Sha384,
                    CryptoHashAlgorithm::Sha512 => HashAlgorithm::Sha512,
                };
                let label_param = label.unwrap_or(b"");
                let ciphertext = self
                    .handle
                    .oaep_encrypt(data, hash_algo, label_param)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::RsaEncryptFailed
                    })?;
                Ok(ciphertext)
            }
        }
    }

    fn verify(
        &self,
        digest: &[u8],
        signature: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<(), CryptoError> {
        let hash_algo = match hash_algorithm {
            Some(CryptoHashAlgorithm::Sha1) => HashAlgorithm::Sha1,
            Some(CryptoHashAlgorithm::Sha256) => HashAlgorithm::Sha256,
            Some(CryptoHashAlgorithm::Sha384) => HashAlgorithm::Sha384,
            Some(CryptoHashAlgorithm::Sha512) => HashAlgorithm::Sha512,
            None => match digest.len() {
                20 => HashAlgorithm::Sha1,
                32 => HashAlgorithm::Sha256,
                48 => HashAlgorithm::Sha384,
                64 => HashAlgorithm::Sha512,
                _ => return Err(CryptoError::RsaVerifyFailed),
            },
        };
        match padding {
            CryptoRsaSignaturePadding::Pkcs1_5 => {
                let result = self.handle.pkcs1_verify(digest, signature, hash_algo);
                if result.is_err() {
                    Err(CryptoError::RsaVerifyFailed)?
                }
            }
            CryptoRsaSignaturePadding::Pss => {
                let salt_len = salt_len.unwrap_or(digest.len() as u16);
                let result =
                    self.handle
                        .pss_verify(digest, signature, hash_algo, salt_len as usize);
                if result.is_err() {
                    return Err(CryptoError::RsaVerifyFailed);
                }
            }
        }
        Ok(())
    }
}

pub trait RsaPrivateOp {
    fn decrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn sign(
        &self,
        digest: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, CryptoError>;
    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError>;
}

pub fn generate_rsa(size: u32) -> Result<(RsaPrivateKey, RsaPublicKey), CryptoError> {
    RsaPrivateKey::generate(size).and_then(|private_key| {
        let public_key_der = private_key.extract_pub_key_der()?;
        RsaPublicKey::from_der(&public_key_der, None).map(|public_key| (private_key, public_key))
    })
}

/// RSA Private Key.
#[derive(Debug)]
pub struct RsaPrivateKey {
    #[cfg(feature = "use-openssl")]
    handle: PKey<Private>,

    #[cfg(feature = "use-symcrypt")]
    handle: RsaKey,
}

#[cfg(feature = "use-openssl")]
impl RsaOp<RsaPrivateKey> for RsaPrivateKey {
    /// Generate an RSA private key.
    fn generate(size: u32) -> Result<RsaPrivateKey, CryptoError> {
        // Rsa::generate() uses 65537 as public exponent
        let rsa_private = openssl::rsa::Rsa::generate(size).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGenerateError
        })?;

        // Wrap the private key in a `PKey` object
        let pkey_private =
            openssl::pkey::PKey::from_rsa(rsa_private).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaGenerateError
            })?;

        Ok(RsaPrivateKey {
            handle: pkey_private,
        })
    }

    /// Deserialize an RSA private key from a DER-encoded PKCS#8 format.
    fn from_der(
        der: &[u8],
        expected_type: Option<CryptoKeyKind>,
    ) -> Result<RsaPrivateKey, CryptoError> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaFromDerError
        })?;

        match expected_type {
            Some(CryptoKeyKind::Rsa2kPrivate) | Some(CryptoKeyKind::Rsa2kPrivateCrt) => {
                if pkey.bits() != 2048 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa3kPrivate) | Some(CryptoKeyKind::Rsa3kPrivateCrt) => {
                if pkey.bits() != 3072 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa4kPrivate) | Some(CryptoKeyKind::Rsa4kPrivateCrt) => {
                if pkey.bits() != 4096 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPrivateKey { handle: pkey })
    }

    /// Serialize the RSA private key to a DER-encoded PKCS#8 format.
    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        let der = self
            .handle
            .as_ref()
            .private_key_to_pkcs8()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaToDerError
            })?;

        Ok(der)
    }

    /// Get the modulus of the RSA key.
    fn modulus(&self) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetModulusError
        })?;
        let modulus = rsa.n().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetModulusError
        })?;

        Ok(modulus.to_vec())
    }

    /// Get the public exponent of the RSA key.
    fn public_exponent(&self) -> Result<Vec<u8>, CryptoError> {
        let rsa = self.handle.rsa().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetPublicExponentError
        })?;
        let public_exponent = rsa.e().to_owned().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaGetPublicExponentError
        })?;

        Ok(public_exponent.to_vec())
    }

    /// Get the number of bits of the RSA key.
    fn bits(&self) -> u32 {
        self.handle.bits()
    }
}

#[cfg(feature = "use-openssl")]
impl RsaPrivateOp for RsaPrivateKey {
    // Decryption
    fn decrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let padding = match padding {
            CryptoRsaCryptoPadding::None => openssl::rsa::Padding::NONE,
            CryptoRsaCryptoPadding::Oaep => openssl::rsa::Padding::PKCS1_OAEP,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaDecryptFailed
        })?;

        ctx.decrypt_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaDecryptFailed
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaDecryptFailed
            })?;

        if padding == openssl::rsa::Padding::PKCS1_OAEP {
            // If padding is OAEP, set the OAEP algorithm and the
            // OAEP label (but only if a label was provided)
            let algo = match hash_algorithm.unwrap_or(CryptoHashAlgorithm::Sha256) {
                CryptoHashAlgorithm::Sha1 => Md::sha1(),
                CryptoHashAlgorithm::Sha256 => Md::sha256(),
                CryptoHashAlgorithm::Sha384 => Md::sha384(),
                CryptoHashAlgorithm::Sha512 => Md::sha512(),
            };

            ctx.set_rsa_oaep_md(algo).map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaDecryptFailed
            })?;

            if let Some(label_buffer) = label {
                ctx.set_rsa_oaep_label(label_buffer)
                    .map_err(|openssl_error_stack| {
                        tracing::error!(?openssl_error_stack);
                        CryptoError::RsaEncryptFailed
                    })?;
            }
        }

        let buffer_len = ctx.decrypt(data, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaDecryptFailed
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let decrypted_len =
            ctx.decrypt(data, Some(&mut buffer))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::RsaDecryptFailed
                })?;

        let buffer = &buffer[..decrypted_len];

        Ok(buffer.to_vec())
    }

    // Sign
    fn sign(
        &self,
        digest: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, CryptoError> {
        let padding = match padding {
            CryptoRsaSignaturePadding::Pss => openssl::rsa::Padding::PKCS1_PSS,
            CryptoRsaSignaturePadding::Pkcs1_5 => openssl::rsa::Padding::PKCS1,
        };

        let mut ctx = PkeyCtx::new(&self.handle).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaSignFailed
        })?;

        ctx.sign_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaSignFailed
        })?;

        ctx.set_rsa_padding(padding)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaSignFailed
            })?;

        if let Some(salt_len) = salt_len {
            ctx.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len.into()))
                .map_err(|openssl_error_stack| {
                    tracing::error!(?openssl_error_stack);
                    CryptoError::RsaSignFailed
                })?;
        }

        let hash_algo = match hash_algorithm {
            Some(CryptoHashAlgorithm::Sha1) => Md::sha1(),
            Some(CryptoHashAlgorithm::Sha256) => Md::sha256(),
            Some(CryptoHashAlgorithm::Sha384) => Md::sha384(),
            Some(CryptoHashAlgorithm::Sha512) => Md::sha512(),
            None => match digest.len() {
                20 => Md::sha1(),
                32 => Md::sha256(),
                48 => Md::sha384(),
                64 => Md::sha512(),
                _ => return Err(CryptoError::RsaSignFailed),
            },
        };

        ctx.set_signature_md(hash_algo)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaSignFailed
            })?;

        let buffer_len = ctx.sign(digest, None).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::RsaSignFailed
        })?;

        let mut buffer = vec![0u8; buffer_len];

        let signature_len = ctx
            .sign(digest, Some(&mut buffer))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaSignFailed
            })?;

        let buffer = &buffer[..signature_len];

        Ok(buffer.to_vec())
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        self.handle
            .public_key_to_der()
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::RsaToDerError
            })
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaOp<RsaPrivateKey> for RsaPrivateKey {
    /// Generate an RSA private key.
    fn generate(size: u32) -> Result<RsaPrivateKey, CryptoError> {
        // Use SymCrypt to generate an RSA public/private key pair
        let key = RsaKey::generate_key_pair(size, None, RsaKeyUsage::SignAndEncrypt).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::RsaGenerateError
            },
        )?;

        Ok(RsaPrivateKey { handle: key })
    }

    fn from_der(
        der: &[u8],
        expected_type: Option<CryptoKeyKind>,
    ) -> Result<RsaPrivateKey, CryptoError> {
        use pkcs1::der::Decode;

        let private_key_info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaFromDerError
        })?;

        let private_key = pkcs1::RsaPrivateKey::from_der(private_key_info.private_key).map_err(
            |error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaFromDerError
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
            CryptoError::RsaFromDerError
        })?;

        match expected_type {
            Some(CryptoKeyKind::Rsa2kPrivate) | Some(CryptoKeyKind::Rsa2kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 256 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa3kPrivate) | Some(CryptoKeyKind::Rsa3kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 384 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            Some(CryptoKeyKind::Rsa4kPrivate) | Some(CryptoKeyKind::Rsa4kPrivateCrt) => {
                if symcrypt_key.get_size_of_modulus() != 512 {
                    Err(CryptoError::DerAndKeyTypeMismatch)?
                }
            }
            None => {}
            _ => Err(CryptoError::DerAndKeyTypeMismatch)?,
        }

        Ok(RsaPrivateKey {
            handle: symcrypt_key,
        })
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        use pkcs1::der::Encode;

        let private_key_blob =
            self.handle
                .export_key_pair_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::RsaToDerError
                })?;

        let modulus = pkcs1::UintRef::new(&private_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&private_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;
        let private_exponent =
            pkcs1::UintRef::new(&private_key_blob.private_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;
        let prime1 = pkcs1::UintRef::new(&private_key_blob.p).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let prime2 = pkcs1::UintRef::new(&private_key_blob.q).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let exponent1 = pkcs1::UintRef::new(&private_key_blob.d_p).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let exponent2 = pkcs1::UintRef::new(&private_key_blob.d_q).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let coefficient =
            pkcs1::UintRef::new(&private_key_blob.crt_coefficient).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
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
            CryptoError::RsaToDerError
        })?;

        let null_param: pkcs8::der::AnyRef<'_> = pkcs8::der::asn1::Null.into(); // This creates a DER-encoded NULL
        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: Some(null_param),
        };

        let private_key_info = pkcs8::PrivateKeyInfo::new(alg_id, &private_key_der);
        let der = private_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;

        Ok(der)
    }

    fn modulus(&self) -> Result<Vec<u8>, CryptoError> {
        let blob = self
            .handle
            .export_key_pair_blob()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::RsaGetModulusError
            })?;
        Ok(blob.modulus)
    }

    fn public_exponent(&self) -> Result<Vec<u8>, CryptoError> {
        let blob = self
            .handle
            .export_key_pair_blob()
            .map_err(|symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::RsaGetModulusError
            })?;
        Ok(blob.pub_exp)
    }

    fn bits(&self) -> u32 {
        self.handle.get_size_of_modulus() * 8
    }
}

#[cfg(feature = "use-symcrypt")]
impl RsaPrivateOp for RsaPrivateKey {
    fn decrypt(
        &self,
        data: &[u8],
        padding: CryptoRsaCryptoPadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        label: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        match padding {
            CryptoRsaCryptoPadding::None => Err(CryptoError::RsaDecryptFailed),
            CryptoRsaCryptoPadding::Oaep => {
                let hash_algo = match hash_algorithm.unwrap_or(CryptoHashAlgorithm::Sha256) {
                    CryptoHashAlgorithm::Sha1 => HashAlgorithm::Sha1,
                    CryptoHashAlgorithm::Sha256 => HashAlgorithm::Sha256,
                    CryptoHashAlgorithm::Sha384 => HashAlgorithm::Sha384,
                    CryptoHashAlgorithm::Sha512 => HashAlgorithm::Sha512,
                };
                let label_param = label.unwrap_or(b"");
                let message = self
                    .handle
                    .oaep_decrypt(data, hash_algo, label_param)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::RsaDecryptFailed
                    })?;
                Ok(message)
            }
        }
    }

    fn extract_pub_key_der(&self) -> Result<Vec<u8>, CryptoError> {
        use pkcs1::der::Encode;

        let public_key_blob =
            self.handle
                .export_public_key_blob()
                .map_err(|symcrypt_error_stack| {
                    tracing::error!(?symcrypt_error_stack);
                    CryptoError::RsaToDerError
                })?;

        let modulus = pkcs1::UintRef::new(&public_key_blob.modulus).map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;
        let public_exponent =
            pkcs1::UintRef::new(&public_key_blob.pub_exp).map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;

        let public_key = pkcs1::RsaPublicKey {
            modulus,
            public_exponent,
        };
        let public_key_der = public_key.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;

        let alg_id = spki::AlgorithmIdentifier {
            oid: RSA_OID,
            parameters: None,
        };

        let public_key_der_bitstring = pkcs1::der::asn1::BitString::from_bytes(&public_key_der)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                CryptoError::RsaToDerError
            })?;
        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: alg_id,
            subject_public_key: public_key_der_bitstring,
        };

        let der = subject_public_key_info.to_der().map_err(|error_stack| {
            tracing::error!(?error_stack);
            CryptoError::RsaToDerError
        })?;

        Ok(der)
    }

    fn sign(
        &self,
        digest: &[u8],
        padding: CryptoRsaSignaturePadding,
        hash_algorithm: Option<CryptoHashAlgorithm>,
        salt_len: Option<u16>,
    ) -> Result<Vec<u8>, CryptoError> {
        let hash_algo = match hash_algorithm {
            Some(CryptoHashAlgorithm::Sha1) => HashAlgorithm::Sha1,
            Some(CryptoHashAlgorithm::Sha256) => HashAlgorithm::Sha256,
            Some(CryptoHashAlgorithm::Sha384) => HashAlgorithm::Sha384,
            Some(CryptoHashAlgorithm::Sha512) => HashAlgorithm::Sha512,
            None => match digest.len() {
                20 => HashAlgorithm::Sha1,
                32 => HashAlgorithm::Sha256,
                48 => HashAlgorithm::Sha384,
                64 => HashAlgorithm::Sha512,
                _ => return Err(CryptoError::RsaSignFailed),
            },
        };
        match padding {
            CryptoRsaSignaturePadding::Pkcs1_5 => {
                let signature =
                    self.handle
                        .pkcs1_sign(digest, hash_algo)
                        .map_err(|symcrypt_error_stack| {
                            tracing::error!(?symcrypt_error_stack);
                            CryptoError::RsaSignFailed
                        })?;
                Ok(signature)
            }
            CryptoRsaSignaturePadding::Pss => {
                let salt_len = salt_len.unwrap_or(digest.len() as u16);
                let signature = self
                    .handle
                    .pss_sign(digest, hash_algo, salt_len as usize)
                    .map_err(|symcrypt_error_stack| {
                        tracing::error!(?symcrypt_error_stack);
                        CryptoError::RsaSignFailed
                    })?;
                Ok(signature)
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_rsa_private_der() {
        let data = [1u8; 128];

        // Generate the key
        let keypair = generate_rsa(2048);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        // Encrypt data with the key
        let result = rsa_public.encrypt(&data, CryptoRsaCryptoPadding::Oaep, None, None);
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Convert the key to der
        let result = rsa_private.to_der();
        assert!(result.is_ok());

        // Convert the der back to key
        let result = RsaPrivateKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Rsa2kPrivate));
        assert!(result.is_ok());
        let rsa_private = result.unwrap();

        // Decrypt data with the key
        let result = rsa_private.decrypt(&encrypted, CryptoRsaCryptoPadding::Oaep, None, None);
        assert!(result.is_ok());
        let decrypted = result.unwrap();

        assert_eq!(data.to_vec(), decrypted);

        // Extract public key in der
        let result = rsa_private.extract_pub_key_der();
        assert!(result.is_ok());

        // Test from_der with rsa public key
        let result = rsa_public.to_der();
        assert!(result.is_ok());

        let result = RsaPrivateKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Rsa2kPrivate));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::RsaFromDerError);
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

        let result = RsaPrivateKey::from_der(&DER_PKCS1, Some(CryptoKeyKind::Rsa2kPrivate));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::RsaFromDerError);
        }
    }

    #[test]
    fn test_rsa_public_der() {
        let data = [1u8; 128];

        // Generate the key
        let keypair = generate_rsa(2048);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        let result = rsa_public.to_der();
        assert!(result.is_ok());

        let result = RsaPublicKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Rsa2kPublic));
        assert!(result.is_ok());
        let rsa_public = result.unwrap();

        // Encrypt data with the key
        let result = rsa_public.encrypt(&data, CryptoRsaCryptoPadding::Oaep, None, None);
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Decrypt data with the key
        let result = rsa_private.decrypt(&encrypted, CryptoRsaCryptoPadding::Oaep, None, None);
        assert!(result.is_ok());
        let decrypted = result.unwrap();

        assert_eq!(data.to_vec(), decrypted);

        // Test from_der with rsa private key
        let result = rsa_private.to_der();
        assert!(result.is_ok());

        let result = RsaPublicKey::from_der(&result.unwrap(), Some(CryptoKeyKind::Rsa2kPublic));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::RsaFromDerError);
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

        let result = RsaPublicKey::from_der(&DER_PKCS1, Some(CryptoKeyKind::Rsa2kPublic));
        assert!(result.is_err(), "result {:?}", result);
        if let Err(error) = result {
            assert_eq!(error, CryptoError::RsaFromDerError);
        }
    }

    // Tests creating an RSA public key from raw modulus and exponent data.
    #[test]
    fn test_rsa_public_from_raw() {
        // Start by generating an RSA public key
        let public_key = RsaPublicKey::generate(2048).expect("Failed to generate RSA public key");

        // Extract the public key's modulus and exponent
        let modulus = public_key
            .modulus()
            .expect("Failed to get public key modulus");
        let exponent = public_key
            .public_exponent()
            .expect("Failed to get public key exponent");

        // Use these to create a new RSA public key, this time using `from_raw()`.
        let new_key_result = RsaPublicKey::from_raw(modulus.as_slice(), exponent.as_slice());
        assert!(
            new_key_result.is_ok(),
            "Failed to create RSA public key from raw data"
        );
    }

    #[test]
    fn test_operations() {
        const KEY_SIZE: usize = 256;

        // Generate the key
        let keypair = generate_rsa((KEY_SIZE * 8) as u32);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        // Encrypt data with padding
        const SHA256_SIZE: usize = 32;
        const PADDING_SIZE: usize = (SHA256_SIZE + 1) * 2;
        let data = [1u8; KEY_SIZE - PADDING_SIZE];
        let result = rsa_public.encrypt(
            &data,
            CryptoRsaCryptoPadding::Oaep,
            Some(CryptoHashAlgorithm::Sha256),
            None,
        );
        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Decrypt data with padding
        let result = rsa_private.decrypt(
            &encrypted,
            CryptoRsaCryptoPadding::Oaep,
            Some(CryptoHashAlgorithm::Sha256),
            None,
        );
        assert!(result.is_ok());
        let decrypted = result.unwrap();
        assert_eq!(data.to_vec(), decrypted);

        // Sign the digest with the key
        const DIGEST_SIZE: usize = 20;
        let digest = [1u8; DIGEST_SIZE];
        let result = rsa_private.sign(&digest, CryptoRsaSignaturePadding::Pss, None, None);
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Verify the signature against the correct digest with the key
        let result = rsa_public.verify(
            &digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok());

        // Verify the signature against the wrong digest with the key
        let digest = [2u8; DIGEST_SIZE];
        let result = rsa_public.verify(
            &digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            None,
            None,
        );
        assert_eq!(result, Err(CryptoError::RsaVerifyFailed));

        // Expect to fail with input size that is not equal to the key size
        let data = [1u8; KEY_SIZE - 1];
        let result = rsa_public.encrypt(&data, CryptoRsaCryptoPadding::Oaep, None, None);
        assert_eq!(result, Err(CryptoError::RsaEncryptFailed));

        let data = [1u8; KEY_SIZE + 1];
        let result = rsa_public.encrypt(&data, CryptoRsaCryptoPadding::Oaep, None, None);
        assert_eq!(result, Err(CryptoError::RsaEncryptFailed));

        let digest = [1u8; DIGEST_SIZE - 1];
        let result = rsa_private.sign(&digest, CryptoRsaSignaturePadding::Pss, None, None);
        assert_eq!(result, Err(CryptoError::RsaSignFailed));

        let digest = [1u8; DIGEST_SIZE + 1];
        let result = rsa_private.sign(&digest, CryptoRsaSignaturePadding::Pss, None, None);
        assert_eq!(result, Err(CryptoError::RsaSignFailed));
    }

    fn rsa_pss_with_parameters(
        rsa_private: &RsaPrivateKey,
        rsa_public: &RsaPublicKey,
        digest_size: usize,
        hash_algorithm: CryptoHashAlgorithm,
        salt_len: u16,
    ) {
        let digest = vec![1u8; digest_size];

        let result = rsa_private.sign(
            &digest,
            CryptoRsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert!(result.is_ok());
        let signature = result.unwrap();

        // Verify the signature against the correct digest with the key
        let result = rsa_public.verify(
            &digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert!(result.is_ok());

        // Verify the signature with the wrong salt length
        let result = rsa_public.verify(
            &digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len + 1),
        );
        assert_eq!(result, Err(CryptoError::RsaVerifyFailed));

        // Verify the signature with the wrong hash algorithm
        let wrong_hash_algorithm = if hash_algorithm == CryptoHashAlgorithm::Sha1 {
            CryptoHashAlgorithm::Sha256
        } else {
            CryptoHashAlgorithm::Sha1
        };
        let result = rsa_public.verify(
            &digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            Some(wrong_hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(CryptoError::RsaVerifyFailed));

        // Verify the signature against the wrong digest with the key
        let wrong_digest = vec![2u8; digest_size];
        let result = rsa_public.verify(
            &wrong_digest,
            &signature,
            CryptoRsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(CryptoError::RsaVerifyFailed));

        // Verify the signature against the wrong signature
        let mut wrong_signature = signature;
        wrong_signature[5] = wrong_signature[5].wrapping_add(1);
        let result = rsa_public.verify(
            &digest,
            &wrong_signature,
            CryptoRsaSignaturePadding::Pss,
            Some(hash_algorithm),
            Some(salt_len),
        );
        assert_eq!(result, Err(CryptoError::RsaVerifyFailed));
    }

    #[test]
    fn test_rsa_pss_with_parameters() {
        const KEY_SIZE: usize = 256;

        // Generate the key
        let keypair = generate_rsa((KEY_SIZE * 8) as u32);
        assert!(keypair.is_ok());
        let (rsa_private, rsa_public) = keypair.unwrap();

        let salt_lens = [0u16, 20, 32, 64, 128];

        for salt_len in salt_lens {
            rsa_pss_with_parameters(
                &rsa_private,
                &rsa_public,
                20,
                CryptoHashAlgorithm::Sha1,
                salt_len,
            );
            rsa_pss_with_parameters(
                &rsa_private,
                &rsa_public,
                32,
                CryptoHashAlgorithm::Sha256,
                salt_len,
            );
            rsa_pss_with_parameters(
                &rsa_private,
                &rsa_public,
                48,
                CryptoHashAlgorithm::Sha384,
                salt_len,
            );
            rsa_pss_with_parameters(
                &rsa_private,
                &rsa_public,
                64,
                CryptoHashAlgorithm::Sha512,
                salt_len,
            );
        }
    }

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
