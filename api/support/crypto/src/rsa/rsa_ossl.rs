// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use std::ffi::c_int;
use std::ptr;

use openssl::encrypt::Decrypter;
use openssl::encrypt::Encrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rand::rand_bytes;
use openssl::rsa::Padding as OsslPadding;
use openssl::rsa::Rsa;
use openssl::sign::RsaPssSaltlen;
use openssl::sign::Verifier;
use openssl_sys::*;

use super::*;
use crate::aes::*;
use crate::sha::*;

/// Wrapper for a Ossl private key handle.
pub struct OsslRsaPrivateKeyHandle {
    ossl_private_key: PKey<Private>,
}

pub struct OsslRsaPublicKeyHandle {
    ossl_public_key: PKey<Public>,
}
impl RsaKeyGenOp for RsaKeyGen {
    /// Generates a new RSA key pair of the specified size.
    ///
    /// # Arguments
    /// * `size` - The size of the key in bits.
    ///
    /// # Returns
    /// * `Ok((RsaPrivateKey, RsaPublicKey))` - The generated private and public keys.
    /// * `Err(CryptoError)` - If key generation fails.
    fn rsa_key_gen_pair(
        &self,
        size: usize,
    ) -> Result<(RsaPrivateKeyHandle, RsaPublicKeyHandle), CryptoError> {
        // Generate a new RSA key pair using OpenSSL
        let rsa = Rsa::generate(size as u32).map_err(|e| {
            tracing::error!("RSA key generation failed: {}", e);
            CryptoError::RsaKeyPairGenFailed
        })?;

        // Get Pkey from the Rsa key pair
        let private_key = PKey::from_rsa(rsa).map_err(|e| {
            tracing::error!("Failed to create PKey from RSA: {}", e);
            CryptoError::RsaKeyPairGenFailed
        })?;

        // Extract public key from private key
        let public_key =
            PKey::public_key_from_pem(&private_key.public_key_to_pem().map_err(|e| {
                tracing::error!("Failed to extract public key PEM: {}", e);
                CryptoError::RsaKeyPairGenFailed
            })?)
            .map_err(|e| {
                tracing::error!("Failed to create PKey<Public> from PEM: {}", e);
                CryptoError::RsaKeyPairGenFailed
            })?;

        tracing::debug!(
            "[KeyGen] Successfully generated RSA key pair with key length: {:?}",
            size
        );
        //return key pair
        Ok((
            RsaPrivateKeyHandle {
                private_key_handle: OsslRsaPrivateKeyHandle {
                    ossl_private_key: private_key,
                },
            },
            RsaPublicKeyHandle {
                public_key_handle: OsslRsaPublicKeyHandle {
                    ossl_public_key: public_key,
                },
            },
        ))
    }
}

impl RsaKeyOps<RsaPrivateKeyHandle> for RsaPrivateKeyHandle {
    /// Creates a key from a DER-encoded byte slice.
    ///
    /// # Arguments
    /// * `der` - DER-encoded key data.
    ///
    /// # Returns
    /// * `Ok(T)` - The constructed key.
    /// * `Err(CryptoError)` - If decoding fails.
    fn rsa_key_from_der(der: &[u8]) -> Result<RsaPrivateKeyHandle, CryptoError> {
        tracing::debug!(
            "[KeyImport] Attempting to import RSA private key from DER ({} bytes)",
            der.len()
        );
        // Try to parse the DER as a PKCS#8 RSA private key
        let pkey = PKey::private_key_from_der(der).map_err(|e| {
            tracing::error!("Failed to parse DER as PKCS#8 RSA private key: {}", e);
            CryptoError::RsaDerDecodeFailed
        })?;
        tracing::debug!("[KeyImport] Successfully imported RSA private key from DER");
        Ok(RsaPrivateKeyHandle {
            private_key_handle: OsslRsaPrivateKeyHandle {
                ossl_private_key: pkey,
            },
        })
    }
    /// Returns the size of the key in bits.
    ///
    /// # Parameters
    /// - `&self`: Reference to the key handle.
    ///
    /// # Returns
    /// - `Ok(usize)`: The size of the key in bits.
    /// - `Err(CryptoError)`: If the key size could not be determined.
    fn size(&self) -> Result<usize, CryptoError> {
        let pkey = &self.private_key_handle.ossl_private_key;
        let rsa = pkey.rsa().map_err(|e| {
            tracing::error!("Failed to extract RSA from PKey<Private> for size: {}", e);
            CryptoError::RsaError
        })?;
        let bits = rsa.size() * 8;
        tracing::debug!("[KeyInfo] RSA key size: {} bits", bits);
        Ok(bits as usize)
    }

    /// Serializes the private key to DER format.
    ///
    /// # Parameters
    /// - `&self`: Reference to the key handle.
    /// - `der`: Output buffer to write the DER-encoded key.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the output buffer.
    /// - `Err(CryptoError)` - If serialization fails or the buffer is too small.
    fn rsa_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        tracing::debug!(
            "[KeyExport] Attempting to export RSA private key to DER (buffer size: {} bytes)",
            der.len()
        );
        // Extract the OpenSSL PKey<Private> from the handle
        let pkey = &self.private_key_handle.ossl_private_key;
        // Export the RSA private key to DER (PKCS#8) - explicit PKCS#8 format
        let der_bytes = pkey.private_key_to_pkcs8().map_err(|e| {
            tracing::error!("Failed to serialize RSA private key to PKCS#8 DER: {}", e);
            CryptoError::RsaDerEncodeFailed
        })?;
        if der.len() < der_bytes.len() {
            tracing::error!(
                "Output buffer too small for DER export: required {}, provided {}",
                der_bytes.len(),
                der.len()
            );
            return Err(CryptoError::RsaDerBufferTooSmall);
        }
        der[..der_bytes.len()].copy_from_slice(&der_bytes);
        tracing::debug!(
            "[KeyExport] Successfully exported RSA private key to DER ({} bytes)",
            der_bytes.len()
        );
        Ok(der_bytes.len())
    }
    /// Returns the maximum size of the DER-encoded private key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum size in bytes needed for DER encoding.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_get_key_der_size(&self) -> Result<usize, CryptoError> {
        // Conservative estimate: DER encoding of PKCS#8 RSA private key is always less than this.
        // For n-bit key, PKCS#8 format includes algorithm identifiers and structure overhead.
        // PKCS#8 has more overhead than PKCS#1, so we need a larger estimate.
        let key_bits = self.size()?;
        let modulus_bytes = key_bits.div_ceil(8);
        // PKCS#8 private key has algorithm identifier + PKCS#1 private key wrapped.
        // Add 128 bytes for PKCS#8 overhead (algorithm identifiers, headers, etc).
        let estimated = 8 * (modulus_bytes + 8) + 128;
        Ok(estimated)
    }
}

impl RsaKeyOps<RsaPublicKeyHandle> for RsaPublicKeyHandle {
    /// Creates a key from a DER-encoded byte slice.
    ///
    /// # Arguments
    /// * `der` - DER-encoded public key data.
    ///
    /// # Returns
    /// * `Ok(RsaPublicKeyHandle)` - The constructed public key handle.
    /// * `Err(CryptoError)` - If decoding or import fails.
    fn rsa_key_from_der(der: &[u8]) -> Result<RsaPublicKeyHandle, CryptoError> {
        tracing::debug!(
            "[KeyImport] Attempting to import RSA public key from DER ({} bytes)",
            der.len()
        );
        // Try to parse the DER as a PKCS#8 RSA public key (SubjectPublicKeyInfo)
        let pkey = PKey::public_key_from_der(der).map_err(|e| {
            tracing::error!("Failed to parse DER as PKCS#8 RSA public key: {}", e);
            CryptoError::RsaDerDecodeFailed
        })?;
        tracing::debug!("[KeyImport] Successfully imported RSA public key from DER");
        Ok(RsaPublicKeyHandle {
            public_key_handle: OsslRsaPublicKeyHandle {
                ossl_public_key: pkey,
            },
        })
    }
    /// Serializes the public key to DER format.
    ///
    /// # Arguments
    /// * `&self` - Reference to the public key handle.
    /// * `der` - Output buffer to write the DER-encoded public key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to the output buffer.
    /// * `Err(CryptoError)` - If serialization fails or the buffer is too small.
    fn rsa_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        tracing::debug!(
            "[KeyExport] Attempting to export RSA public key to DER (buffer size: {} bytes)",
            der.len()
        );
        let pkey = &self.public_key_handle.ossl_public_key;
        // Export the RSA public key to DER (SubjectPublicKeyInfo format)
        let der_bytes = pkey.public_key_to_der().map_err(|e| {
            tracing::error!("Failed to serialize RSA public key to PKCS#8 DER: {}", e);
            CryptoError::RsaDerEncodeFailed
        })?;
        if der.len() < der_bytes.len() {
            tracing::error!(
                "Output buffer too small for DER export: required {}, provided {}",
                der_bytes.len(),
                der.len()
            );
            return Err(CryptoError::RsaDerBufferTooSmall);
        }
        der[..der_bytes.len()].copy_from_slice(&der_bytes);
        tracing::debug!(
            "[KeyExport] Successfully exported RSA public key to DER ({} bytes)",
            der_bytes.len()
        );
        Ok(der_bytes.len())
    }

    /// Returns the size of the key in bits.
    ///
    /// # Parameters
    /// - `&self`: Reference to the key handle.
    ///
    /// # Returns
    /// - `Ok(usize)`: The size of the key in bits.
    /// - `Err(CryptoError)`: If the key size could not be determined.
    fn size(&self) -> Result<usize, CryptoError> {
        let pkey = &self.public_key_handle.ossl_public_key;
        let rsa = pkey.rsa().map_err(|e| {
            tracing::error!("Failed to extract RSA from PKey<Public> for size: {}", e);
            CryptoError::RsaError
        })?;
        let bits = rsa.size() * 8;
        tracing::debug!("[KeyInfo] RSA public key size: {} bits", bits);
        Ok(bits as usize)
    }
    /// Returns the size of the estimated RSA public key der in bytes.
    ///
    /// # Returns
    /// * `Ok(usize)` - The size of the key in bits.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_get_key_der_size(&self) -> Result<usize, CryptoError> {
        // Estimate the maximum DER-encoded size for a PKCS#8 RSA public key (SubjectPublicKeyInfo).
        // For n-bit key, this includes algorithm identifier + PKCS#1 public key.
        // PKCS#8 public key format has more overhead than raw PKCS#1.
        let key_bits = self.size()?;
        let modulus_bytes = key_bits.div_ceil(8);
        // SubjectPublicKeyInfo has algorithm identifier + BIT STRING wrapper + PKCS#1 public key.
        // Add 64 bytes for PKCS#8 headers/tags, algorithm identifier, and 8 bytes for exponent.
        let estimated = modulus_bytes + 8 + 64;
        Ok(estimated)
    }
}

impl RsaPublicKeyOp for RsaPublicKeyHandle {
    /// Encrypts the given data using the specified padding, hash algorithm, and optional label.
    ///
    /// # Arguments
    /// * `data` - The plaintext data to encrypt.
    /// * `padding` - The padding scheme to use (e.g., OAEP).
    /// * `hash_algo` - The hash algorithm to use (if applicable).
    /// * `label` - Optional label for OAEP padding.
    /// * `cipher_data` - Output buffer for the encrypted data.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to `cipher_data` on success.
    /// * `Err(CryptoError)` - If encryption fails.
    fn rsa_encrypt<'a>(
        &self,
        data: &[u8],
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        cipher_data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        tracing::debug!(
            "[Encrypt] Encrypting data ({} bytes) with RSA public key",
            data.len()
        );
        let pkey = &self.public_key_handle.ossl_public_key;
        let mut encrypter = Encrypter::new(pkey).map_err(|e| {
            tracing::error!("Failed to create Encrypter: {}", e);
            CryptoError::RsaError
        })?;
        match padding {
            RsaCryptPadding::None => {
                encrypter
                    .set_rsa_padding(openssl::rsa::Padding::NONE)
                    .map_err(|e| {
                        tracing::error!("Failed to set NONE padding: {}", e);
                        CryptoError::RsaError
                    })?;
            }
            RsaCryptPadding::Oaep => {
                encrypter
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
                    .map_err(|e| {
                        tracing::error!("Failed to set OAEP padding: {}", e);
                        CryptoError::RsaError
                    })?;
                // Set OAEP hash algorithm
                let md = match hash_algo {
                    HashAlgo::Sha1 => MessageDigest::sha1(),
                    HashAlgo::Sha256 => MessageDigest::sha256(),
                    HashAlgo::Sha384 => MessageDigest::sha384(),
                    HashAlgo::Sha512 => MessageDigest::sha512(),
                };
                encrypter.set_rsa_oaep_md(md).map_err(|e| {
                    tracing::error!("Failed to set OAEP hash: {}", e);
                    CryptoError::RsaError
                })?;
                // Set OAEP label if provided and non-empty
                if let Some(l) = label {
                    if !l.is_empty() {
                        encrypter.set_rsa_oaep_label(l).map_err(|e| {
                            tracing::error!("Failed to set OAEP label: {}", e);
                            CryptoError::RsaError
                        })?;
                    }
                }
            }
        }
        if data.is_empty() {
            tracing::error!("Input data to encrypt is empty");
            return Err(CryptoError::RsaEncryptInputEmpty);
        }
        if cipher_data.is_empty() {
            tracing::error!("Output buffer for cipher data is empty");
            return Err(CryptoError::RsaEncryptOutputBufferEmpty);
        }
        let required_len = encrypter.encrypt_len(data).map_err(|e| {
            tracing::error!("Failed to get required encrypted length: {}", e);
            CryptoError::RsaEncryptGetCipherLenFailed
        })?;
        if cipher_data.len() < required_len {
            tracing::error!(
                "Output buffer for cipher data is too small: required {}, provided {}",
                required_len,
                cipher_data.len()
            );
            return Err(CryptoError::RsaEncryptOutputBufferTooSmall);
        }
        let len = encrypter.encrypt(data, cipher_data).map_err(|e| {
            tracing::error!("RSA encryption failed: {}", e);
            CryptoError::RsaEncryptFailed
        })?;
        tracing::debug!("[Encrypt] Successfully encrypted data ({} bytes)", len);
        Ok(&cipher_data[..len])
    }

    /// Verifies the given signature for the provided data using the specified padding, hash algorithm, and optional salt size.
    ///
    /// # Arguments
    /// * `data` - The data whose signature is to be verified.
    /// * `padding` - The signature padding scheme (e.g., PSS, PKCS1_5).
    /// * `hash_algo` - The hash algorithm to use.
    /// * `salt_size` - Optional salt size for PSS padding.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails.
    fn rsa_verify(
        &self,
        data: &[u8],
        padding: RsaSignaturePadding,
        hash_algo: HashAlgo,
        salt_len: Option<usize>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let pkey = &self.public_key_handle.ossl_public_key;
        let mut verifier = Verifier::new(
            match hash_algo {
                HashAlgo::Sha1 => MessageDigest::sha1(),
                HashAlgo::Sha256 => MessageDigest::sha256(),
                HashAlgo::Sha384 => MessageDigest::sha384(),
                HashAlgo::Sha512 => MessageDigest::sha512(),
            },
            pkey,
        )
        .map_err(|e| {
            tracing::error!("Failed to create Verifier: {}", e);
            CryptoError::RsaSignatureVerifierCreateFailed
        })?;

        match padding {
            RsaSignaturePadding::Pkcs1_5 => {
                verifier.set_rsa_padding(OsslPadding::PKCS1).map_err(|e| {
                    tracing::error!("Failed to set PKCS1 padding: {}", e);
                    CryptoError::RsaSignatureSetPaddingFailed
                })?;
            }
            RsaSignaturePadding::Pss => {
                verifier
                    .set_rsa_padding(OsslPadding::PKCS1_PSS)
                    .map_err(|e| {
                        tracing::error!("Failed to set PSS padding: {}", e);
                        CryptoError::RsaSignatureSetPaddingFailed
                    })?;
                let salt_len = match salt_len {
                    Some(salt_len) => salt_len,
                    None => {
                        tracing::error!("Salt length must be provided for PSS padding");
                        return Err(CryptoError::RsaPssSaltlenInvalid);
                    }
                };
                let modulus_bits = self.size()?;
                let pss_saltlen = get_pss_saltlen(salt_len, hash_algo, modulus_bits)?;
                verifier.set_rsa_pss_saltlen(pss_saltlen).map_err(|e| {
                    tracing::error!("Failed to set PSS salt length: {}", e);
                    CryptoError::RsaSignatureSetPssSaltlenFailed
                })?;
            }
        }

        verifier.update(data).map_err(|e| {
            tracing::error!("Failed to update verifier with data: {}", e);
            CryptoError::RsaSignatureVerifierUpdateFailed
        })?;
        let verified = verifier.verify(signature).map_err(|e| {
            tracing::error!("Signature verification failed: {}", e);
            CryptoError::RsaSignatureFailed
        })?;
        if verified {
            Ok(())
        } else {
            tracing::error!("Signature verification failed: signature is invalid");
            Err(CryptoError::RsaSignatureInvalid)
        }
    }
    /// Returns the required output buffer size for RSA encryption with the given parameters.
    ///
    /// # Arguments
    /// * `data_len` - Length of the plaintext data to encrypt.
    /// * `padding` - The padding scheme to use (e.g., OAEP).
    /// * `hash_algo` - The hash algorithm to use (if applicable).
    /// * `label` - Optional label for OAEP padding.
    ///
    /// # Note
    /// The output length for RSA encryption is always the modulus size in bytes, regardless of input data length or padding.
    /// See: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    ///
    /// These parameters are accepted for API compatibility and future-proofing, as some cryptographic backends or algorithms
    /// may require them to determine the output length. For OpenSSL and standard RSA, the output length is always the modulus size.
    ///
    /// # Returns
    /// * `Ok(usize)` - The required output buffer size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn rsa_encrypt_len(
        &self,
        data_len: usize,
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
    ) -> Result<usize, CryptoError> {
        let pkey = &self.public_key_handle.ossl_public_key;
        let modulus_size = pkey
            .rsa()
            .map_err(|e| {
                tracing::error!(
                    "Failed to extract RSA from PKey<Public> for modulus size: {}",
                    e
                );
                CryptoError::RsaError
            })?
            .size() as usize;
        match padding {
            RsaCryptPadding::Oaep => {
                let hash_len = match hash_algo {
                    HashAlgo::Sha1 => 20,
                    HashAlgo::Sha256 => 32,
                    HashAlgo::Sha384 => 48,
                    HashAlgo::Sha512 => 64,
                };
                let max_input = modulus_size - 2 * hash_len - 2;
                if data_len > max_input {
                    tracing::error!("OAEP input too large: {} > {}", data_len, max_input);
                    return Err(CryptoError::RsaEncryptInputTooLarge);
                }
                Ok(modulus_size)
            }
            RsaCryptPadding::None => {
                if data_len > modulus_size {
                    tracing::error!("Raw RSA input too large: {} > {}", data_len, modulus_size);
                    return Err(CryptoError::RsaEncryptInputTooLarge);
                }
                Ok(modulus_size)
            }
        }
    }

    /// Wraps user data using hybrid encryption: AES session key + RSA OAEP.
    ///
    /// This function implements a hybrid encryption scheme:
    /// 1. Generate a random AES session key of the specified size
    /// 2. Generate a random 16-byte IV
    /// 3. Encrypt the user data using AES-CBC with PKCS#7 padding
    /// 4. Encrypt the AES session key using RSA OAEP
    /// 5. Return a blob containing: [RSA-encrypted AES key | IV | AES-encrypted data]
    ///
    /// # Arguments
    /// * `user_data` - The user data to wrap.
    /// * `aes_key_size` - The size of the AES session key to generate.
    /// * `hash_algo` - The OAEP hash algorithm for RSA encryption.
    /// * `label` - Optional OAEP label.
    /// * `wrapped_data` - Output buffer for the complete wrapped blob.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The wrapped blob bytes.
    /// * `Err(CryptoError)` - If wrapping fails.
    fn rsa_wrap<'a>(
        &self,
        user_data: &[u8],
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        wrapped_data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        tracing::debug!(
            "[Wrap] Wrapping user data ({} bytes) with RSA wrap encryption",
            user_data.len()
        );

        // Input validation
        if user_data.is_empty() {
            tracing::error!("User data to wrap is empty");
            return Err(CryptoError::RsaWrapInputEmpty);
        }

        // Step 1: Generate random AES KEK (Key Encryption Key)
        let aes_key_len = aes_key_size.key_len();
        let mut aes_kek = vec![0u8; aes_key_len];
        rand_bytes(&mut aes_kek).map_err(|e| {
            tracing::error!("Failed to generate random AES KEK: {}", e);
            CryptoError::AesKeyGenError
        })?;

        // Step 2: Encrypt user data with AES Key Wrap 2 (RFC 5649)
        let wrapped_user_data = aes_kw2_wrap_ossl(user_data, &aes_kek)?;

        // Step 3: Encrypt the AES KEK with RSA OAEP
        let rsa_modulus_size =
            self.rsa_encrypt_len(aes_key_len, RsaCryptPadding::Oaep, hash_algo)?;
        let mut encrypted_aes_kek = vec![0u8; rsa_modulus_size];
        let encrypted_kek_slice = self.rsa_encrypt(
            &aes_kek,
            RsaCryptPadding::Oaep,
            hash_algo,
            label,
            &mut encrypted_aes_kek,
        )?;

        // Calculate the total blob size: [RSA-encrypted AES KEK | AES-KW2 wrapped data]
        let encrypted_kek_len = encrypted_kek_slice.len();
        let wrapped_data_len = wrapped_user_data.len();
        let total_len = encrypted_kek_len + wrapped_data_len;

        if wrapped_data.len() < total_len {
            tracing::error!(
                "Output buffer too small: need {} bytes, got {}",
                total_len,
                wrapped_data.len()
            );
            return Err(CryptoError::RsaWrapOutputBufferTooSmall);
        }

        // Step 4: Build the blob: [RSA-encrypted AES KEK | AES-KW2 wrapped data]
        let mut offset = 0;

        // Copy RSA-encrypted AES KEK
        wrapped_data[offset..offset + encrypted_kek_len].copy_from_slice(encrypted_kek_slice);
        offset += encrypted_kek_len;

        // Copy AES Key Wrap 2 encrypted data
        wrapped_data[offset..offset + wrapped_data_len].copy_from_slice(&wrapped_user_data);

        // Security: Zero out the AES KEK from memory after use
        aes_kek.fill(0);

        tracing::debug!(
            "[Wrap] Successfully created wrapped blob ({} bytes): RSA KEK={}, AES-KW2 data={}",
            total_len,
            encrypted_kek_len,
            wrapped_data_len
        );

        Ok(&wrapped_data[..total_len])
    }

    /// Returns the required output buffer size for RSA wrapping.
    ///
    /// # Arguments
    /// * `user_data_len` - Length of the user data to wrap.
    /// * `aes_key_size` - The size of the AES session key.
    /// * `hash_algo` - The OAEP hash algorithm.
    ///
    /// # Returns
    /// * `Ok(usize)` - The required output buffer size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn rsa_wrap_len(
        &self,
        user_data_len: usize,
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
    ) -> Result<usize, CryptoError> {
        // Get the AES key length to use for RSA encryption length calculation
        let aes_key_len = aes_key_size.key_len();

        // RSA-encrypted AES KEK size (always modulus size)
        let rsa_encrypted_kek_len =
            self.rsa_encrypt_len(aes_key_len, RsaCryptPadding::Oaep, hash_algo)?;

        // AES Key Wrap 2 output size (RFC 5649): padded to 8-byte boundary + 8 bytes ICV
        let padded_len = user_data_len.div_ceil(8) * 8; // Round up to 8-byte boundary
        let aes_kw2_wrapped_size = padded_len + 8;

        Ok(rsa_encrypted_kek_len + aes_kw2_wrapped_size)
    }
}

impl RsaPrivateKeyOp for RsaPrivateKeyHandle {
    /// Decrypts the given cipher data using the specified padding, hash algorithm, and optional label.
    ///
    /// # Arguments
    /// * `cipher_data` - The encrypted data to decrypt.
    /// * `padding` - The padding scheme to use (e.g., OAEP).
    /// * `hash_algo` - The hash algorithm to use (if applicable).
    /// * `label` - Optional label for OAEP padding.
    /// * `data` - Output buffer for the decrypted data.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to `data` on success.
    /// * `Err(CryptoError)` - If decryption fails.
    fn rsa_decrypt<'a>(
        &self,
        cipher_data: &[u8],
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        tracing::debug!(
            "[Decrypt] Decrypting data ({} bytes) with RSA private key",
            cipher_data.len()
        );
        let pkey = &self.private_key_handle.ossl_private_key;
        let mut decrypter = Decrypter::new(pkey).map_err(|e| {
            tracing::error!("Failed to create Decrypter: {}", e);
            CryptoError::RsaError
        })?;
        match padding {
            RsaCryptPadding::None => {
                decrypter
                    .set_rsa_padding(openssl::rsa::Padding::NONE)
                    .map_err(|e| {
                        tracing::error!("Failed to set NONE padding: {}", e);
                        CryptoError::RsaError
                    })?;
            }
            RsaCryptPadding::Oaep => {
                decrypter
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
                    .map_err(|e| {
                        tracing::error!("Failed to set OAEP padding: {}", e);
                        CryptoError::RsaError
                    })?;
                // Set OAEP hash algorithm
                let md = match hash_algo {
                    HashAlgo::Sha1 => MessageDigest::sha1(),
                    HashAlgo::Sha256 => MessageDigest::sha256(),
                    HashAlgo::Sha384 => MessageDigest::sha384(),
                    HashAlgo::Sha512 => MessageDigest::sha512(),
                };
                decrypter.set_rsa_oaep_md(md).map_err(|e| {
                    tracing::error!("Failed to set OAEP hash: {}", e);
                    CryptoError::RsaError
                })?;
                // Set OAEP label if provided and non-empty
                if let Some(l) = label {
                    if !l.is_empty() {
                        decrypter.set_rsa_oaep_label(l).map_err(|e| {
                            tracing::error!("Failed to set OAEP label: {}", e);
                            CryptoError::RsaError
                        })?;
                    }
                }
            }
        }
        if cipher_data.is_empty() {
            tracing::error!("Input cipher data to decrypt is empty");
            return Err(CryptoError::RsaDecryptInputEmpty);
        }
        if data.is_empty() {
            tracing::error!("Output buffer for decrypted data is empty");
            return Err(CryptoError::RsaDecryptOutputBufferEmpty);
        }
        let required_len = decrypter.decrypt_len(cipher_data).map_err(|e| {
            tracing::error!("Failed to get required decrypted length: {}", e);
            CryptoError::RsaDecryptGetPlainLenFailed
        })?;
        if data.len() < required_len {
            tracing::error!(
                "Output buffer for decrypted data is too small: required {}, provided {}",
                required_len,
                data.len()
            );
            return Err(CryptoError::RsaDecryptOutputBufferTooSmall);
        }
        let len = decrypter.decrypt(cipher_data, data).map_err(|e| {
            tracing::error!("RSA decryption failed: {}", e);
            CryptoError::RsaDecryptFailed
        })?;
        tracing::debug!("[Decrypt] Successfully decrypted data ({} bytes)", len);
        Ok(&data[..len])
    }

    /// Signs the given data using the specified padding, hash algorithm, and optional salt size.
    ///
    /// # Arguments
    /// * `data` - The data to sign.
    /// * `padding` - The signature padding scheme (e.g., PSS, PKCS1_5).
    /// * `hash_algo` - The hash algorithm to use.
    /// * `salt_size` - Optional salt size for PSS padding.
    /// * `signature` - Output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(usize)` - The number of bytes written to `signature` on success.
    /// * `Err(CryptoError)` - If signing fails.
    fn rsa_sign<'a>(
        &self,
        data: &[u8],
        padding: RsaSignaturePadding,
        hash_algo: HashAlgo,
        salt_len: Option<usize>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let pkey = &self.private_key_handle.ossl_private_key;
        let mut signer = openssl::sign::Signer::new(
            match hash_algo {
                HashAlgo::Sha1 => MessageDigest::sha1(),
                HashAlgo::Sha256 => MessageDigest::sha256(),
                HashAlgo::Sha384 => MessageDigest::sha384(),
                HashAlgo::Sha512 => MessageDigest::sha512(),
            },
            pkey,
        )
        .map_err(|e| {
            tracing::error!("Failed to create Signer: {}", e);
            CryptoError::RsaSignatureVerifierCreateFailed
        })?;

        match padding {
            RsaSignaturePadding::Pkcs1_5 => {
                signer.set_rsa_padding(OsslPadding::PKCS1).map_err(|e| {
                    tracing::error!("Failed to set PKCS1 padding: {}", e);
                    CryptoError::RsaSignatureSetPaddingFailed
                })?;
            }
            RsaSignaturePadding::Pss => {
                signer
                    .set_rsa_padding(OsslPadding::PKCS1_PSS)
                    .map_err(|e| {
                        tracing::error!("Failed to set PSS padding: {}", e);
                        CryptoError::RsaSignatureSetPaddingFailed
                    })?;
                let salt_len = match salt_len {
                    Some(salt_len) => salt_len,
                    None => {
                        tracing::error!("Salt length must be provided for PSS padding");
                        return Err(CryptoError::RsaPssSaltlenInvalid);
                    }
                };
                let modulus_bits = self.size()?;
                // check is salt len is valid
                let pss_saltlen = get_pss_saltlen(salt_len, hash_algo, modulus_bits)?;
                signer.set_rsa_pss_saltlen(pss_saltlen).map_err(|e| {
                    tracing::error!("Failed to set PSS salt length: {}", e);
                    CryptoError::RsaSignatureSetPssSaltlenFailed
                })?;
            }
        }

        signer.update(data).map_err(|e| {
            tracing::error!("Failed to update signer with data: {}", e);
            CryptoError::RsaSignatureVerifierUpdateFailed
        })?;
        let sig = signer.sign_to_vec().map_err(|e| {
            tracing::error!("RSA signing failed: {}", e);
            CryptoError::RsaSignatureFailed
        })?;
        if signature.len() < sig.len() {
            tracing::error!(
                "Output buffer for signature is too small: required {}, provided {}",
                sig.len(),
                signature.len()
            );
            return Err(CryptoError::RsaSignOutputBufferTooSmall);
        }
        signature[..sig.len()].copy_from_slice(&sig);
        tracing::debug!("[Sign] Successfully signed data ({} bytes)", sig.len());
        Ok(&signature[..sig.len()])
    }

    /// Returns the maximum size of the signature for this RSA private key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum size in bytes of the signature.
    /// * `Err(CryptoError)` - If the signature size cannot be determined.
    fn rsa_max_signature_len(&self) -> Result<usize, CryptoError> {
        self.modulus_size_bytes()
    }

    /// Returns the maximum size of the decrypted data for this RSA private key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum size in bytes of the decrypted data.
    /// * `Err(CryptoError)` - If the decrypt size cannot be determined.
    fn rsa_max_decrypt_len(&self) -> Result<usize, CryptoError> {
        self.modulus_size_bytes()
    }

    /// Unwraps user data using hybrid decryption: RSA OAEP + AES session key.
    ///
    /// This function reverses the hybrid encryption scheme:
    /// 1. Parse the wrapped blob: [RSA-encrypted AES key | IV | AES-encrypted data]
    /// 2. Decrypt the AES session key using RSA OAEP
    /// 3. Decrypt the user data using AES-CBC with PKCS#7 padding
    /// 4. Return the original user data
    ///
    /// # Arguments
    /// * `wrapped_blob` - The complete wrapped blob from `rsa_wrap`.
    /// * `aes_key_size` - The size of the AES session key used.
    /// * `hash_algo` - The OAEP hash algorithm used for RSA decryption.
    /// * `label` - Optional OAEP label (must match the one used in wrapping).
    /// * `unwrapped_data` - Output buffer for the unwrapped user data.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The unwrapped user data bytes.
    /// * `Err(CryptoError)` - If unwrapping fails.
    fn rsa_unwrap<'a>(
        &self,
        wrapped_blob: &[u8],
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        unwrapped_data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        tracing::debug!(
            "[Unwrap] Unwrapping blob ({} bytes) with RSA unwrap decryption",
            wrapped_blob.len()
        );

        // Calculate expected component sizes
        let rsa_modulus_size = self.rsa_max_decrypt_len()?;
        let aes_key_len = aes_key_size.key_len();

        // Validate minimum blob size: RSA key + at least one AES block
        let min_blob_size = rsa_modulus_size + 16; // minimum 1 AES block for encrypted data
        if wrapped_blob.is_empty() {
            tracing::error!("Wrapped blob is empty");
            return Err(CryptoError::RsaUnwrapInputEmpty);
        }
        if wrapped_blob.len() < min_blob_size {
            tracing::error!(
                "Wrapped blob too small: {} bytes, expected at least {}",
                wrapped_blob.len(),
                min_blob_size
            );
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        // Step 1: Parse the blob: [RSA-encrypted AES key | AES-encrypted data]
        let mut offset = 0;

        // Extract RSA-encrypted session key
        let encrypted_key = &wrapped_blob[offset..offset + rsa_modulus_size];
        offset += rsa_modulus_size;

        // Extract AES-encrypted data (remainder of the blob)
        let encrypted_data = &wrapped_blob[offset..];

        // Step 2: Decrypt the AES session key using RSA OAEP
        let mut temp_buffer = vec![0u8; rsa_modulus_size];
        let decrypted_key_slice = self.rsa_decrypt(
            encrypted_key,
            RsaCryptPadding::Oaep,
            hash_algo,
            label,
            &mut temp_buffer,
        )?;

        // Validate the decrypted AES key length
        if decrypted_key_slice.len() != aes_key_len {
            tracing::error!(
                "Decrypted AES key length mismatch: expected {} bytes for {:?}, got {}",
                aes_key_len,
                aes_key_size,
                decrypted_key_slice.len()
            );
            return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
        }

        // Step 3: Unwrap the user data using AES Key Wrap 2 (RFC 5649)
        let unwrapped_len = aes_kw2_unwrap_ossl(
            decrypted_key_slice,
            encrypted_data,
            unwrapped_data,
            aes_key_size,
        )?;

        // Security: Zero out the temporary buffer containing the decrypted AES key
        temp_buffer.fill(0);

        tracing::debug!(
            "[Unwrap] Successfully unwrapped user data ({} bytes)",
            unwrapped_len
        );

        Ok(&unwrapped_data[..unwrapped_len])
    }

    /// Returns the maximum size of the unwrapped user data buffer required.
    ///
    /// # Arguments
    /// * `wrapped_blob_len` - Length of the wrapped blob.
    /// * `aes_key_size` - The size of the AES session key used.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum unwrapped data size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn rsa_unwrap_len(
        &self,
        wrapped_blob_len: usize,
        _aes_key_size: AesKeySize,
    ) -> Result<usize, CryptoError> {
        // Calculate component sizes
        let rsa_modulus_size = self.rsa_max_decrypt_len()?;

        // Validate minimum blob size for AES-KW2
        let min_blob_size = rsa_modulus_size + 16; // RSA key + at least 8 bytes data + 8 bytes ICV
        if wrapped_blob_len < min_blob_size {
            tracing::error!(
                "Invalid wrapped blob length: {} bytes, expected at least {}",
                wrapped_blob_len,
                min_blob_size
            );
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        // The AES-KW2 wrapped data length is the remainder after RSA key
        let aes_kw2_data_len = wrapped_blob_len - rsa_modulus_size;

        // Maximum possible user data length for AES-KW2 (subtract 8-byte ICV)
        // AES-KW2 adds exactly 8 bytes overhead (ICV)
        if aes_kw2_data_len < 8 {
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        Ok(aes_kw2_data_len - 8)
    }
}

impl RsaPrivateKeyHandle {
    /// Returns the modulus size in bytes for this RSA private key.
    fn modulus_size_bytes(&self) -> Result<usize, CryptoError> {
        let pkey = &self.private_key_handle.ossl_private_key;
        let rsa = pkey.rsa().map_err(|e| {
            tracing::error!(
                "Failed to extract RSA from PKey<Private> for modulus size: {}",
                e
            );
            CryptoError::RsaError
        })?;
        Ok(rsa.size() as usize)
    }
}

/// Computes a valid OpenSSL RsaPssSaltlen for a given salt length, hash algorithm, and RSA modulus size.
///
/// # Parameters
/// - `salt_len`: Desired salt length in bytes for PSS signature.
/// - `hash_algo`: Hash algorithm used for PSS (determines hash output length).
/// - `modulus_bits`: RSA modulus size in bits (e.g., 2048 for a 2048-bit key).
///
/// # Returns
/// - `Ok(RsaPssSaltlen)`: If the salt length is valid for the given modulus and hash.
/// - `Err(CryptoError)`: If the salt length is not allowed by the equation below or hash is unsupported.
fn get_pss_saltlen(
    salt_len: usize,
    hash_algo: HashAlgo,
    modulus_bits: usize,
) -> Result<RsaPssSaltlen, CryptoError> {
    let hash_len = match hash_algo {
        HashAlgo::Sha1 => 20,
        HashAlgo::Sha256 => 32,
        HashAlgo::Sha384 => 48,
        HashAlgo::Sha512 => 64,
    };
    // # Equation
    // The maximum allowed salt length for RSA-PSS is:
    //
    //     saltLen ≤ k - hLen - 2
    //
    // where:
    //   - `k` = RSA modulus length in bytes = (modulus_bits + 7) / 8
    //   - `hLen` = hash output length in bytes (e.g., 32 for SHA-256)
    //
    // This ensures the encoded message fits the modulus as required by PKCS#1 v2.2 and FIPS 186-4.
    let k = modulus_bits.div_ceil(8); // modulus length in bytes
    if k < hash_len + 2 {
        tracing::error!(
            "RSA modulus too small for PSS: modulus_bytes={} hash_len={}",
            k,
            hash_len
        );
        return Err(CryptoError::RsaPssSaltlenInvalid);
    }
    let max_salt = k - hash_len - 2;
    if salt_len > max_salt {
        tracing::error!(
            "PSS salt length {} exceeds max allowed {} for modulus {} bits and {:?}",
            salt_len,
            max_salt,
            modulus_bits,
            hash_algo
        );
        return Err(CryptoError::RsaPssSaltlenInvalid);
    }
    Ok(RsaPssSaltlen::custom(salt_len as i32))
}

/// AES Key Wrap 2 (RFC 5649) encryption using OpenSSL native implementation
///
/// # Arguments
/// * `user_data` - The plaintext data to wrap
/// * `aes_key` - The AES Key Encryption Key (KEK)
///
/// # Returns
/// * `Ok(Vec<u8>)` - The wrapped data
/// * `Err(CryptoError)` - If wrapping fails
#[allow(unsafe_code)]
fn aes_kw2_wrap_ossl(user_data: &[u8], aes_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if user_data.is_empty() {
        return Err(CryptoError::RsaWrapInputEmpty);
    }
    //SAFETY: AES Key Wrap requires at least 1 block (8 bytes) of data
    unsafe {
        // Create cipher context
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(CryptoError::RsaWrapAesEncryptFailed);
        }

        let result = (|| {
            // Select appropriate AES-WRAP-PAD cipher based on key size
            let cipher = match aes_key.len() {
                16 => EVP_aes_128_wrap_pad(),
                24 => EVP_aes_192_wrap_pad(),
                32 => EVP_aes_256_wrap_pad(),
                _ => return Err(CryptoError::RsaWrapAesEncryptFailed),
            };

            if cipher.is_null() {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            // Initialize encryption
            let ret =
                EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), aes_key.as_ptr(), ptr::null());
            if ret != 1 {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            // AES Key Wrap can expand by up to 8 bytes (64 bits)
            let mut outbuf = vec![0u8; user_data.len() + 16]; // Extra space for safety
            let mut outlen: c_int = 0;

            // Perform encryption
            let ret = EVP_EncryptUpdate(
                ctx,
                outbuf.as_mut_ptr(),
                &mut outlen,
                user_data.as_ptr(),
                user_data.len() as c_int,
            );
            if ret != 1 {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            let mut tmplen: c_int = 0;
            // Bounds check before pointer arithmetic
            if (outlen as usize) >= outbuf.len() {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            let ret =
                EVP_EncryptFinal_ex(ctx, outbuf.as_mut_ptr().add(outlen as usize), &mut tmplen);
            if ret != 1 {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            let total_len = outlen + tmplen;
            if total_len < 0 || total_len as usize > outbuf.len() {
                return Err(CryptoError::RsaWrapAesEncryptFailed);
            }

            outbuf.truncate(total_len as usize);
            Ok(outbuf)
        })();

        // Cleanup
        EVP_CIPHER_CTX_free(ctx);
        result
    }
}

/// AES Key Wrap 2 (RFC 5649) decryption using OpenSSL native implementation
///
/// # Arguments
/// * `aes_key` - The AES Key Encryption Key (KEK)
/// * `wrapped_data` - The wrapped data to unwrap
/// * `output` - Output buffer for unwrapped data
/// * `aes_key_size` - The AES key size (for validation)
///
/// # Returns
/// * `Ok(usize)` - The length of unwrapped data
/// * `Err(CryptoError)` - If unwrapping fails
#[allow(unsafe_code)]
fn aes_kw2_unwrap_ossl(
    aes_key: &[u8],
    wrapped_data: &[u8],
    output: &mut [u8],
    _aes_key_size: AesKeySize,
) -> Result<usize, CryptoError> {
    if wrapped_data.is_empty() || wrapped_data.len() < 16 {
        return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
    }
    //SAFETY: AES Key Wrap requires at least 1 block (8 bytes) of data
    unsafe {
        // Create cipher context
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(CryptoError::RsaUnwrapAesDecryptFailed);
        }

        let result = (|| {
            // Select appropriate AES-WRAP-PAD cipher based on key size
            let cipher = match aes_key.len() {
                16 => EVP_aes_128_wrap_pad(),
                24 => EVP_aes_192_wrap_pad(),
                32 => EVP_aes_256_wrap_pad(),
                _ => return Err(CryptoError::RsaUnwrapAesDecryptFailed),
            };

            if cipher.is_null() {
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            // Initialize decryption
            let ret =
                EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), aes_key.as_ptr(), ptr::null());
            if ret != 1 {
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            let mut outlen: c_int = 0;

            // Check output buffer size before decryption
            if output.len() < wrapped_data.len() {
                return Err(CryptoError::RsaUnwrapOutputBufferTooSmall);
            }

            // Perform decryption
            let ret = EVP_DecryptUpdate(
                ctx,
                output.as_mut_ptr(),
                &mut outlen,
                wrapped_data.as_ptr(),
                wrapped_data.len() as c_int,
            );
            if ret != 1 {
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            let mut tmplen: c_int = 0;
            // Ensure we don't write beyond buffer bounds
            if (outlen as usize) >= output.len() {
                return Err(CryptoError::RsaUnwrapOutputBufferTooSmall);
            }

            let remaining_space = output.len() - outlen as usize;
            let ret = if remaining_space > 0 {
                EVP_DecryptFinal_ex(ctx, output.as_mut_ptr().add(outlen as usize), &mut tmplen)
            } else {
                0 // No space for final block
            };

            if ret != 1 {
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            let total_len = outlen + tmplen;
            if total_len < 0 || total_len as usize > output.len() {
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            Ok(total_len as usize)
        })();

        // Cleanup
        EVP_CIPHER_CTX_free(ctx);
        result
    }
}
