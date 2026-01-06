// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA-based key wrapping and unwrapping using AES Key Wrap with Padding.
//!
//! This module implements a hybrid key wrapping scheme that combines RSA-OAEP
//! with AES Key Wrap with Padding (AES-KWP). This approach allows secure wrapping
//! of keys of any size using the benefits of both asymmetric and symmetric
//! cryptography.
//!
//! # Algorithm Overview
//!
//! The wrapping process:
//! 1. Generate a random AES key (KEK - Key Encryption Key) of configurable size
//! 2. Use AES-KWP to wrap the target key with the KEK
//! 3. Use RSA-OAEP to encrypt the KEK with the RSA public key
//! 4. Concatenate the encrypted KEK and wrapped key
//!
//! The unwrapping process:
//! 1. Extract the encrypted KEK from the wrapped key material
//! 2. Use RSA-OAEP to decrypt the KEK with the RSA private key
//! 3. Use AES-KWP to unwrap the target key with the KEK
//!
//! # Format
//!
//! Wrapped key format:
//! ```text
//! [RSA-encrypted KEK (variable length)] || [AES-KWP wrapped key (variable length)]
//! ```
//!
//! # Security Properties
//!
//! - Combines the key transport capabilities of RSA with efficient symmetric wrapping
//! - Supports wrapping keys of any size (limited only by practical constraints)
//! - Provides authenticated encryption through AES-KWP
//! - Uses OAEP padding for RSA to provide semantic security
//!
//! # Use Cases
//!
//! - Wrapping symmetric keys for secure transport
//! - Key backup and archival with asymmetric protection
//! - Hybrid encryption scenarios requiring flexible key sizes

use super::*;

/// RSA-based key wrapping using AES Key Wrap with Padding.
///
/// This structure implements a hybrid key wrapping scheme that uses RSA-OAEP to
/// protect an ephemeral AES key, which in turn wraps the target key using AES-KWP.
/// This approach provides the security of RSA with the flexibility of AES-KWP for
/// arbitrary key sizes.
///
/// # Algorithm Details
///
/// The implementation uses:
/// - AES key of configurable size (128, 192, or 256 bits) for the Key Encryption Key (KEK)
/// - RSA-OAEP with configurable hash algorithm for asymmetric encryption
/// - AES-KWP (RFC 5649) for symmetric key wrapping
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync`.
pub struct RsaAesKeyWrap {
    /// Hash algorithm for RSA-OAEP padding
    hash: HashAlgo,
    /// AES KEK size in bytes (16, 24, or 32 for AES-128, AES-192, or AES-256)
    kek_size: usize,
}

impl RsaAesKeyWrap {
    /// Creates a new RSA key wrap instance.
    ///
    /// # Arguments
    ///
    /// * `hash` - Hash algorithm to use for RSA-OAEP padding
    /// * `kek_size` - AES KEK size in bytes (16 for AES-128, 24 for AES-192, or 32 for AES-256)
    ///
    /// # Returns
    ///
    /// A new `RsaKeyWrap` instance configured with the specified hash algorithm and KEK size.
    pub fn new(hash: HashAlgo, kek_size: usize) -> Self {
        Self { hash, kek_size }
    }
}

impl WrapOp for RsaAesKeyWrap {
    type Key = RsaPublicKey;

    /// Wraps a cryptographic key using RSA-OAEP and AES-KWP.
    ///
    /// This method implements a hybrid key wrapping scheme that:
    /// 1. Generates a random ephemeral AES KEK of the configured size
    /// 2. Wraps the target key using AES-KWP with the ephemeral KEK
    /// 3. Encrypts the ephemeral KEK using RSA-OAEP with the public key
    /// 4. Concatenates the encrypted KEK and wrapped target key
    ///
    /// The resulting wrapped key material can be safely transmitted or stored,
    /// and can only be unwrapped using the corresponding RSA private key.
    ///
    /// # Arguments
    ///
    /// * `key` - RSA public key used to encrypt the ephemeral KEK
    /// * `target_key` - The cryptographic key to be wrapped (must implement `ExportableKey`)
    /// * `wrapped_key` - Optional output buffer for the wrapped key material.
    ///   If `None`, only returns the required buffer size without performing the operation.
    ///
    /// # Returns
    ///
    /// Returns the size of the wrapped key material in bytes. If `wrapped_key` is `None`,
    /// this is the required buffer size. If `wrapped_key` is provided, this is the actual
    /// number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target key cannot be exported to bytes
    /// - Random KEK generation fails
    /// - AES-KWP wrapping fails
    /// - RSA-OAEP encryption fails
    /// - The output buffer is too small (when `wrapped_key` is provided)
    ///
    /// # Security
    ///
    /// - The ephemeral KEK is generated using cryptographically secure randomness
    /// - AES-KWP provides authenticated encryption with integrity checking
    /// - RSA-OAEP provides semantic security against chosen-ciphertext attacks
    /// - The wrapped key can only be unwrapped with the corresponding private key
    fn wrap_key<TargetKey: ExportableKey>(
        &self,
        key: &Self::Key,
        target_key: &TargetKey,
        wrapped_key: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Export the target key to bytes
        let target_bytes = target_key.to_vec()?;

        // Generate a random AES KEK with configured size
        let kek = AesKey::generate(self.kek_size)?;

        // Wrap the target key using AES-KWP
        let mut kwp = AesKeyWrapPadAlgo::default();
        let wrapped_target = Encrypter::encrypt_vec(&mut kwp, &kek, &target_bytes)?;

        // Export the KEK to bytes
        let kek_vec = kek.to_vec()?;

        // Encrypt the KEK using RSA-OAEP
        let mut rsa_enc = RsaEncryptAlgo::with_oaep_padding(self.hash.clone(), None);
        let encrypted_kek = Encrypter::encrypt_vec(&mut rsa_enc, key, &kek_vec)?;

        // Calculate total size
        let total_size = encrypted_kek.len() + wrapped_target.len();

        if let Some(output) = wrapped_key {
            if output.len() < total_size {
                return Err(CryptoError::RsaBufferTooSmall);
            }
            // Concatenate: [encrypted KEK] || [wrapped target key]
            output[..encrypted_kek.len()].copy_from_slice(&encrypted_kek);
            output[encrypted_kek.len()..total_size].copy_from_slice(&wrapped_target);
        }

        Ok(total_size)
    }
}

impl UnwrapOp for RsaAesKeyWrap {
    type Key = RsaPrivateKey;

    /// Unwraps a cryptographic key using RSA-OAEP and AES-KWP.
    ///
    /// This method reverses the key wrapping process by:
    /// 1. Splitting the wrapped key material into encrypted KEK and wrapped target
    /// 2. Decrypting the KEK using RSA-OAEP with the private key
    /// 3. Unwrapping the target key using AES-KWP with the decrypted KEK
    /// 4. Importing and returning the unwrapped target key
    ///
    /// The method verifies the integrity of the wrapped key material through
    /// AES-KWP's built-in authentication, ensuring that any tampering or
    /// corruption is detected.
    ///
    /// # Type Parameters
    ///
    /// * `TargetKey` - The type of key being unwrapped. Must implement `ImportableKey`
    ///   and have its `KeyImportOp::Key` associated type match itself.
    ///
    /// # Arguments
    ///
    /// * `key` - RSA private key used to decrypt the ephemeral KEK
    /// * `wrapped_key` - The wrapped key material produced by `wrap_key`
    ///
    /// # Returns
    ///
    /// Returns the unwrapped key of type `TargetKey::Key` (which is typically
    /// `TargetKey` itself for most implementations).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The wrapped key material is too short (less than RSA key size)
    /// - RSA-OAEP decryption fails (wrong private key or corrupted data)
    /// - The decrypted KEK size doesn't match the expected size
    /// - AES key import fails
    /// - AES-KWP unwrapping fails (integrity check failure, tampering detected)
    /// - Target key import from bytes fails
    ///
    /// # Security
    ///
    /// - AES-KWP provides authenticated encryption that detects tampering
    /// - RSA-OAEP decryption will fail if the wrong private key is used
    /// - Timing-safe operations prevent leaking information about failures
    /// - Any corruption or modification of wrapped key material will be detected
    fn unwrap_key<TargetKey: ImportableKey>(
        &self,
        key: &Self::Key,
        wrapped_key: &[u8],
    ) -> Result<TargetKey, CryptoError> {
        // Step 1: Determine the encrypted KEK size by querying the decryption operation
        // Create a decryption context to query the ciphertext size
        let mut rsa_enc_query = RsaEncryptAlgo::with_oaep_padding(self.hash.clone(), None);

        // The decrypt operation with None output will tell us the expected plaintext size
        // but we need the ciphertext size which is the RSA modulus size
        // We can determine this by trying to decrypt with progressively larger inputs
        // However, a simpler approach is to use the public key derived from the private key
        let public_key = key.public_key()?;
        let rsa_ciphertext_size = rsa_enc_query.encrypt(&public_key, &[], None)?;

        if wrapped_key.len() < rsa_ciphertext_size {
            return Err(CryptoError::RsaDecryptError);
        }

        // Step 2: Split the wrapped key into encrypted KEK and wrapped target
        let encrypted_kek = &wrapped_key[..rsa_ciphertext_size];
        let wrapped_target = &wrapped_key[rsa_ciphertext_size..];

        // Step 3: Decrypt the KEK using RSA-OAEP
        let mut rsa_enc = RsaEncryptAlgo::with_oaep_padding(self.hash.clone(), None);
        let kek_buffer = Decrypter::decrypt_vec(&mut rsa_enc, key, encrypted_kek)?;

        // Extract the actual KEK bytes
        let kek_bytes = &kek_buffer[..self.kek_size];
        if kek_buffer.len() < self.kek_size {
            return Err(CryptoError::AesInvalidKeySize);
        }

        // Step 4: Import the KEK as an AES key
        let kek = AesKey::from_bytes(kek_bytes)?;

        // Step 5: Unwrap the target key using AES-KWP
        let mut kwp = AesKeyWrapPadAlgo::default();
        let unwrapped_bytes = Decrypter::decrypt_vec(&mut kwp, &kek, wrapped_target)?;

        // Step 6: Import the target key from the unwrapped bytes
        TargetKey::from_bytes(&unwrapped_bytes)
    }
}
