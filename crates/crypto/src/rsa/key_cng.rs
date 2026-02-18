// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA key management using Windows CNG (Cryptography Next Generation).
//!
//! This module provides RSA public and private key implementations that use the Windows
//! Cryptography Next Generation (CNG) API. It supports key generation, import/export,
//! and conversion between Windows CNG blob format and DER encoding.
//!
//! # Features
//!
//! - **RSA Private Keys**: Full-featured private keys with signing and decryption capabilities
//! - **RSA Public Keys**: Public keys with verification and encryption capabilities
//! - **Key Generation**: Cryptographically secure random key pair generation
//! - **Format Conversion**: Bidirectional conversion between CNG blob format and DER encoding
//! - **Secure Management**: Automatic cleanup of key handles through RAII patterns
//! - **Validation**: Comprehensive blob structure validation for security
//! - **Key Wrapping**: Support for RSA-based key wrapping/unwrapping operations
//!
//! # Supported Key Sizes
//!
//! - **RSA-2048**: 256 bytes (2048 bits) - Minimum recommended for new applications
//! - **RSA-3072**: 384 bytes (3072 bits) - Enhanced security for sensitive applications
//! - **RSA-4096**: 512 bytes (4096 bits) - High security for long-term protection
//!
//! # Platform
//!
//! This implementation is Windows-specific and uses the BCrypt APIs from Windows CNG.
//! Key operations are performed using hardware acceleration when available.
//!
//! # Safety
//!
//! This module contains unsafe code for interfacing with Windows CNG APIs. All unsafe
//! operations are carefully encapsulated with proper error handling and resource cleanup
//! through RAII patterns. Key material is automatically zeroized when key handles are dropped.

use std::marker::*;
use std::mem::*;
use std::ops::*;

use windows::Win32::Security::Cryptography::*;

use super::*;

type CngRsaPrivateKeyHandle = CngRsaKeyHandle<CngRsaPrivateKeyInfo>;
type CngRsaPublicKeyHandle = CngRsaKeyHandle<CngRsaPublicKeyInfo>;

#[allow(unsafe_code)]
// SAFETY: CngRsaPrivateKey wraps Windows CNG handles which are thread-safe and can be sent across threads
unsafe impl Send for CngRsaPrivateKey {}

#[allow(unsafe_code)]
// SAFETY: CngRsaPrivateKey wraps Windows CNG handles which are thread-safe and can be shared across threads
unsafe impl Sync for CngRsaPrivateKey {}

#[allow(unsafe_code)]
// SAFETY: CngRsaPublicKey wraps Windows CNG handles which are thread-safe and can be sent across threads
unsafe impl Send for CngRsaPublicKey {}

#[allow(unsafe_code)]
// SAFETY: CngRsaPublicKey wraps Windows CNG handles which are thread-safe and can be shared across threads
unsafe impl Sync for CngRsaPublicKey {}

/// RSA private key implementation using Windows CNG.
///
/// This structure wraps a Windows CNG RSA private key handle and provides a safe
/// Rust interface for RSA private key operations. The key can be used for both
/// signing and decryption operations.
///
/// # Key Capabilities
///
/// - **Signing**: Generate RSA signatures for authentication and integrity
/// - **Decryption**: Decrypt data encrypted with the corresponding public key
/// - **Key Derivation**: Extract the corresponding public key
/// - **Import/Export**: Convert to/from DER format for interoperability
///
/// # Trait Implementations
///
/// - `Key`: Base key trait
/// - `DecryptionKey`: Marks this key as capable of decryption
/// - `SigningKey`: Marks this key as capable of signing
/// - `PrivateKey`: Provides access to the corresponding public key
/// - `KeyExportOp`: Supports exporting to DER format
/// - `KeyImportOp`: Supports importing from DER format
/// - `KeyGenerationOp`: Supports generating new random keys
#[derive(Clone, Debug)]
pub struct CngRsaPrivateKey {
    key: CngRsaPrivateKeyHandle,
}

/// Implements the base `Key` trait, marking this type as a cryptographic key.
impl Key for CngRsaPrivateKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.key.size
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.size() * 8
    }
}

/// Implements `DecryptionKey`, enabling this key to be used for RSA decryption operations.
impl DecryptionKey for CngRsaPrivateKey {}

/// Implements `SigningKey`, enabling this key to be used for RSA signature operations.
impl SigningKey for CngRsaPrivateKey {}

/// Implements `UnwrappingKey`, enabling this key to be used for key unwrapping operations.
impl UnwrappingKey for CngRsaPrivateKey {}

/// Implements `PrivateKey`, providing access to the corresponding public key.
impl PrivateKey for CngRsaPrivateKey {
    type PublicKey = RsaPublicKey;

    /// Derives the corresponding RSA public key from this private key.
    ///
    /// # Returns
    ///
    /// The corresponding public key that can verify signatures created by this private key
    /// and encrypt data that this private key can decrypt.
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        Ok(CngRsaPublicKey {
            key: CngRsaPublicKeyHandle::try_from(&self.key)?,
        })
    }
}

/// Implements `ExportableKey`, enabling this key to be exported to byte representations.
impl ExportableKey for CngRsaPrivateKey {
    /// Exports the private key to DER format.
    ///
    /// The key is first converted to Windows CNG blob format, then encoded as DER.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional buffer to write the DER data. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written or required for the DER encoding.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        DerRsaPrivateKey::try_from(&self.key)?.to_der(bytes)
    }
}

/// Implements `ImportableKey`, enabling this key to be imported from byte representations.
impl ImportableKey for CngRsaPrivateKey {
    /// Imports an RSA private key from DER format.
    ///
    /// The DER data is first parsed, then converted to Windows CNG blob format
    /// and imported into a CNG key handle.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded RSA private key data
    ///
    /// # Returns
    ///
    /// A new RSA private key imported from the DER data.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let der = DerRsaPrivateKey::from_der(bytes)?;
        if !is_valid_key_size(der.key_size()) {
            return Err(CryptoError::EccInvalidKeySize);
        }
        let key = CngRsaPrivateKeyHandle::try_from(&der)?;
        Ok(Self { key })
    }
}

impl KeyGenerationOp for CngRsaPrivateKey {
    type Key = Self;

    /// Generates a new random RSA key pair.
    ///
    /// Uses Windows CNG to generate a cryptographically secure random RSA key pair
    /// with the specified key size.
    ///
    /// # Arguments
    ///
    /// * `size` - The key size in bytes (e.g., 256 for RSA-2048, 512 for RSA-4096)
    ///
    /// # Returns
    ///
    /// A new randomly generated RSA private key.
    fn generate(size: usize) -> Result<Self::Key, CryptoError> {
        if !is_valid_key_size(size) {
            return Err(CryptoError::RsaInvalidKeySize);
        }

        let key = CngRsaPrivateKeyHandle::new(size).map_err(|_| CryptoError::RsaKeyGenError)?;
        Ok(Self { key })
    }
}

/// Provides access to RSA key components.
///
/// This implementation allows extracting the modulus (n) and public exponent (e)
/// from the private key, which are needed for various cryptographic operations
/// and key metadata inspection.
impl RsaKeyOp for CngRsaPrivateKey {
    /// Exports the RSA modulus (n) to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `n` - Optional buffer to receive the modulus. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The size in bytes of the modulus component.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too small or key export fails.
    fn n(&self, n: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.key.to_blob()?;
        let len = blob.n().len();

        if let Some(n) = n {
            if n.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            n[..len].copy_from_slice(blob.n());
        }

        Ok(len)
    }

    /// Exports the RSA public exponent (e) to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `e` - Optional buffer to receive the exponent. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The size in bytes of the exponent component (typically 3 bytes for e=65537).
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too small or key export fails.
    fn e(&self, e: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.key.to_blob()?;
        let len = blob.e().len();

        if let Some(e) = e {
            if e.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            e[..len].copy_from_slice(blob.e());
        }

        Ok(len)
    }
}

impl CngRsaPrivateKey {
    /// Returns the underlying Windows CNG key handle.
    ///
    /// This method is used internally for cryptographic operations.
    pub(crate) fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.key.handle()
    }

    #[allow(unsafe_code)]
    pub fn from_bcrypt_blob(blob: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: CngRsaPrivateKeyHandle::from_bcrypt_blob(blob)?,
        })
    }

    #[allow(unsafe_code)]
    pub fn to_bcrypt_blob(&self) -> Result<Vec<u8>, CryptoError> {
        self.key.to_bcrypt_blob()
    }
}

/// RSA public key implementation using Windows CNG.
///
/// This structure wraps a Windows CNG RSA public key handle and provides a safe
/// Rust interface for RSA public key operations. The key can be used for both
/// signature verification and encryption operations.
///
/// # Key Capabilities
///
/// - **Verification**: Verify RSA signatures for authentication
/// - **Encryption**: Encrypt data that can only be decrypted by the private key
/// - **Import/Export**: Convert to/from DER format for interoperability
///
/// # Trait Implementations
///
/// - `Key`: Base key trait
/// - `EncryptionKey`: Marks this key as capable of encryption
/// - `VerificationKey`: Marks this key as capable of signature verification
/// - `PublicKey`: Marks this as a public key
/// - `KeyExportOp`: Supports exporting to DER format
/// - `KeyImportOp`: Supports importing from DER format
#[derive(Clone, Debug)]
pub struct CngRsaPublicKey {
    key: CngRsaPublicKeyHandle,
}

/// Implements the base `Key` trait, marking this type as a cryptographic key.
impl Key for CngRsaPublicKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.key.size
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.size() * 8
    }
}

/// Implements `EncryptionKey`, enabling this key to be used for RSA encryption operations.
impl EncryptionKey for CngRsaPublicKey {}

/// Implements `VerificationKey`, enabling this key to be used for RSA signature verification.
impl VerificationKey for CngRsaPublicKey {}

/// Implements `WrappingKey`, enabling this key to be used for key wrapping operations.
impl WrappingKey for CngRsaPublicKey {}

/// Implements `PublicKey`, marking this as a public key that can be freely distributed.
impl PublicKey for CngRsaPublicKey {}

/// Implements `ExportableKey`, enabling this key to be exported to byte representations.
impl ExportableKey for CngRsaPublicKey {
    /// Exports the public key to DER format.
    ///
    /// The key is first converted to Windows CNG blob format, then encoded as DER.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional buffer to write the DER data. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written or required for the DER encoding.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let der = DerRsaPublicKey::try_from(&self.key)?;
        der.to_der(bytes)
    }
}

/// Implements `ImportableKey`, enabling this key to be imported from byte representations.
impl ImportableKey for CngRsaPublicKey {
    /// Imports an RSA public key from DER format.
    ///
    /// The DER data is first parsed, then converted to Windows CNG blob format
    /// and imported into a CNG key handle.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded RSA public key data
    ///
    /// # Returns
    ///
    /// A new RSA public key imported from the DER data.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let der = DerRsaPublicKey::from_der(bytes)?;
        let key = CngRsaPublicKeyHandle::try_from(&der)?;
        Ok(Self { key })
    }
}

/// Provides access to RSA public key components.
///
/// This implementation allows extracting the modulus (n) and public exponent (e)
/// from the public key, which are the only components available in a public key.
impl RsaKeyOp for CngRsaPublicKey {
    /// Exports the RSA modulus (n) to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `n` - Optional buffer to receive the modulus. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The size in bytes of the modulus component.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too small or key export fails.
    fn n(&self, n: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.key.to_blob()?;
        let len = blob.n().len();

        if let Some(n) = n {
            if n.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            n[..len].copy_from_slice(blob.n());
        }

        Ok(len)
    }

    /// Exports the RSA public exponent (e) to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `e` - Optional buffer to receive the exponent. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// The size in bytes of the exponent component (typically 3 bytes for e=65537).
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too small or key export fails.
    fn e(&self, e: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.key.to_blob()?;
        let len = blob.e().len();

        if let Some(e) = e {
            if e.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            e[..len].copy_from_slice(blob.e());
        }

        Ok(len)
    }
}

impl CngRsaPublicKey {
    /// Returns the underlying Windows CNG key handle.
    ///
    /// This method is used internally for cryptographic operations.
    pub(crate) fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.key.handle()
    }
}

/// Trait defining RSA key type information for Windows CNG.
///
/// This trait associates each key type (private or public) with its corresponding
/// blob format and Windows CNG blob type identifier.
trait CngRsaKeyInfo {
    /// The blob type used to store this key's data.
    type Blob: CngRsaKeyBlob;

    /// Returns the Windows CNG blob type identifier for this key type.
    fn blob_type() -> windows::core::PCWSTR;
}

/// Type information for RSA private keys.
#[derive(Clone, Debug)]
struct CngRsaPrivateKeyInfo;
impl CngRsaKeyInfo for CngRsaPrivateKeyInfo {
    type Blob = CngRsaPrivateKeyBlob;

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_RSAFULLPRIVATE_BLOB
    }
}

/// Type information for RSA public keys.
#[derive(Clone, Debug)]
struct CngRsaPublicKeyInfo;
impl CngRsaKeyInfo for CngRsaPublicKeyInfo {
    type Blob = CngRsaPublicKeyBlob;

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_RSAPUBLIC_BLOB
    }
}

/// RAII wrapper for Windows CNG RSA key handles.
///
/// This structure manages the lifetime of a Windows CNG RSA key handle, ensuring
/// proper cleanup when the key is no longer needed. It is parameterized by key type
/// (private or public) to enforce type safety at compile time.
///
/// # Type Safety
///
/// The generic `KeyInfo` parameter ensures that operations are performed with the
/// correct blob type and Windows CNG identifiers for each key type. This prevents
/// mixing private and public key operations at compile time.
///
/// # Resource Management
///
/// The handle implements `Drop` to ensure that the underlying Windows CNG key handle
/// is properly destroyed, preventing resource leaks. This follows Rust's RAII pattern.
#[derive(Debug)]
struct CngRsaKeyHandle<KeyInfo: CngRsaKeyInfo> {
    /// The underlying Windows CNG key handle.
    handle: BCRYPT_KEY_HANDLE,
    /// The key size in bytes.
    size: usize,
    /// Phantom data to associate the handle with its key type.
    marker: PhantomData<KeyInfo>,
}

impl<KeyInfo: CngRsaKeyInfo> Drop for CngRsaKeyHandle<KeyInfo> {
    /// Ensures proper cleanup of the Windows CNG key handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Calling Windows CNG BCryptDestroyKey API.
        // - self.handle is a valid BCRYPT_KEY_HANDLE owned by this instance
        // - This is called exactly once during drop, ensuring no double-free
        unsafe {
            let _ = BCryptDestroyKey(self.handle);
        }
    }
}

impl<KeyInfo: CngRsaKeyInfo> Clone for CngRsaKeyHandle<KeyInfo> {
    /// Clones the key handle by exporting and re-importing the key blob.
    #[allow(unsafe_code)]
    fn clone(&self) -> Self {
        let Ok(bytes) = self.to_blob() else {
            // Clone cannot fail.
            panic!("Failed to export CNG RSA key blob for cloning");
        };
        let Ok(handle) = Self::from_blob(&bytes) else {
            // Clone cannot fail.
            panic!("Failed to import CNG RSA key blob for cloning");
        };
        handle
    }
}

impl<KeyInfo: CngRsaKeyInfo> CngRsaKeyHandle<KeyInfo> {
    /// Generates a new random RSA key pair using Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `len` - The key size in bytes
    ///
    /// # Returns
    ///
    /// A new key handle containing the generated key pair.
    #[allow(unsafe_code)]
    fn new(len: usize) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();

        // Generate key pair
        // SAFETY: Calling Windows CNG BCryptGenerateKeyPair API.
        // - BCRYPT_RSA_ALG_HANDLE is a valid global algorithm handle
        // - handle is a valid mutable reference to store the result
        // - len is validated to be a reasonable key size
        let status =
            unsafe { BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &mut handle, len as u32 * 8, 0) };
        status.ok().map_err(|_| CryptoError::RsaKeyGenError)?;

        // Finalize the key pair
        // SAFETY: Calling Windows CNG BCryptFinalizeKeyPair to finalize the key pair.
        // - handle is a valid BCRYPT_KEY_HANDLE from successful BCryptGenerateKeyPair call
        // - 0 flags means standard finalization
        let status = unsafe { BCryptFinalizeKeyPair(handle, 0) };
        status.ok().map_err(|_| CryptoError::RsaKeyGenError)?;

        Ok(Self {
            handle,
            size: len,
            marker: PhantomData,
        })
    }

    /// Returns the underlying Windows CNG key handle.
    ///
    /// This provides access to the raw Windows CNG handle for use in platform-specific
    /// cryptographic operations. The handle remains valid as long as this key object
    /// exists and is automatically destroyed when the key is dropped.
    ///
    /// # Returns
    ///
    /// The Windows `BCRYPT_KEY_HANDLE` for this key.
    fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    /// Exports the key to Windows CNG blob format.
    ///
    /// # Returns
    ///
    /// A validated blob containing the key material.
    #[allow(unsafe_code)]
    fn to_blob(&self) -> Result<KeyInfo::Blob, CryptoError> {
        // Query required buffer size
        let mut len = 0u32;
        // SAFETY: Calling Windows CNG BCryptExportKey to query buffer size.
        // - self.handle() is a valid BCRYPT_KEY_HANDLE
        // - None for hExportKey means no key encryption
        // - KeyInfo::blob_type() is a valid blob type string
        // - None for output buffer to query size
        // - len is a valid mutable reference to receive required size
        let status = unsafe {
            BCryptExportKey(self.handle(), None, KeyInfo::blob_type(), None, &mut len, 0)
        };
        status.ok().map_err(|_| CryptoError::RsaKeyExportError)?;

        // Export the key
        let mut data = vec![0u8; len as usize];
        // SAFETY: Calling Windows CNG BCryptExportKey to export the key.
        // - self.handle() is a valid BCRYPT_KEY_HANDLE
        // - None for hExportKey means no key encryption
        // - KeyInfo::blob_type() is a valid blob type string
        // - data buffer is allocated with the required size from previous query
        // - len is a valid mutable reference to receive actual size
        let status = unsafe {
            BCryptExportKey(
                self.handle(),
                None,
                KeyInfo::blob_type(),
                Some(&mut data),
                &mut len,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaKeyExportError)?;
        KeyInfo::Blob::new(data)
    }

    /// Imports a key from Windows CNG blob format.
    ///
    /// # Arguments
    ///
    /// * `blob` - Validated blob containing key material
    ///
    /// # Returns
    ///
    /// A new key handle containing the imported key.
    #[allow(unsafe_code)]
    fn from_blob(blob: &KeyInfo::Blob) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Calling Windows CNG BCryptImportKeyPair to import an RSA key.
        // - BCRYPT_RSA_ALG_HANDLE is the global RSA algorithm handle
        // - None for hImportKey means no key encryption
        // - KeyInfo::blob_type() is a valid blob type string
        // - handle is a valid mutable reference to receive the key handle
        // - blob.as_bytes() contains validated key material with correct format
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                KeyInfo::blob_type(),
                &mut handle,
                blob.as_bytes(),
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaKeyImportError)?;

        Ok(Self {
            handle,
            size: blob.key_size(),
            marker: PhantomData,
        })
    }

    #[allow(unsafe_code)]
    fn from_bcrypt_blob(blob: &[u8]) -> Result<Self, CryptoError> {
        // valid the blob is RSA Private Key Blob
        if blob.len() < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() {
            return Err(CryptoError::RsaInvalidPrivateKeyBlob);
        }

        let header_size = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
        if blob.len() < header_size {
            return Err(CryptoError::RsaInvalidPrivateKeyBlob);
        }

        // SAFETY: We have validated that blob is at least the size of BCRYPT_RSAKEY_BLOB
        let header = unsafe { &*(blob.as_ptr() as *const BCRYPT_RSAKEY_BLOB) };
        if header.Magic != BCRYPT_RSAPRIVATE_MAGIC {
            return Err(CryptoError::RsaInvalidPrivateKeyBlob);
        }

        let size = header.BitLength.div_ceil(8) as usize;
        if !is_valid_key_size(size) {
            return Err(CryptoError::RsaInvalidKeySize);
        }

        // check the blob length
        let expected_len = header_size
            + header.cbModulus as usize
            + header.cbPublicExp as usize
            + header.cbPrime1 as usize
            + header.cbPrime2 as usize;

        if blob.len() != expected_len {
            return Err(CryptoError::RsaInvalidPrivateKeyBlob);
        }

        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Calling Windows CNG BCryptImportKeyPair to import an RSA private key.
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAPRIVATE_BLOB,
                &mut handle,
                blob,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaKeyImportError)?;

        Ok(Self {
            handle,
            size,
            marker: PhantomData,
        })
    }

    #[allow(unsafe_code)]
    fn to_bcrypt_blob(&self) -> Result<Vec<u8>, CryptoError> {
        let mut len = 0u32;

        // SAFETY: Calling Windows CNG BCryptExportKey to query buffer size.
        let status = unsafe {
            BCryptExportKey(
                self.handle(),
                None,
                BCRYPT_RSAPRIVATE_BLOB,
                None,
                &mut len,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaKeyExportError)?;

        let mut blob = vec![0u8; len as usize];

        // SAFETY: Calling Windows CNG BCryptExportKey to export the key blob.
        let status = unsafe {
            BCryptExportKey(
                self.handle(),
                None,
                BCRYPT_RSAPRIVATE_BLOB,
                Some(&mut blob),
                &mut len,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::RsaKeyExportError)?;
        blob.truncate(len as usize);

        Ok(blob)
    }
}

/// Trait for Windows CNG RSA key blobs.
///
/// This trait defines the interface for working with Windows CNG RSA key blobs,
/// which are the native format for storing RSA keys in Windows CNG.
trait CngRsaKeyBlob {
    /// Creates a new blob from raw bytes, validating the structure.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw blob data
    ///
    /// # Returns
    ///
    /// A validated blob or an error if the data is invalid.
    fn new(data: Vec<u8>) -> Result<Self, CryptoError>
    where
        Self: Sized;

    /// Returns the key size in bytes.
    fn key_size(&self) -> usize;

    /// Returns the raw blob bytes.
    fn as_bytes(&self) -> &[u8];
}

/// Windows CNG blob format for RSA private keys.
///
/// This structure represents an RSA private key in the Windows CNG blob format
/// (BCRYPT_RSAFULLPRIVATE_BLOB). It validates the blob structure and provides
/// access to individual RSA components.
///
/// # Blob Structure
///
/// The blob contains:
/// - Header: Magic number, bit length, and component sizes
/// - Public exponent (e)
/// - Modulus (n)
/// - Prime 1 (p)
/// - Prime 2 (q)
/// - Exponent 1 (dp = d mod (p-1))
/// - Exponent 2 (dq = d mod (q-1))
/// - Coefficient (qi = q^-1 mod p)
/// - Private exponent (d)
struct CngRsaPrivateKeyBlob {
    /// The key size in bytes.
    key_len: usize,
    /// The raw blob data including header.
    data: Vec<u8>,
    /// Byte ranges for each RSA component within the data.
    components: Vec<Range<usize>>,
}

impl CngRsaKeyBlob for CngRsaPrivateKeyBlob {
    fn new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let header = Self::header(&data)?;

        if header.Magic != BCRYPT_RSAFULLPRIVATE_MAGIC {
            Err(CryptoError::RsaInvalidPrivateKeyBlob)?;
        }

        let key_len = header.BitLength.div_ceil(8) as usize;
        let components = Self::make_comp_ranges(header);
        let len = components.iter().map(|r| r.len()).sum::<usize>();
        if data.len() != Self::HEADER_LEN + len {
            Err(CryptoError::RsaInvalidPrivateKeyBlob)?;
        }

        Ok(Self {
            key_len,
            data,
            components,
        })
    }

    fn key_size(&self) -> usize {
        self.key_len
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl CngRsaPrivateKeyBlob {
    const HEADER_LEN: usize = size_of::<BCRYPT_RSAKEY_BLOB>();

    /// Creates a new private key blob from RSA components.
    ///
    /// # Arguments
    ///
    /// * `key_len` - The key size in bytes
    /// * `e` - Public exponent
    /// * `n` - Modulus
    /// * `p` - Prime 1
    /// * `q` - Prime 2
    /// * `dp` - Exponent 1 (d mod (p-1))
    /// * `dq` - Exponent 2 (d mod (q-1))
    /// * `qi` - Coefficient (q^-1 mod p)
    /// * `d` - Private exponent
    ///
    /// # Returns
    ///
    /// A new private key blob containing all components.
    fn with_components(
        key_len: usize,
        e: &[u8],
        n: &[u8],
        p: &[u8],
        q: &[u8],
        dp: &[u8],
        dq: &[u8],
        qi: &[u8],
        d: &[u8],
    ) -> Self {
        let modulus_size = key_len;
        let prime_size = modulus_size / 2;

        assert_eq!(n.len(), modulus_size);

        let p = Self::pad_to_len(p, prime_size);
        let q = Self::pad_to_len(q, prime_size);
        let dp = Self::pad_to_len(dp, prime_size);
        let dq = Self::pad_to_len(dq, prime_size);
        let qi = Self::pad_to_len(qi, prime_size);
        let d = Self::pad_to_len(d, modulus_size);

        let data_len = Self::HEADER_LEN
            + n.len()
            + e.len()
            + p.len()
            + q.len()
            + dp.len()
            + dq.len()
            + qi.len()
            + d.len();

        let mut data = Vec::with_capacity(data_len);

        let header = BCRYPT_RSAKEY_BLOB {
            Magic: BCRYPT_RSAFULLPRIVATE_MAGIC,
            BitLength: (n.len() * 8) as u32,
            cbPublicExp: e.len() as u32,
            cbModulus: n.len() as u32,
            cbPrime1: p.len() as u32,
            cbPrime2: q.len() as u32,
        };

        Self::copy_header(&header, &mut data);
        data.extend_from_slice(e);
        data.extend_from_slice(n);
        data.extend_from_slice(&p);
        data.extend_from_slice(&q);
        data.extend_from_slice(&dp);
        data.extend_from_slice(&dq);
        data.extend_from_slice(&qi);
        data.extend_from_slice(&d);

        Self {
            key_len,
            data,
            components: Self::make_comp_ranges(&header),
        }
    }

    fn pad_to_len(data: &[u8], len: usize) -> Vec<u8> {
        if data.len() >= len {
            data.to_vec()
        } else {
            let mut padded = vec![0u8; len - data.len()];
            padded.extend_from_slice(data);
            padded
        }
    }

    /// Returns the public exponent 'e' from the RSA key blob.
    ///
    /// The public exponent is typically 65537 (0x010001) for modern RSA keys.
    fn e(&self) -> &[u8] {
        &self.data[self.components[0].clone()]
    }

    /// Returns the modulus 'n' from the RSA key blob.
    ///
    /// The modulus is the product of the two primes p and q (n = p * q).
    fn n(&self) -> &[u8] {
        &self.data[self.components[1].clone()]
    }

    /// Returns the first prime 'p' from the RSA key blob.
    ///
    /// This is one of the two secret primes used to construct the RSA key.
    fn p(&self) -> &[u8] {
        &self.data[self.components[2].clone()]
    }

    /// Returns the second prime 'q' from the RSA key blob.
    ///
    /// This is the other secret prime used to construct the RSA key.
    fn q(&self) -> &[u8] {
        &self.data[self.components[3].clone()]
    }

    /// Returns the first exponent 'dp' (d mod (p-1)) from the RSA key blob.
    ///
    /// This value is used for CRT (Chinese Remainder Theorem) optimization.
    fn dp(&self) -> &[u8] {
        &self.data[self.components[4].clone()]
    }

    /// Returns the second exponent 'dq' (d mod (q-1)) from the RSA key blob.
    ///
    /// This value is used for CRT (Chinese Remainder Theorem) optimization.
    fn dq(&self) -> &[u8] {
        &self.data[self.components[5].clone()]
    }

    /// Returns the coefficient 'qi' (q^-1 mod p) from the RSA key blob.
    ///
    /// This value is used for CRT (Chinese Remainder Theorem) optimization.
    fn qi(&self) -> &[u8] {
        &self.data[self.components[6].clone()]
    }

    /// Returns the private exponent 'd' from the RSA key blob.
    ///
    /// The private exponent is the multiplicative inverse of e modulo φ(n).
    fn d(&self) -> &[u8] {
        &self.data[self.components[7].clone()]
    }

    /// Extracts the blob header from raw data.
    ///
    /// # Safety
    ///
    /// This method performs pointer casting and must validate the buffer size first.
    #[allow(unsafe_code)]
    fn header(data: &[u8]) -> Result<&BCRYPT_RSAKEY_BLOB, CryptoError> {
        if data.len() < Self::HEADER_LEN {
            Err(CryptoError::RsaInvalidPrivateKeyBlob)?;
        }

        // SAFETY: Casting blob bytes to BCRYPT_RSAKEY_BLOB pointer.
        // - Blob size is validated to be at least HEADER_LEN bytes
        // - BCRYPT_RSAKEY_BLOB is a C struct with defined layout
        // - The reference lifetime is tied to the data slice lifetime
        unsafe { Ok(&*(data.as_ptr() as *const BCRYPT_RSAKEY_BLOB)) }
    }

    /// Copies the blob header to a vector.
    ///
    /// # Safety
    ///
    /// This method performs pointer casting to convert the struct to bytes.
    #[allow(unsafe_code)]
    fn copy_header(&header: &BCRYPT_RSAKEY_BLOB, vec: &mut Vec<u8>) {
        // SAFETY: Converting BCRYPT_RSAKEY_BLOB struct to byte slice.
        // - header is a valid reference to BCRYPT_RSAKEY_BLOB
        // - HEADER_LEN matches the size of BCRYPT_RSAKEY_BLOB struct
        // - The resulting slice lifetime is limited to this scope
        // - Data is immediately copied to vec, so no lifetime issues
        unsafe {
            let src = std::slice::from_raw_parts(
                &header as *const BCRYPT_RSAKEY_BLOB as *const u8,
                Self::HEADER_LEN,
            );
            vec.extend_from_slice(src);
        }
    }

    /// Computes byte ranges for each RSA component based on the header.
    ///
    /// Returns a vector of ranges in the order: e, n, p, q, dp, dq, qi, d.
    fn make_comp_ranges(header: &BCRYPT_RSAKEY_BLOB) -> Vec<Range<usize>> {
        let mut ranges = Vec::with_capacity(8);

        // range for e
        let mut offset = Self::HEADER_LEN;
        ranges.push(offset..offset + header.cbPublicExp as usize);

        // range for n
        offset += header.cbPublicExp as usize;
        ranges.push(offset..offset + header.cbModulus as usize);

        // range for p
        offset += header.cbModulus as usize;
        ranges.push(offset..offset + header.cbPrime1 as usize);

        // range for q
        offset += header.cbPrime1 as usize;
        ranges.push(offset..offset + header.cbPrime2 as usize);
        // range for dp
        offset += header.cbPrime2 as usize;
        ranges.push(offset..offset + header.cbPrime1 as usize);

        // range for dq
        offset += header.cbPrime1 as usize;
        ranges.push(offset..offset + header.cbPrime2 as usize);

        // range for qi
        offset += header.cbPrime2 as usize;
        ranges.push(offset..offset + header.cbPrime1 as usize);

        // range for d
        offset += header.cbPrime1 as usize;
        ranges.push(offset..offset + header.cbModulus as usize);
        ranges
    }
}

/// Windows CNG blob format for RSA public keys.
///
/// This structure represents an RSA public key in the Windows CNG blob format
/// (BCRYPT_RSAPUBLIC_BLOB). It validates the blob structure and provides
/// access to the RSA public key components.
///
/// # Blob Structure
///
/// The blob contains:
/// - Header: Magic number, bit length, and component sizes
/// - Public exponent (e)
/// - Modulus (n)
pub struct CngRsaPublicKeyBlob {
    /// The key size in bytes.
    key_size: usize,
    /// The raw blob data including header.
    data: Vec<u8>,
    /// Byte ranges for each RSA component within the data.
    components: Vec<Range<usize>>,
}

impl CngRsaKeyBlob for CngRsaPublicKeyBlob {
    fn new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let header = Self::header(&data)?;

        if header.Magic != BCRYPT_RSAPUBLIC_MAGIC {
            Err(CryptoError::RsaInvalidPublicKeyBlob)?;
        }

        let key_size = header.BitLength.div_ceil(8) as usize;
        let components = Self::make_comp_ranges(header);

        let len = components.iter().map(|r| r.len()).sum::<usize>();
        if data.len() != Self::HEADER_LEN + len {
            Err(CryptoError::RsaInvalidPublicKeyBlob)?;
        }

        Ok(Self {
            key_size,
            data,
            components,
        })
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl CngRsaPublicKeyBlob {
    const HEADER_LEN: usize = size_of::<BCRYPT_RSAKEY_BLOB>();

    /// Creates a new public key blob from RSA components.
    ///
    /// # Arguments
    ///
    /// * `key_len` - The key size in bytes
    /// * `n` - Modulus
    /// * `e` - Public exponent
    ///
    /// # Returns
    ///
    /// A new public key blob containing the components.
    fn with_components(key_len: usize, e: &[u8], n: &[u8]) -> Self {
        let mut data = Vec::with_capacity(Self::HEADER_LEN + e.len() + n.len());

        let header = BCRYPT_RSAKEY_BLOB {
            Magic: BCRYPT_RSAPUBLIC_MAGIC,
            BitLength: (n.len() * 8) as u32,
            cbPublicExp: e.len() as u32,
            cbModulus: n.len() as u32,
            ..Default::default()
        };

        Self::copy_header(&header, &mut data);
        data.extend_from_slice(e);
        data.extend_from_slice(n);

        Self {
            key_size: key_len,
            data,
            components: Self::make_comp_ranges(&header),
        }
    }

    /// Returns the public exponent 'e' from the RSA key blob.
    fn e(&self) -> &[u8] {
        &self.data[self.components[0].clone()]
    }

    /// Returns the modulus 'n' from the RSA key blob.
    fn n(&self) -> &[u8] {
        &self.data[self.components[1].clone()]
    }

    /// Extracts the blob header from raw data.
    ///
    /// # Safety
    ///
    /// This method performs pointer casting and must validate the buffer size first.
    #[allow(unsafe_code)]
    fn header(data: &[u8]) -> Result<&BCRYPT_RSAKEY_BLOB, CryptoError> {
        if data.len() < Self::HEADER_LEN {
            Err(CryptoError::RsaInvalidPublicKeyBlob)?;
        }
        // SAFETY: Casting blob bytes to BCRYPT_RSAKEY_BLOB pointer.
        // - Blob size is validated to be at least HEADER_LEN bytes
        // - BCRYPT_RSAKEY_BLOB is a C struct with defined layout
        // - The reference lifetime is tied to the data slice lifetime
        unsafe { Ok(&*(data.as_ptr() as *const BCRYPT_RSAKEY_BLOB)) }
    }

    /// Copies the blob header to a vector.
    ///
    /// # Safety
    ///
    /// This method performs pointer casting to convert the struct to bytes.
    #[allow(unsafe_code)]
    fn copy_header(&header: &BCRYPT_RSAKEY_BLOB, vec: &mut Vec<u8>) {
        // SAFETY: Converting BCRYPT_RSAKEY_BLOB struct to byte slice.
        // - header is a valid reference to BCRYPT_RSAKEY_BLOB
        // - HEADER_LEN matches the size of BCRYPT_RSAKEY_BLOB struct
        // - The resulting slice lifetime is limited to this scope
        // - Data is immediately copied to vec, so no lifetime issues
        unsafe {
            let src = std::slice::from_raw_parts(
                &header as *const BCRYPT_RSAKEY_BLOB as *const u8,
                Self::HEADER_LEN,
            );
            vec.extend_from_slice(src);
        }
    }

    /// Computes byte ranges for each RSA component based on the header.
    ///
    /// Returns a vector of ranges in the order: e, n.
    fn make_comp_ranges(header: &BCRYPT_RSAKEY_BLOB) -> Vec<Range<usize>> {
        let mut ranges = Vec::with_capacity(2);

        // range for e
        let mut offset = Self::HEADER_LEN;
        ranges.push(offset..offset + header.cbPublicExp as usize);

        // range for n
        offset += header.cbPublicExp as usize;
        ranges.push(offset..offset + header.cbModulus as usize);

        ranges
    }
}

impl TryFrom<&CngRsaPublicKeyHandle> for DerRsaPublicKey {
    type Error = CryptoError;

    /// Converts a CNG RSA public key handle to DER format.
    ///
    /// The key is first exported to a CNG blob, then the blob components are
    /// extracted and encoded as DER.
    fn try_from(key: &CngRsaPublicKeyHandle) -> Result<Self, CryptoError> {
        let blob = key.to_blob().map_err(|_| CryptoError::RsaKeyExportError)?;
        Ok(DerRsaPublicKey::new(blob.n(), blob.e()))
    }
}

impl TryFrom<&DerRsaPublicKey> for CngRsaPublicKeyHandle {
    type Error = CryptoError;

    /// Converts a DER RSA public key to a CNG RSA public key handle.
    ///
    /// The DER data is parsed into components, converted to a CNG blob,
    /// and imported into Windows CNG.
    fn try_from(key: &DerRsaPublicKey) -> Result<Self, CryptoError> {
        let blob = CngRsaPublicKeyBlob::with_components(key.key_size(), key.e(), key.n());
        CngRsaPublicKeyHandle::from_blob(&blob).map_err(|_| CryptoError::RsaKeyImportError)
    }
}
impl TryFrom<&CngRsaPrivateKeyHandle> for DerRsaPrivateKey {
    type Error = CryptoError;

    /// Converts a CNG RSA private key handle to DER format.
    ///
    /// The key is first exported to a CNG blob, then all private key components
    /// are extracted and encoded as DER.
    fn try_from(key: &CngRsaPrivateKeyHandle) -> Result<Self, CryptoError> {
        let blob = key.to_blob().map_err(|_| CryptoError::RsaKeyExportError)?;
        Ok(DerRsaPrivateKey::new(
            blob.e(),
            blob.n(),
            blob.d(),
            blob.p(),
            blob.q(),
            blob.dp(),
            blob.dq(),
            blob.qi(),
        ))
    }
}

impl TryFrom<&DerRsaPrivateKey> for CngRsaPrivateKeyHandle {
    type Error = CryptoError;

    /// Converts a DER RSA private key to a CNG RSA private key handle.
    ///
    /// The DER data is parsed into all private key components, converted to a
    /// CNG blob, and imported into Windows CNG.
    fn try_from(key: &DerRsaPrivateKey) -> Result<Self, CryptoError> {
        let blob = CngRsaPrivateKeyBlob::with_components(
            key.key_size(),
            key.e(),
            key.n(),
            key.p(),
            key.q(),
            key.dp(),
            key.dq(),
            key.qi(),
            key.d(),
        );

        CngRsaPrivateKeyHandle::from_blob(&blob).map_err(|_| CryptoError::RsaKeyImportError)
    }
}

impl TryFrom<&CngRsaPrivateKeyHandle> for CngRsaPublicKeyHandle {
    type Error = CryptoError;

    /// Extracts the public key from a CNG RSA private key handle.
    ///
    /// The private key is exported to a blob, the public components (n, e) are
    /// extracted, and a new public key handle is created.
    fn try_from(key: &CngRsaPrivateKeyHandle) -> Result<Self, CryptoError> {
        let priv_blob = key.to_blob().map_err(|_| CryptoError::RsaKeyExportError)?;
        let pub_blob = CngRsaPublicKeyBlob::with_components(
            priv_blob.key_size(),
            priv_blob.e(),
            priv_blob.n(),
        );
        CngRsaPublicKeyHandle::from_blob(&pub_blob)
    }
}

/// Validates whether the given key size is supported.
///
/// This method checks if the key size is one of the standard RSA sizes
/// supported by this implementation.
///
/// # Arguments
///
/// * `size` - Key size in bytes to validate
///
/// # Returns
///
/// `true` if the size is valid (256, 384, or 512 bytes), `false` otherwise.
///
/// # Valid Sizes
///
/// - 256 bytes (2048 bits) - Minimum recommended
/// - 384 bytes (3072 bits) - Enhanced security
/// - 512 bytes (4096 bits) - High security
fn is_valid_key_size(size: usize) -> bool {
    matches!(size, 256 | 384 | 512)
}
