// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG (Cryptography Next Generation) AES key management.
//!
//! This module provides AES key operations using Windows CNG APIs, including
//! key generation, import, and export capabilities for AES-128, AES-192, and AES-256.
//!
//! # Key Sizes
//!
//! Supports the standard AES key sizes:
//! - **AES-128**: 16 bytes (128 bits)
//! - **AES-192**: 24 bytes (192 bits)
//! - **AES-256**: 32 bytes (256 bits)
//!
//! # Platform
//!
//! This implementation is Windows-specific and uses the BCrypt APIs from
//! Windows Cryptography Next Generation (CNG).
//!
//! # Safety
//!
//! This module contains unsafe code for calling Windows CNG APIs. All unsafe
//! operations are carefully encapsulated and include proper error handling and
//! resource cleanup through RAII patterns.

use std::mem;

use windows::Win32::Security::Cryptography::*;

use super::*;

type CngAesCbcKeyHandle = CngAesKeyHandle<CbcMode>;
type CngAesEcbKeyHandle = CngAesKeyHandle<EcbMode>;
type CngAesXtsKeyHandle = CngAesKeyHandle<XtsMode>;
type CngAesGcmKeyHandle = CngAesKeyHandle<GcmMode>;

/// Windows CNG implementation of an AES key.
///
/// This structure wraps Windows BCrypt key handles for both ECB and CBC modes,
/// providing AES key management operations including generation, import, and
/// export through the Windows Cryptography Next Generation (CNG) APIs.
///
/// The key maintains separate handles for ECB and CBC operations to allow
/// efficient use with different cipher modes.
///
/// # Thread Safety
///
/// Windows CNG key handles are thread-safe and can be used from multiple threads.
#[derive(Clone)]
pub struct CngAesKey {
    /// Windows CNG key handle for AES-ECB operations
    ecb_handle: CngAesEcbKeyHandle,

    /// Windows CNG key handle for AES-CBC operations
    cbc_handle: CngAesCbcKeyHandle,

    /// Windows CNG key handle for AES-GCM operations
    gcm_handle: CngAesGcmKeyHandle,
}

/// Marker trait implementation indicating this is a cryptographic key.
impl Key for CngAesKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.cbc_handle.len()
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.cbc_handle.len() * 8
    }
}

/// Marks this key as suitable for encryption operations.
///
/// This implementation enables `CngAesKey` to be used with encryption
/// operations in both AES-ECB and AES-CBC modes.
impl EncryptionKey for CngAesKey {}

/// Marks this key as suitable for decryption operations.
///
/// This implementation enables `CngAesKey` to be used with decryption
/// operations in both AES-ECB and AES-CBC modes.
impl DecryptionKey for CngAesKey {}

/// Symmetric key trait implementation providing key length information.
impl SymmetricKey for CngAesKey {}

/// Marks this key as importable for key unwrapping operations.
impl ImportableKey for CngAesKey {
    /// Imports an AES key from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key material (must be 16, 24, or 32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully imported AES key
    /// * `Err(CryptoError)` - Key import failed
    ///
    /// # Errors
    ///
    /// * `AesInvalidKeySize` - If bytes length is not 16, 24, or 32
    /// * `AesKeyGenError` - If Windows CNG key import fails
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        CngAesKey::create_key(AesKeyGenArgs::Slice(bytes))
    }
}

/// Marks this key as exportable for key wrapping operations.
impl ExportableKey for CngAesKey {
    /// Exports the AES key to raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional buffer to receive the key material. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of the key in bytes
    /// * `Err(CryptoError)` - Key export failed
    ///
    /// # Errors
    ///
    /// * `AesInvalidBufferError` - If provided buffer is too small
    /// * `AesError` - If Windows CNG key export fails
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        const HDR_SIZE: usize = mem::size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>();
        if let Some(bytes) = bytes {
            if bytes.len() < self.size() {
                Err(CryptoError::AesBufferTooSmall)?;
            }

            let expected_size = self.bcrypt_export_key(None)?;

            #[cfg(test)]
            assert!(expected_size == HDR_SIZE + self.size());

            let mut blob = vec![0u8; expected_size];
            let _actual_size = self.bcrypt_export_key(Some(&mut blob))?;

            #[cfg(test)]
            assert!(_actual_size == expected_size);

            bytes[..self.size()].copy_from_slice(&blob[HDR_SIZE..HDR_SIZE + self.size()]);
        }
        Ok(self.size())
    }
}

/// Key generation trait implementation for creating random AES keys.
impl KeyGenerationOp for CngAesKey {
    type Key = Self;

    /// Generates a new random AES key of the specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Key size in bytes (must be 16, 24, or 32)
    ///
    /// # Returns
    ///
    /// * `Ok(Self::Key)` - Successfully generated AES key
    /// * `Err(CryptoError)` - Key generation failed
    ///
    /// # Errors
    ///
    /// * `AesInvalidKeySize` - If size is not 16, 24, or 32 bytes
    /// * `RngError` - If random number generation fails
    /// * `AesKeyGenError` - If Windows CNG key creation fails
    fn generate(size: usize) -> Result<Self::Key, CryptoError> {
        CngAesKey::create_key(AesKeyGenArgs::Size(size))
    }
}

impl CngAesKey {
    /// Creates a new CNG AES key with handles for both ECB and CBC modes.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Raw key material (16, 24, or 32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully created AES key
    /// * `Err(CryptoError)` - If key generation fails
    ///
    /// # Errors
    ///
    /// * `AesKeyGenError` - If Windows CNG key generation fails
    pub(crate) fn new(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            ecb_handle: CngAesKeyHandle::new(key_bytes)?,
            cbc_handle: CngAesKeyHandle::new(key_bytes)?,
            gcm_handle: CngAesKeyHandle::new(key_bytes)?,
        })
    }

    /// Returns the Windows CNG key handle for ECB mode operations.
    ///
    /// # Returns
    ///
    /// The underlying `BCRYPT_KEY_HANDLE` for use with CNG ECB APIs
    pub(crate) fn ecb_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.ecb_handle.handle()
    }

    /// Returns the Windows CNG key handle for CBC mode operations.
    ///
    /// # Returns
    ///
    /// The underlying `BCRYPT_KEY_HANDLE` for use with CNG CBC APIs
    pub(crate) fn cbc_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.cbc_handle.handle()
    }

    /// Returns the Windows CNG key handle for GCM mode operations.
    ///
    /// # Returns
    ///
    /// The underlying `BCRYPT_KEY_HANDLE` for use with CNG GCM APIs
    pub(crate) fn gcm_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.gcm_handle.handle()
    }

    /// Validates that the provided key size is supported by AES.
    ///
    /// # Arguments
    /// * `len` - Key length in bytes to validate
    ///
    /// # Returns
    /// * `true` - If the length is 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    /// * `false` - If the length is not a valid AES key size
    fn is_valid_key_size(len: usize) -> bool {
        matches!(len, 16 | 24 | 32)
    }

    /// Internal key generation function supporting both random generation and import.
    ///
    /// This function validates the key size, generates random bytes if needed,
    /// and creates key handles for both ECB and CBC modes.
    ///
    /// # Arguments
    ///
    /// * `args` - Key generation arguments (either size or existing key bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(CngAesKey)` - Successfully created AES key with ECB and CBC handles
    /// * `Err(CryptoError)` - Key generation or validation failure
    ///
    /// # Errors
    ///
    /// * `AesInvalidKeySize` - If the key size is not 16, 24, or 32 bytes
    /// * `RngError` - If random number generation fails (for Size variant)
    /// * `AesKeyGenError` - If Windows CNG key generation fails
    fn create_key<'a>(args: AesKeyGenArgs<'a>) -> Result<CngAesKey, CryptoError> {
        let bytes = match args {
            AesKeyGenArgs::Size(size) => {
                if !Self::is_valid_key_size(size) {
                    Err(CryptoError::AesInvalidKeySize)?;
                }
                let mut key_bytes = vec![0u8; size];
                Rng::rand_bytes(&mut key_bytes)?;
                key_bytes
            }
            AesKeyGenArgs::Slice(slice) => {
                if !Self::is_valid_key_size(slice.len()) {
                    Err(CryptoError::AesInvalidKeySize)?;
                }
                slice.to_vec()
            }
        };

        CngAesKey::new(&bytes)
    }

    /// Exports key data using Windows CNG BCryptExportKey API.
    ///
    /// This internal method exports the key blob from the CBC handle, which includes
    /// both the header and the raw key material.
    ///
    /// # Arguments
    ///
    /// * `slice` - Optional buffer to receive the exported key blob. If `None`, returns required size
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of the exported key blob data
    /// * `Err(CryptoError)` - If the key export operation fails
    ///
    /// # Errors
    ///
    /// * `AesError` - If the Windows CNG export operation fails
    ///
    /// # Notes
    ///
    /// The exported blob includes a `BCRYPT_KEY_DATA_BLOB_HEADER` followed by the raw key bytes.
    /// This method is used internally by the `KeyExportOp` trait implementation.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_export_key(&self, slice: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let mut size = 0u32;
        // SAFETY: Get required size for key export
        let status = unsafe {
            BCryptExportKey(
                self.cbc_handle(),
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_KEY_DATA_BLOB,
                slice,
                &mut size,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::AesError)?;
        Ok(size as usize)
    }
}

/// Internal enum for specifying AES key generation arguments.
///
/// This enum allows the internal key generation function to handle both
/// random key generation and key import from existing material in a unified way.
enum AesKeyGenArgs<'a> {
    /// Generate a random key of the specified size in bytes (16, 24, or 32)
    Size(usize),
    /// Import a key from the provided byte slice (must be 16, 24, or 32 bytes)
    Slice(&'a [u8]),
}

/// Windows CNG implementation of an AES-XTS key.
///
/// This structure wraps Windows BCrypt key handles for AES-XTS mode,
/// providing AES-XTS key management operations including generation, import,
/// and export through the Windows Cryptography Next Generation (CNG) APIs.
///
/// AES-XTS (XEX-based tweaked-codebook mode with ciphertext stealing) is
/// designed for disk encryption and requires keys that are twice the size
/// of standard AES keys (32 bytes for AES-128-XTS, 64 bytes for AES-256-XTS).
///
/// # Thread Safety
///
/// Windows CNG key handles are thread-safe and can be used from multiple threads.
#[derive(Clone)]
pub struct CngAesXtsKey {
    /// Windows CNG key handle for AES-XTS operations
    xts_handle: CngAesXtsKeyHandle,
}
/// Marker trait implementation indicating this is a cryptographic key.
impl Key for CngAesXtsKey {
    /// Returns the length of the AES-XTS key in bytes.
    ///
    /// The key size is 32 (AES-128-XTS) or 64 (AES-256-XTS) bytes,
    /// representing the combined size of the data and tweak keys.
    fn size(&self) -> usize {
        self.xts_handle.len()
    }

    /// Returns the length of the AES-XTS key in bits.
    ///
    /// The key size is 256 (AES-128-XTS) or 512 (AES-256-XTS) bits,
    /// representing the combined size of the data and tweak keys.
    fn bits(&self) -> usize {
        self.xts_handle.len() * 8
    }
}

/// Marks this key as containing secret material.
///
/// This implementation indicates that `CngAesXtsKey` contains sensitive
/// cryptographic material that must be protected and handled securely.
impl SecretKey for CngAesXtsKey {}

/// Provides symmetric key operations for AES-XTS XTS keys.
impl SymmetricKey for CngAesXtsKey {}

/// Marks this key as suitable for encryption operations.
///
/// This implementation enables `CngAesXtsKey` to be used with encryption
/// operations in AES-XTS mode.
impl EncryptionKey for CngAesXtsKey {}

/// Marks this key as suitable for decryption operations.
///
/// This implementation enables `CngAesXtsKey` to be used with decryption
/// operations in AES-XTS mode.
impl DecryptionKey for CngAesXtsKey {}
/// Key generation trait implementation for creating random AES-XTS keys.
impl KeyGenerationOp for CngAesXtsKey {
    type Key = Self;

    /// Generates a new random AES-XTS key of the specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - Key size in bytes (must be 32 or 64)
    ///
    /// # Returns
    ///
    /// * `Ok(Self::Key)` - Successfully generated AES-XTS key
    /// * `Err(CryptoError)` - Key generation failed
    ///
    /// # Errors
    ///
    /// * `AesXtsInvalidKeySize` - If size is not 32 or 64 bytes
    /// * `RngError` - If random number generation fails
    /// * `AesKeyGenError` - If Windows CNG key creation fails
    fn generate(size: usize) -> Result<Self::Key, CryptoError> {
        // Generate random bytes
        let mut key_bytes = vec![0u8; size];
        Rng::rand_bytes(&mut key_bytes)?;

        CngAesXtsKey::from_bytes(key_bytes.as_ref())
    }
}
/// Marks this key as importable for key unwrapping operations.
impl ImportableKey for CngAesXtsKey {
    /// Imports an AES XTS key from raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key material (must be 32 or 64 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully imported AES-XTS key
    /// * `Err(CryptoError)` - Key import failed
    ///
    /// # Errors
    ///
    /// * `AesXtsInvalidKeySize` - If bytes length is not 32 or 64
    /// * `AesXtsInvalidKey` - If the key halves are identical (`K1 == K2`)
    /// * `AesKeyGenError` - If Windows CNG key import fails
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        CngAesXtsKey::new(bytes)
    }
}
/// Marks this key as exportable for key wrapping operations.
impl ExportableKey for CngAesXtsKey {
    /// Exports the AES-XTS key to raw key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional buffer to receive the key material. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of the key in bytes
    /// * `Err(CryptoError)` - Key export failed
    ///
    /// # Errors
    ///
    /// * `AesInvalidBufferError` - If provided buffer is too small
    /// * `AesError` - If Windows CNG key export fails
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        const HDR_SIZE: usize = mem::size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>();
        if let Some(bytes) = bytes {
            if bytes.len() < self.size() {
                Err(CryptoError::AesXtsBufferTooSmall)?;
            }

            let expected_size = self.bcrypt_export_key(None)?;

            #[cfg(test)]
            assert!(expected_size == HDR_SIZE + self.size());

            let mut blob = vec![0u8; expected_size];
            let _actual_size = self.bcrypt_export_key(Some(&mut blob))?;

            #[cfg(test)]
            assert!(_actual_size == expected_size);

            bytes[..self.size()].copy_from_slice(&blob[HDR_SIZE..HDR_SIZE + self.size()]);
        }
        Ok(self.size())
    }
}
impl CngAesXtsKey {
    /// Creates a new CNG AES-XTS key with handle for XTS mode.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Raw key material (32 or 64 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully created AES-XTS key
    /// * `Err(CryptoError)` - If key generation fails
    ///
    /// # Errors
    ///
    /// * `AesXtsInvalidKeySize` - If `key_bytes` length is not 32 or 64
    /// * `AesXtsInvalidKey` - If the key halves are identical (`K1 == K2`)
    /// * `AesKeyGenError` - If Windows CNG key generation fails
    fn new(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        // Validate the AES-XTS key material before creating the CNG handle.
        Self::is_valid_key(key_bytes)?;
        Ok(Self {
            xts_handle: CngAesXtsKeyHandle::new(key_bytes)?,
        })
    }

    /// Returns the Windows CNG key handle for XTS mode operations.
    ///
    /// # Returns
    ///
    /// The underlying `BCRYPT_KEY_HANDLE` for use with CNG XTS APIs
    pub(crate) fn xts_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.xts_handle.handle()
    }

    /// Validates raw AES-XTS key material.
    ///
    /// AES-XTS keys are a concatenation of two independent AES keys (K1 || K2):
    /// - 32 bytes total for AES-128-XTS (16 + 16)
    /// - 64 bytes total for AES-256-XTS (32 + 32)
    ///
    /// Some backends reject identical halves, so we enforce `K1 != K2` here.
    ///
    /// # Arguments
    /// * `key` - Raw key material to validate
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key length is not 32 or 64 bytes.
    /// - The key halves are identical.
    fn is_valid_key(key: &[u8]) -> Result<(), CryptoError> {
        // Check key size.
        if key.len() != 32 && key.len() != 64 {
            Err(CryptoError::AesXtsInvalidKeySize)?;
        }
        // AES-XTS requires independent keys (K1 != K2).
        let (k1, k2) = key.split_at(key.len() / 2);
        if k1 == k2 {
            Err(CryptoError::AesXtsInvalidKey)?;
        }
        Ok(())
    }

    /// Exports key data using Windows CNG BCryptExportKey API.
    ///
    /// This internal method exports the key blob from the XTS handle, which includes
    /// both the header and the raw key material.
    ///
    /// # Arguments
    ///
    /// * `slice` - Optional buffer to receive the exported key blob. If `None`, returns required size
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of the exported key blob data
    /// * `Err(CryptoError)` - If the key export operation fails
    ///
    /// # Errors
    ///
    /// * `AesError` - If the Windows CNG export operation fails
    ///
    /// # Notes
    ///
    /// The exported blob includes a `BCRYPT_KEY_DATA_BLOB_HEADER` followed by the raw key bytes.
    /// This method is used internally by the `KeyExportOp` trait implementation.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_export_key(&self, slice: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let mut size = 0u32;
        // SAFETY: Get required size for key export
        let status = unsafe {
            BCryptExportKey(
                self.xts_handle(),
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_KEY_DATA_BLOB,
                slice,
                &mut size,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::AesError)?;
        Ok(size as usize)
    }
}

/// Marker trait for AES algorithm modes.
///
/// This trait provides type-level differentiation between different AES cipher modes
/// (ECB, CBC, etc.) when working with Windows CNG key handles. Each mode implements
/// this trait to provide the appropriate `BCRYPT_ALG_HANDLE` for that mode.
///
/// # Implementors
///
/// * `EcbMode` - AES-ECB (Electronic Codebook) mode
/// * `CbcMode` - AES-CBC (Cipher Block Chaining) mode
pub trait AesAlgoMode {
    /// Returns the Windows CNG algorithm handle for this mode.
    ///
    /// # Returns
    ///
    /// The `BCRYPT_ALG_HANDLE` constant corresponding to this AES mode.
    fn algo_handle() -> BCRYPT_ALG_HANDLE;
}

/// Marker type for AES-ECB mode.
///
/// Electronic Codebook (ECB) mode is the simplest block cipher mode where each
/// block of plaintext is encrypted independently. This marker type is used with
/// `CngAesKeyHandle` to create ECB-mode key handles.
///
/// # Security Warning
///
/// ECB mode does not provide semantic security and should not be used for most
/// cryptographic applications. Identical plaintext blocks produce identical ciphertext
/// blocks, which can leak information about the data structure.

#[derive(Clone)]
pub struct EcbMode;

impl AesAlgoMode for EcbMode {
    fn algo_handle() -> BCRYPT_ALG_HANDLE {
        BCRYPT_AES_ECB_ALG_HANDLE
    }
}

/// Marker type for AES-CBC mode.
///
/// Cipher Block Chaining (CBC) mode is a block cipher mode where each block of
/// plaintext is XORed with the previous ciphertext block before encryption. This
/// marker type is used with `CngAesKeyHandle` to create CBC-mode key handles.
///
/// CBC mode requires an initialization vector (IV) and provides better security
/// than ECB mode for most applications.

#[derive(Clone)]
pub struct CbcMode;

impl AesAlgoMode for CbcMode {
    fn algo_handle() -> BCRYPT_ALG_HANDLE {
        BCRYPT_AES_CBC_ALG_HANDLE
    }
}

/// Marker type for AES-XTS mode.
///
/// XEX-based tweaked-codebook mode with ciphertext stealing (XTS) is a block cipher
/// mode designed for disk encryption. This marker type is used with `CngAesKeyHandle`
/// to create XTS-mode key handles.
///
/// XTS mode uses two keys: one for encryption and one for the tweak. The combined key
/// length must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS).
#[derive(Clone)]
pub struct XtsMode;

impl AesAlgoMode for XtsMode {
    fn algo_handle() -> BCRYPT_ALG_HANDLE {
        BCRYPT_XTS_AES_ALG_HANDLE
    }
}

/// Marker type for AES-GCM mode.
///
/// Galois/Counter Mode (GCM) is an authenticated encryption mode that provides
/// both confidentiality and authenticity. This marker type is used with
/// `CngAesKeyHandle` to create GCM-mode key handles.
///
/// GCM mode requires an initialization vector (IV) and produces an authentication
/// tag that verifies the integrity and authenticity of both the ciphertext and
/// any additional authenticated data (AAD).
#[derive(Clone)]
pub struct GcmMode;

impl AesAlgoMode for GcmMode {
    fn algo_handle() -> BCRYPT_ALG_HANDLE {
        BCRYPT_AES_GCM_ALG_HANDLE
    }
}

/// Generic Windows CNG key handle wrapper for AES operations.
///
/// This structure provides a type-safe wrapper around Windows CNG key handles
/// for different AES modes of operation. The generic parameter `M` is a marker
/// type that implements `AesAlgoMode` to specify the algorithm mode (e.g., ECB or CBC).
///
/// # Type Parameters
///
/// * `M` - A marker type implementing `AesAlgoMode`. Common values include:
///   - `EcbMode` for AES-ECB mode
///   - `CbcMode` for AES-CBC mode
///
/// # Thread Safety
///
/// Windows CNG key handles are thread-safe and can be used from multiple threads.
///
/// # Lifetime
///
/// The key handle is automatically destroyed when this structure is dropped,
/// ensuring proper resource cleanup.
pub struct CngAesKeyHandle<M: AesAlgoMode> {
    /// Windows CNG key handle for the specified algorithm mode
    handle: BCRYPT_KEY_HANDLE,
    /// Size of the key in bytes (16, 24, or 32)
    len: usize,
    /// PhantomData to hold the mode marker
    _mode: std::marker::PhantomData<M>,
}

impl<M: AesAlgoMode> CngAesKeyHandle<M> {
    /// Creates a new CNG AES key handle by generating a symmetric key.
    ///
    /// This method creates a Windows CNG key handle for the algorithm mode specified
    /// by the type parameter `M`. The key material is imported into the CNG subsystem
    /// and managed securely by the Windows kernel.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Raw key material (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully created key handle
    /// * `Err(CryptoError::AesKeyGenError)` - If key generation fails
    ///
    /// # Errors
    ///
    /// Returns `AesKeyGenError` if the Windows CNG `BCryptGenerateSymmetricKey` operation fails.
    ///
    /// # Safety
    ///
    /// This method uses unsafe Windows CNG APIs but ensures proper error handling.
    /// The created handle is automatically cleaned up when the structure is dropped.
    #[allow(unsafe_code)]
    pub(crate) fn new(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        //SAFETY: Generate symmetric key for the specified algorithm mode
        let status = unsafe {
            BCryptGenerateSymmetricKey(M::algo_handle(), &mut handle, None, key_bytes, 0)
        };
        status.ok().map_err(|_| CryptoError::AesKeyGenError)?;

        Ok(Self {
            handle,
            len: key_bytes.len(),
            _mode: std::marker::PhantomData,
        })
    }

    /// Returns the Windows CNG key handle.
    ///
    /// # Returns
    ///
    /// The underlying `BCRYPT_KEY_HANDLE` for use with CNG APIs
    pub(crate) fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    /// Returns the size of the key in bytes.
    ///
    /// # Returns
    ///
    /// The key size: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Automatic cleanup implementation that destroys the Windows CNG key handle.
///
/// This ensures that the key handle is properly released when the `CngAesKeyHandle`
/// goes out of scope, preventing resource leaks.
impl<M: AesAlgoMode> Drop for CngAesKeyHandle<M> {
    /// Destroys the underlying Windows CNG key handle.
    ///
    /// This method is called automatically when the key is dropped.
    /// Any errors during cleanup are silently ignored as there's no
    /// meaningful way to handle them during drop.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API to destroy the key handle.
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

impl<M: AesAlgoMode> Clone for CngAesKeyHandle<M> {
    #[allow(unsafe_code)]
    fn clone(&self) -> Self {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        //SAFETY: Duplicate the existing key handle
        let status = unsafe { BCryptDuplicateKey(self.handle, &mut handle, None, 0) };

        // Clone cannot fail.
        if status.is_err() {
            panic!("Failed to duplicate AES CNG key handle");
        }

        Self {
            handle,
            len: self.len,
            _mode: std::marker::PhantomData,
        }
    }
}
