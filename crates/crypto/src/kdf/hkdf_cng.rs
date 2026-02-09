// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HKDF (HMAC-based Key Derivation Function) implementation using Windows CNG.
//!
//! This module provides HKDF key derivation operations using the Windows Cryptography
//! Next Generation (CNG) API. HKDF is a key derivation function defined in RFC 5869
//! that uses HMAC to derive keys from input key material.
//!
//! # HKDF Process
//!
//! HKDF consists of two phases:
//!
//! 1. **Extract**: Derives a pseudorandom key (PRK) from input key material (IKM) and optional salt
//! 2. **Expand**: Expands the PRK into multiple output keying material (OKM) bytes
//!
//! # Supported Hash Functions
//!
//! - SHA-1 (deprecated for cryptographic use, provided for compatibility)
//! - SHA-256
//! - SHA-384
//! - SHA-512
//!
//! # Security Considerations
//!
//! - Salt should be random and unique for each derivation
//! - Info parameter provides domain separation
//! - Output length should match the required key size

use windows::Win32::Security::Cryptography::*;

use super::*;

/// HKDF key derivation operation using Windows CNG.
///
/// This structure holds the configuration for an HKDF key derivation operation,
/// including the mode (extract, expand, or both), hash algorithm, salt, and info parameters.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the referenced hash algorithm and optional parameters
///
/// # Fields
///
/// * `mode` - The HKDF operation mode (Extract, Expand, or ExtractAndExpand)
/// * `hash` - Hash algorithm to use for HKDF-HMAC operations
/// * `salt` - Optional salt value for the extract phase
/// * `info` - Optional context/application-specific info for the expand phase
pub struct CngHkdfAlgo<'a> {
    mode: HkdfMode,
    hash: &'a HashAlgo,
    salt: Option<&'a [u8]>,
    info: Option<&'a [u8]>,
}

impl<'a> CngHkdfAlgo<'a> {
    /// Creates a new HKDF operation with the specified parameters.
    ///
    /// # Parameters
    ///
    /// * `mode` - The HKDF operation mode (Extract, Expand, or ExtractAndExpand)
    /// * `hash` - Reference to the hash algorithm to use
    /// * `salt` - Optional salt for the extract phase (recommended for security)
    /// * `info` - Optional context information for the expand phase
    ///
    /// # Returns
    ///
    /// A new `CngHkdf` instance configured with the specified parameters.
    pub fn new(
        mode: HkdfMode,
        hash: &'a HashAlgo,
        salt: Option<&'a [u8]>,
        info: Option<&'a [u8]>,
    ) -> CngHkdfAlgo<'a> {
        CngHkdfAlgo {
            mode,
            hash,
            salt,
            info,
        }
    }
}

impl<'a> DeriveOp for CngHkdfAlgo<'a> {
    /// The source key type (generic secret key).
    type Key = GenericSecretKey;
    /// The derived key type (generic secret key).
    type DerivedKey = GenericSecretKey;

    /// Performs HKDF key derivation according to the configured mode.
    ///
    /// This method implements the HKDF algorithm as specified in RFC 5869.
    /// Depending on the mode, it performs extraction, expansion, or both.
    ///
    /// # Parameters
    ///
    /// * `key` - The input key material (IKM) or pseudorandom key (PRK)
    /// * `length` - The desired length of the output keying material in bytes
    ///
    /// # Returns
    ///
    /// A derived key of the specified length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Extract mode is used and length doesn't match the hash output size
    /// - Expand mode is used and the PRK length doesn't match the hash output size
    /// - The key derivation operation fails
    /// - Memory allocation fails
    fn derive(&self, key: &Self::Key, length: usize) -> Result<Self::DerivedKey, CryptoError> {
        let key_vec = key.to_vec()?;

        // Perform HKDF Extract
        let prk = if self.mode == HkdfMode::Extract || self.mode == HkdfMode::ExtractAndExpand {
            if self.mode == HkdfMode::Extract && length != self.hash.size() {
                Err(CryptoError::HmacInvalidDerivedKeyLength)?;
            }
            CngHkdfKeyHandle::with_salt(&key_vec, self.hash, self.salt)?
        } else {
            // if key extraction is not requested than `key` is PRK
            if key.size() != self.hash.size() {
                // Length of PRK must be equal to hash output size
                return Err(CryptoError::HkdfInvalidPrkLength);
            }
            CngHkdfKeyHandle::with_prk(&key_vec, self.hash)?
        };

        // Perform HKDF Expand
        let okm = if self.mode == HkdfMode::Expand || self.mode == HkdfMode::ExtractAndExpand {
            // if key expansion is requested than produce OKM
            prk.derive_vec(self.info, length)?
        } else {
            // if key expansion is not requested than PRK is the OKM
            prk.to_vec()?
        };

        GenericSecretKey::from_bytes(&okm)
    }
}

impl<'a> CngHkdfAlgo<'a> {}

/// RAII wrapper for Windows CNG HKDF key handles.
///
/// This structure manages a `BCRYPT_KEY_HANDLE` representing an HKDF key.
/// The handle is automatically cleaned up when the structure is dropped,
/// ensuring proper resource management.
///
/// # Fields
///
/// * `handle` - The underlying Windows CNG key handle
struct CngHkdfKeyHandle {
    handle: BCRYPT_KEY_HANDLE,
}

impl Drop for CngHkdfKeyHandle {
    /// Automatically cleans up the CNG key handle when dropped.
    ///
    /// This ensures that Windows CNG resources are properly released.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Calling BCryptDestroyKey with a valid BCRYPT_KEY_HANDLE.
        // - self.handle is a valid handle obtained from BCryptGenerateSymmetricKey
        // - The handle is only destroyed once as Drop is called exactly once
        // - Ignoring the result is safe as cleanup is best-effort during Drop
        let _ = unsafe { BCryptDestroyKey(self.handle) };
    }
}

impl Clone for CngHkdfKeyHandle {
    #[allow(unsafe_code)]
    fn clone(&self) -> Self {
        // Duplicate the existing key handle using BCryptDuplicateKey
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Calling Windows CNG API to duplicate a key handle. self.handle is valid.
        let status = unsafe { BCryptDuplicateKey(self.handle, &mut handle, None, 0) };

        // Clone cannot fail.
        if status.is_err() {
            panic!("Failed to duplicate HKDF CNG key handle");
        }

        Self { handle }
    }
}

impl CngHkdfKeyHandle {
    /// Creates a new HKDF key handle from key material.
    ///
    /// This method initializes a CNG key handle and sets the hash algorithm.
    ///
    /// # Parameters
    ///
    /// * `key` - The key material bytes
    /// * `hash` - The hash algorithm to use for HKDF
    ///
    /// # Returns
    ///
    /// A new key handle configured with the specified hash algorithm.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfError` if handle creation or hash algorithm setup fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn new(key: &[u8], hash: &HashAlgo) -> Result<Self, CryptoError> {
        let key = Self {
            handle: Self::crate_handle(key)?,
        };
        key.set_hash_alog(hash)?;
        Ok(key)
    }

    /// Creates a new HKDF key handle with salt for the extract phase.
    ///
    /// This method performs the HKDF extract phase, deriving a pseudorandom key (PRK)
    /// from the input key material and optional salt.
    ///
    /// # Parameters
    ///
    /// * `ikm` - Input key material bytes
    /// * `hash` - The hash algorithm to use
    /// * `salt` - Optional salt value (empty if None)
    ///
    /// # Returns
    ///
    /// A finalized key handle containing the extracted PRK.
    ///
    /// # Errors
    ///
    /// Returns an error if key creation or finalization fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn with_salt(ikm: &[u8], hash: &HashAlgo, salt: Option<&[u8]>) -> Result<Self, CryptoError> {
        let key = Self::new(ikm, hash)?;
        key.finalize_with_salt(salt)?;
        Ok(key)
    }

    /// Creates a new HKDF key handle from a pseudorandom key (PRK).
    ///
    /// This method creates a key handle from an existing PRK, skipping the extract phase.
    /// The PRK is typically the output of a previous HKDF extract operation.
    ///
    /// # Parameters
    ///
    /// * `prk` - Pseudorandom key bytes
    /// * `hash` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A finalized key handle ready for the expand phase.
    ///
    /// # Errors
    ///
    /// Returns an error if key creation or finalization fails.
    fn with_prk(prk: &[u8], hash: &HashAlgo) -> Result<Self, CryptoError> {
        let key = Self::new(prk, hash)?;
        key.finalize()?;
        Ok(key)
    }

    /// Derives output keying material (OKM) using the expand phase.
    ///
    /// This method performs the HKDF expand phase, generating the requested number
    /// of output bytes from the PRK and optional info parameter.
    ///
    /// # Parameters
    ///
    /// * `info` - Optional context/application-specific information
    /// * `length` - The desired length of output keying material in bytes
    ///
    /// # Returns
    ///
    /// A vector containing the derived keying material.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfDeriveError` if the derivation operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn derive_vec(&self, info: Option<&[u8]>, length: usize) -> Result<Vec<u8>, CryptoError> {
        // Build parameter list for expand phase
        let params = self.build_params(info);

        let param_list = if params.is_empty() {
            None
        } else {
            Some(BCryptBufferDesc {
                ulVersion: BCRYPTBUFFER_VERSION,
                cBuffers: params.len() as u32,
                pBuffers: params.as_ptr() as *mut _,
            })
        };

        // Perform key derivation (Expand phase)
        let mut key = vec![0u8; length];
        let mut bytes_copied: u32 = 0;

        // SAFETY: Calling BCryptKeyDerivation with valid parameters.
        // - self.handle is a valid finalized BCRYPT_KEY_HANDLE
        // - param_list contains valid BCryptBufferDesc if present, None otherwise
        // - key is a valid mutable buffer allocated to the requested length
        // - bytes_copied is a valid mutable reference to receive the actual output size
        // - Flags set to 0 for default behavior
        let status = unsafe {
            BCryptKeyDerivation(
                self.handle,
                param_list.as_ref().map(|p| p as *const _),
                &mut key,
                &mut bytes_copied as *mut u32,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::HkdfDeriveError)?;
        key.truncate(bytes_copied as usize);

        Ok(key)
    }

    /// Exports the key material as a vector of bytes.
    ///
    /// This method exports the key from the CNG handle and extracts the raw key material
    /// by parsing the Windows CNG key blob format.
    ///
    /// # Returns
    ///
    /// A vector containing the raw key material bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key export fails
    /// - Blob format is invalid
    /// - Memory allocation fails
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn to_vec(&self) -> Result<Vec<u8>, CryptoError> {
        // Get required buffer size for key export
        let size = self.bcrypt_export_key(None)?;

        // Export key blob
        let mut key_blob = vec![0u8; size];
        self.bcrypt_export_key(Some(&mut key_blob))?;

        // Skip header to get raw key material
        //
        // BLOB is in follwing format:
        // - Header (BCRYPT_KEY_DATA_BLOB_HEADER))
        // - ALGO ID Length (u32 big-endian)
        // - ALGO ID string (bytes. length as per previous field)
        // - Key material (bytes)
        //
        // Since the key is created internally we do not need to extesnively
        // valide the blob header and algorithm id.
        let mut skip_bytes = std::mem::size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>();
        skip_bytes += {
            let algo_id_len = u32::from_be_bytes(
                key_blob[skip_bytes..skip_bytes + std::mem::size_of::<u32>()]
                    .try_into()
                    .map_err(|_| CryptoError::HkdfDeriveError)?,
            );
            std::mem::size_of::<u32>() + algo_id_len as usize
        };

        Ok(key_blob.iter().skip(skip_bytes).cloned().collect())
    }

    /// Creates a Windows CNG key handle from raw key bytes.
    ///
    /// This method generates a symmetric key handle using the Windows CNG HKDF algorithm.
    ///
    /// # Parameters
    ///
    /// * `key` - The raw key material bytes
    ///
    /// # Returns
    ///
    /// A Windows CNG key handle.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfError` if key generation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn crate_handle(key: &[u8]) -> Result<BCRYPT_KEY_HANDLE, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Calling BCryptGenerateSymmetricKey with valid parameters.
        // - BCRYPT_HKDF_ALG_HANDLE is a valid global algorithm handle
        // - handle is a valid mutable reference to receive the key handle
        // - None for pbKeyObject means CNG manages the key object internally
        // - key is a valid byte slice
        // - Flags set to 0 for default behavior
        let status = unsafe {
            BCryptGenerateSymmetricKey(BCRYPT_HKDF_ALG_HANDLE, &mut handle, None, key, 0)
        };
        status.ok().map_err(|_| CryptoError::HkdfError)?;
        Ok(handle)
    }

    /// Sets the hash algorithm for the HKDF operation.
    ///
    /// This method configures the Windows CNG key handle to use the specified
    /// hash algorithm for HKDF-HMAC operations.
    ///
    /// # Parameters
    ///
    /// * `hash` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// Success if the hash algorithm is set correctly.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfError` if the property cannot be set.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn set_hash_alog(&self, hash: &HashAlgo) -> Result<(), CryptoError> {
        let algo_id = hash.algo_id();
        // SAFETY: Creating a byte slice from wide string and calling BCryptSetProperty.
        // - alog_id_wide.as_ptr() is valid for the lifetime of alog_id_wide
        // - Length calculation includes all wide characters plus null terminator
        // - from_raw_parts creates a valid slice for the calculated length
        // - self.handle is a valid BCRYPT_KEY_HANDLE
        // - BCRYPT_HKDF_HASH_ALGORITHM is a valid property identifier
        // - bytes slice is valid and properly sized
        let status = unsafe {
            let alog_id_wide = algo_id.as_wide();
            let bytes = std::slice::from_raw_parts(
                alog_id_wide.as_ptr() as *const u8,
                (alog_id_wide.len() + 1) * std::mem::size_of::<u16>(),
            );
            BCryptSetProperty(self.handle.into(), BCRYPT_HKDF_HASH_ALGORITHM, bytes, 0)
        };
        status.ok().map_err(|_| CryptoError::HkdfError)
    }

    /// Finalizes the HKDF key handle without a salt.
    ///
    /// This method marks the key as ready for use in the expand phase. It should be
    /// called when using a pre-existing PRK (Expand mode only).
    ///
    /// # Returns
    ///
    /// Success if the key is finalized correctly.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfError` if finalization fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    ///
    /// # Implementation Note
    ///
    /// Uses a direct system call to work around a windows-rs limitation with NULL pointers.
    #[allow(unsafe_code)]
    fn finalize(&self) -> Result<(), CryptoError> {
        // WORKAROUND: Following code is needed to workaround the issue where CNG for HKDF
        // expects pbInput to be NULL and cbInput to be 0 when finalizing without salt.
        // windows-rs BCryptSetProperty passes pbInput as a valid pointer and cbInput as
        // zero. However, CNG treats the pbInput as an invalid parameter even though cbInput
        // is zero and returns an error.
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            #[link_name = "BCryptSetProperty"]
            fn _BCryptSetProperty(
                hObject: BCRYPT_HANDLE,
                pszProperty: windows::core::PCWSTR,
                pbInput: *const u8,
                cbInput: u32,
                flags: u32,
            ) -> windows::Win32::Foundation::NTSTATUS;
        }

        // SAFETY: Calling _BCryptSetProperty directly with NULL pointer.
        // - self.handle is a valid BCRYPT_KEY_HANDLE
        // - BCRYPT_HKDF_PRK_AND_FINALIZE is a valid property identifier
        // - std::ptr::null() is explicitly required by CNG for this operation
        // - cbInput is 0 to match the NULL pointer
        // - Flags set to 0 for default behavior
        // This workaround is necessary because windows-rs doesn't support NULL pointers
        // for this specific CNG operation which requires NULL for finalization without salt
        let status = unsafe {
            _BCryptSetProperty(
                self.handle.into(),
                BCRYPT_HKDF_PRK_AND_FINALIZE,
                std::ptr::null(),
                0,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::HkdfError)
    }

    /// Finalizes the HKDF key handle with a salt value.
    ///
    /// This method completes the extract phase by applying the salt and finalizing
    /// the key as a PRK ready for expansion.
    ///
    /// # Parameters
    ///
    /// * `salt` - Optional salt value (empty if None)
    ///
    /// # Returns
    ///
    /// Success if the key is finalized correctly.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfError` if finalization fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn finalize_with_salt(&self, salt: Option<&[u8]>) -> Result<(), CryptoError> {
        let salt = salt.unwrap_or(&[]);
        // SAFETY: Calling BCryptSetProperty with salt parameter.
        // - self.handle is a valid BCRYPT_KEY_HANDLE
        // - BCRYPT_HKDF_SALT_AND_FINALIZE is a valid property identifier
        // - salt is a valid byte slice (empty slice if None)
        // - Flags set to 0 for default behavior
        let status = unsafe {
            BCryptSetProperty(self.handle.into(), BCRYPT_HKDF_SALT_AND_FINALIZE, salt, 0)
        };
        status.ok().map_err(|_| CryptoError::HkdfError)
    }

    /// Builds the parameter list for the HKDF expand operation.
    ///
    /// This method constructs a Windows CNG buffer descriptor containing the
    /// optional info parameter for key derivation.
    ///
    /// # Parameters
    ///
    /// * `info` - Optional context/application-specific information
    ///
    /// # Returns
    ///
    /// A vector of BCryptBuffer structures for the CNG API.
    fn build_params(&self, info: Option<&[u8]>) -> Vec<BCryptBuffer> {
        let default_info = [];
        let info_bytes = info.unwrap_or(&default_info);

        let mut params = Vec::new();

        // Add info parameter for expansion if provided
        if !info_bytes.is_empty() {
            params.push(BCryptBuffer {
                cbBuffer: info_bytes.len() as u32,
                BufferType: KDF_HKDF_INFO,
                pvBuffer: info_bytes.as_ptr() as *mut _,
            });
        }

        params
    }

    /// Exports the key material from the CNG handle.
    ///
    /// This method uses the Windows CNG BCryptExportKey API to export the key
    /// in KEY_DATA_BLOB format.
    ///
    /// # Parameters
    ///
    /// * `output` - Optional output buffer. If None, only returns required size.
    ///
    /// # Returns
    ///
    /// The size of the exported key blob in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HkdfDeriveError` if the export operation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn bcrypt_export_key(&self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let mut size = 0u32;
        // SAFETY: Calling BCryptExportKey to get size or export key.
        // - self.handle is a valid BCRYPT_KEY_HANDLE
        // - BCRYPT_KEY_HANDLE::default() (NULL) for hExportKey means no key encryption
        // - BCRYPT_KEY_DATA_BLOB is a valid blob type identifier
        // - output is either None or a valid mutable buffer
        // - size is a valid mutable reference to receive required/actual size
        // - Flags set to 0 for default behavior
        let status = unsafe {
            BCryptExportKey(
                self.handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_KEY_DATA_BLOB,
                output,
                &mut size,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::HkdfDeriveError)?;
        Ok(size as usize)
    }
}
