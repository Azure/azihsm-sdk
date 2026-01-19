// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG ECC key management.
//!
//! This module provides ECC key operations using Windows Cryptography Next Generation (CNG) APIs.
//! It supports both ECDSA (signing/verification) and ECDH (key agreement) operations on the
//! NIST P-256, P-384, and P-521 curves.
//!
//! # Architecture
//!
//! Windows CNG requires separate key handles for ECDSA and ECDH operations, even for the same
//! key material. This module maintains both handles in [`CngEccPrivateKey`] and [`CngEccPublicKey`]
//! to support both operation types efficiently.
//!
//! # Key Format
//!
//! Keys can be imported/exported in DER format (PKCS#8 for private keys, X.509 SubjectPublicKeyInfo
//! for public keys). Internally, Windows CNG uses a proprietary blob format with a header containing
//! the magic number (identifying curve and key type) and the key components (x, y, and optionally d).

use std::marker::PhantomData;

use windows::Win32::Security::Cryptography::*;

use super::*;

type CngEcdsaPrivateKeyHandle = CngEccKeyHandle<CngEcdsaPrivateKeyInfo>;
type CngEcdsaPublicKeyHandle = CngEccKeyHandle<CngEcdsaPublicKeyInfo>;
type CngEcdhPrivateKeyHandle = CngEccKeyHandle<CngEcdhPrivateKeyInfo>;
type CngEcdhPublicKeyHandle = CngEccKeyHandle<CngEcdhPublicKeyInfo>;

#[allow(unsafe_code)]
// SAFETY: CngEccPrivateKey wraps Windows CNG handles which are thread-safe and can be sent across threads
unsafe impl Send for CngEccPrivateKey {}

#[allow(unsafe_code)]
// SAFETY: CngEccPrivateKey wraps Windows CNG handles which are thread-safe and can be shared across threads
unsafe impl Sync for CngEccPrivateKey {}

#[allow(unsafe_code)]
// SAFETY: CngEccPublicKey wraps Windows CNG handles which are thread-safe and can be sent across threads
unsafe impl Send for CngEccPublicKey {}

#[allow(unsafe_code)]
// SAFETY: CngEccPublicKey wraps Windows CNG handles which are thread-safe and can be shared across threads
unsafe impl Sync for CngEccPublicKey {}

/// Windows CNG ECC private key supporting both ECDSA and ECDH operations.
///
/// This key maintains separate handles for ECDSA (signing/verification) and
/// ECDH (key agreement) operations, as required by the Windows CNG API.
#[derive(Debug, Clone)]
pub struct CngEccPrivateKey {
    ecdsa_key: CngEcdsaPrivateKeyHandle,
    ecdh_key: CngEcdhPrivateKeyHandle,
}

/// Marks this type as a cryptographic key.
impl Key for CngEccPrivateKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.curve().point_size()
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.curve().bit_size()
    }
}

/// Marks this type as a key that can be used for key derivation.
impl DerivationKey for CngEccPrivateKey {}

/// Marks this type as a key that can be used for signing operations.
impl SigningKey for CngEccPrivateKey {}

impl PrivateKey for CngEccPrivateKey {
    type PublicKey = CngEccPublicKey;

    /// Derives the public key from this private key.
    ///
    /// Creates a new [`CngEccPublicKey`] containing only the public components (x, y)
    /// by exporting the private key and truncating the private component (d).
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        Ok(CngEccPublicKey {
            ecdsa_key: CngEcdsaPublicKeyHandle::try_from(&self.ecdsa_key)?,
            ecdh_key: CngEcdhPublicKeyHandle::try_from(&self.ecdh_key)?,
        })
    }
}

/// Marks this key as exportable.
impl ExportableKey for CngEccPrivateKey {
    /// Exports the private key in DER format (PKCS#8).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let der_key = DerEccPrivateKey::try_from(&self.ecdsa_key)?;
        der_key.to_der(bytes)
    }
}

/// Marks this key as importable.
impl ImportableKey for CngEccPrivateKey {
    /// Imports a private key from DER format (PKCS#8).
    ///
    /// Creates both ECDSA and ECDH handles from the imported key material.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded private key
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let der_key = DerEccPrivateKey::from_der(bytes)?;

        let ecdsa_key = CngEcdsaPrivateKeyHandle::try_from(&der_key)?;
        let ecdh_key = CngEcdhPrivateKeyHandle::try_from(&der_key)?;

        Ok(Self {
            ecdsa_key,
            ecdh_key,
        })
    }
}

impl KeyGenerationOp for CngEccPrivateKey {
    type Key = Self;

    /// Generates a new random ECC private key.
    ///
    /// # Arguments
    ///
    /// * `size` - Key size in bits (256, 384, or 521)
    ///
    /// # Returns
    ///
    /// A new private key with both ECDSA and ECDH handles.
    ///
    /// # Security
    ///
    /// Uses Windows CNG's cryptographically secure random number generator.
    fn generate(size: usize) -> Result<Self, CryptoError> {
        let curve = EccCurve::try_from(size)?;
        let ecdsa_key = CngEcdsaPrivateKeyHandle::new(curve)?;
        let ecdh_key = CngEcdhPrivateKeyHandle::try_from(&ecdsa_key)?;
        Ok(Self {
            ecdsa_key,
            ecdh_key,
        })
    }
}

impl EccKeyOp for CngEccPrivateKey {
    /// Returns the elliptic curve used by this key.
    ///
    /// # Returns
    ///
    /// The `EccCurve` identifier (P256, P384, or P521).
    fn curve(&self) -> EccCurve {
        self.ecdsa_key.curve()
    }

    /// Retrieves the X and Y coordinates of the public key point.
    ///
    /// This method can either return the required buffer size (when `coord` is `None`)
    /// or copy the coordinates to the provided buffers (when `coord` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `coord` - Optional tuple of mutable buffers for (x, y) coordinates.
    ///
    /// # Returns
    ///
    /// The size of each coordinate in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffers are too small.
    fn coord(&self, coord: Option<(&mut [u8], &mut [u8])>) -> Result<usize, CryptoError> {
        let len = self.curve().point_size();

        if let Some((x_buf, y_buf)) = coord {
            if x_buf.len() < len || y_buf.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }

            let blob = self.ecdsa_key.to_blob()?;

            x_buf.copy_from_slice(blob.x());
            y_buf.copy_from_slice(blob.y());

            self.x(Some(x_buf))?;
            self.y(Some(y_buf))?;
        }

        Ok(len)
    }
}

impl CngEccPrivateKey {
    /// Generates a new private key for the specified curve.
    ///
    /// Convenience method that wraps [`generate`](Self::generate) with curve-based sizing.
    pub fn from_curve(curve: EccCurve) -> Result<Self, CryptoError> {
        Self::generate(curve.bit_size())
    }

    /// Returns the ECDSA key handle for signing operations.
    pub(super) fn ecdsa_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.ecdsa_key.handle()
    }

    /// Returns the ECDH key handle for key agreement operations.
    pub(super) fn ecdh_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.ecdh_key.handle()
    }

    /// Exports the x-coordinate of the public key point.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    pub fn x(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.ecdsa_key.to_blob()?;
        if let Some(buf) = bytes {
            if buf.len() < blob.x().len() {
                Err(CryptoError::EccBufferTooSmall)?;
            }
            buf[..blob.x().len()].copy_from_slice(blob.x());
        }
        Ok(blob.x().len())
    }

    /// Exports the y-coordinate of the public key point.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    pub fn y(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.ecdsa_key.to_blob()?;
        if let Some(buf) = bytes {
            if buf.len() < blob.y().len() {
                Err(CryptoError::EccBufferTooSmall)?;
            }
            buf[..blob.y().len()].copy_from_slice(blob.y());
        }
        Ok(blob.y().len())
    }
}

/// Windows CNG ECC public key supporting both ECDSA and ECDH operations.
///
/// This key maintains separate handles for ECDSA (verification) and
/// ECDH (key agreement) operations, as required by the Windows CNG API.
#[derive(Debug, Clone)]
pub struct CngEccPublicKey {
    ecdsa_key: CngEcdsaPublicKeyHandle,
    ecdh_key: CngEcdhPublicKeyHandle,
}

/// Marks this type as a cryptographic key.
impl Key for CngEccPublicKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.curve().point_size()
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.curve().bit_size()
    }
}

/// Marks this type as a key that can be used for verification operations.
impl VerificationKey for CngEccPublicKey {}

/// Marks this type as a public key.
impl PublicKey for CngEccPublicKey {}

/// Marks this key as exportable.
impl ExportableKey for CngEccPublicKey {
    /// Exports the public key in DER format (X.509 SubjectPublicKeyInfo).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let der_key = DerEccPublicKey::try_from(&self.ecdsa_key)?;
        der_key.to_der(bytes)
    }
}

/// Marks this key as importable.
impl ImportableKey for CngEccPublicKey {
    ///
    /// Creates both ECDSA and ECDH handles from the imported key material.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded public key
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let der_key = DerEccPublicKey::from_der(bytes)?;

        let ecdsa_key = CngEcdsaPublicKeyHandle::try_from(&der_key)?;
        let ecdh_key = CngEcdhPublicKeyHandle::try_from(&der_key)?;

        Ok(Self {
            ecdsa_key,
            ecdh_key,
        })
    }
}

impl EccKeyOp for CngEccPublicKey {
    /// Returns the elliptic curve used by this key.
    ///
    /// # Returns
    ///
    /// The `EccCurve` identifier (P256, P384, or P521).
    fn curve(&self) -> EccCurve {
        self.ecdsa_key.curve()
    }

    /// Retrieves the X and Y coordinates of the public key point.
    ///
    /// This method can either return the required buffer size (when `coord` is `None`)
    /// or copy the coordinates to the provided buffers (when `coord` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `coord` - Optional tuple of mutable buffers for (x, y) coordinates.
    ///
    /// # Returns
    ///
    /// The size of each coordinate in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffers are too small.
    fn coord(&self, coord: Option<(&mut [u8], &mut [u8])>) -> Result<usize, CryptoError> {
        let len = self.curve().point_size();

        if let Some((x_buf, y_buf)) = coord {
            if x_buf.len() < len || y_buf.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }

            let blob = self.ecdsa_key.to_blob()?;

            x_buf.copy_from_slice(blob.x());
            y_buf.copy_from_slice(blob.y());

            self.x(Some(x_buf))?;
            self.y(Some(y_buf))?;
        }

        Ok(len)
    }
}

#[allow(dead_code)]
impl CngEccPublicKey {
    /// Returns the ECDSA key handle for verification operations.
    pub(super) fn ecdsa_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.ecdsa_key.handle()
    }

    /// Returns the ECDH key handle for key agreement operations.
    pub(super) fn ecdh_handle(&self) -> BCRYPT_KEY_HANDLE {
        self.ecdh_key.handle()
    }

    /// Returns the curve used by this key.
    pub fn curve(&self) -> EccCurve {
        self.ecdsa_key.curve()
    }

    /// Exports the x-coordinate of the public key point.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    fn x(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.ecdsa_key.to_blob()?;
        if let Some(buf) = bytes {
            if buf.len() < blob.x().len() {
                Err(CryptoError::EccBufferTooSmall)?;
            }
            buf[..blob.x().len()].copy_from_slice(blob.x());
        }
        Ok(blob.x().len())
    }

    /// Exports the y-coordinate of the public key point.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written (or required if `bytes` is `None`).
    fn y(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let blob = self.ecdsa_key.to_blob()?;
        if let Some(buf) = bytes {
            if buf.len() < blob.y().len() {
                Err(CryptoError::EccBufferTooSmall)?;
            }
            buf[..blob.y().len()].copy_from_slice(blob.y());
        }
        Ok(blob.y().len())
    }
}

/// Trait defining key type-specific operations for CNG ECC keys.
///
/// This trait abstracts the differences between ECDSA/ECDH and public/private keys,
/// providing the necessary information for Windows CNG operations including algorithm
/// handles, blob formats, and magic number conversions.
trait CngEccKeyInfo {
    /// Returns the algorithm handle for the given curve.
    ///
    /// Different curves and operations (ECDSA vs ECDH) require different algorithm handles.
    fn algo_handle(curve: EccCurve) -> BCRYPT_ALG_HANDLE;

    /// Returns the blob type identifier for import/export operations.
    ///
    /// Returns either `BCRYPT_ECCPRIVATE_BLOB` or `BCRYPT_ECCPUBLIC_BLOB`.
    fn blob_type() -> windows::core::PCWSTR;

    /// Extracts the curve from the blob magic number.
    ///
    /// Each combination of curve, key type, and operation has a unique magic number.
    fn curve_from_magic(magic: u32) -> Result<EccCurve, CryptoError>;

    /// Converts ECDSA magic number to ECDH magic number.
    ///
    /// Returns an error for ECDH key types (which are already ECDH).
    fn ecdh_magic_from_ecdsa(magic: u32) -> Result<u32, CryptoError>;

    /// Converts private key magic number to public key magic number.
    ///
    /// Returns an error for public key types (which cannot become private).
    fn priv_magic_from_pub(magic: u32) -> Result<u32, CryptoError>;

    /// Returns the number of key components in the blob.
    ///
    /// Returns 2 for public keys (x, y) and 3 for private keys (x, y, d).
    fn blob_component_count() -> usize;
}

/// Internal wrapper for Windows CNG key handles.
///
/// Provides RAII-style management of `BCRYPT_KEY_HANDLE` with automatic cleanup.
/// The `KeyInfo` type parameter distinguishes between ECDSA/ECDH and public/private keys.
#[derive(Debug)]
struct CngEccKeyHandle<KeyInfo: CngEccKeyInfo> {
    handle: BCRYPT_KEY_HANDLE,
    curve: EccCurve,
    marker: PhantomData<KeyInfo>,
}

impl<KeyInfo: CngEccKeyInfo> Clone for CngEccKeyHandle<KeyInfo> {
    /// Clones the key handle by exporting and re-importing the key blob.
    #[allow(unsafe_code)]
    fn clone(&self) -> Self {
        let Ok(bytes) = self.to_blob() else {
            // Clone cannot fail.
            panic!("Failed to export CNG ECC key blob for cloning");
        };
        let Ok(handle) = Self::from_blob(&bytes) else {
            // Clone cannot fail.
            panic!("Failed to import CNG ECC key blob for cloning");
        };
        handle
    }
}

impl<KeyInfo: CngEccKeyInfo> Drop for CngEccKeyHandle<KeyInfo> {
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

impl<KeyInfo: CngEccKeyInfo> CngEccKeyHandle<KeyInfo> {
    /// Generates a new random key pair using Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve to use
    ///
    /// # Returns
    ///
    /// A new key handle containing the generated key pair.
    #[allow(unsafe_code)]
    fn new(curve: EccCurve) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();

        // Generate key pair
        // SAFETY: Calling Windows CNG BCryptGenerateKeyPair API.
        // - algo_handle returns a valid BCRYPT_ALG_HANDLE for the curve
        // - handle is a valid mutable reference to store the result
        // - curve determines the key size
        let status = unsafe {
            BCryptGenerateKeyPair(
                KeyInfo::algo_handle(curve),
                &mut handle,
                curve.bit_size() as u32,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::EccKeyGenError)?;

        // Finalize the key pair
        // SAFETY: Calling Windows CNG BCryptFinalizeKeyPair to finalize the ECC key pair.
        // - handle is a valid BCRYPT_KEY_HANDLE from successful BCryptGenerateKeyPair call
        // - 0 flags means standard finalization
        let status = unsafe { BCryptFinalizeKeyPair(handle, 0) };
        status.ok().map_err(|_| CryptoError::EccKeyGenError)?;

        Ok(Self {
            curve,
            handle,
            marker: PhantomData,
        })
    }

    /// Returns the underlying Windows CNG key handle.
    fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    /// Returns the curve used by this key.
    fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Exports the key to Windows CNG blob format.
    ///
    /// # Returns
    ///
    /// A validated blob containing the key material.
    #[allow(unsafe_code)]
    fn to_blob(&self) -> Result<CngEccKeyBlob<KeyInfo>, CryptoError> {
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
        status.ok().map_err(|_| CryptoError::EccKeyExportError)?;

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
        status.ok().map_err(|_| CryptoError::EccKeyExportError)?;

        CngEccKeyBlob::new(data)
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
    fn from_blob(blob: &CngEccKeyBlob<KeyInfo>) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Calling Windows CNG BCryptImportKeyPair to import an ECC key.
        // - KeyInfo::algo_handle() provides the valid algorithm handle for the curve
        // - None for hImportKey means no key encryption
        // - KeyInfo::blob_type() is a valid blob type string
        // - handle is a valid mutable reference to receive the key handle
        // - blob.as_slice() contains validated key material with correct format
        let status = unsafe {
            BCryptImportKeyPair(
                KeyInfo::algo_handle(blob.curve()),
                None,
                KeyInfo::blob_type(),
                &mut handle,
                blob.as_slice(),
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::EccKeyImportError)?;

        Ok(Self {
            handle,
            curve: blob.curve(),
            marker: PhantomData,
        })
    }
}

/// Windows CNG ECC key blob wrapper.
///
/// This structure validates and wraps the raw blob data exported from Windows CNG.
struct CngEccKeyBlob<KeyInfo: CngEccKeyInfo> {
    data: Vec<u8>,
    curve: EccCurve,
    marker: PhantomData<KeyInfo>,
}

impl<KeyInfo: CngEccKeyInfo> CngEccKeyBlob<KeyInfo> {
    const HEADER_SIZE: usize = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();

    /// Creates and validates a new blob from raw bytes.
    ///
    /// Validates:
    /// - Header size
    /// - Magic number matches KeyInfo type
    /// - Point size matches curve
    ///
    /// # Arguments
    ///
    /// * `data` - Raw blob data from Windows CNG
    fn new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let header = Self::header(&data)?;
        let curve = KeyInfo::curve_from_magic(header.dwMagic)?;
        let point_size = header.cbKey as usize;

        // Validate point size matches curve
        if point_size != curve.point_size() {
            Err(CryptoError::EccKeyImportError)?;
        }

        // Validate blob size (header + 3 points for private key, 2 for public)
        if data.len() != Self::HEADER_SIZE + KeyInfo::blob_component_count() * point_size {
            Err(CryptoError::EccKeyImportError)?;
        }

        Ok(Self {
            data,
            curve,
            marker: PhantomData,
        })
    }

    /// Returns the raw blob data.
    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the curve used by this key.
    fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Returns the x-coordinate of the public key point.
    fn x(&self) -> &[u8] {
        let point_size = self.curve.point_size();
        &self.data[Self::HEADER_SIZE..Self::HEADER_SIZE + point_size]
    }

    /// Returns the y-coordinate of the public key point.
    fn y(&self) -> &[u8] {
        let point_size = self.curve.point_size();
        &self.data[Self::HEADER_SIZE + point_size..Self::HEADER_SIZE + 2 * point_size]
    }

    /// Converts this blob from ECDSA to ECDH format by changing the magic number.
    ///
    /// # Type Parameters
    ///
    /// * `TargetKeyInfo` - The target key info type (must be an ECDH variant)
    fn ecdh_blob<TargetKeyInfo: CngEccKeyInfo>(
        mut self,
    ) -> Result<CngEccKeyBlob<TargetKeyInfo>, CryptoError> {
        let magic = KeyInfo::ecdh_magic_from_ecdsa(Self::header(&self.data)?.dwMagic)?;
        let header = Self::header_mut(&mut self.data)?;
        header.dwMagic = magic;
        CngEccKeyBlob::<TargetKeyInfo>::new(self.data)
    }

    /// Converts this private key blob to a public key blob.
    ///
    /// Truncates the private key component (d) and updates the magic number.
    ///
    /// # Type Parameters
    ///
    /// * `TargetKeyInfo` - The target key info type (must be a public key variant)
    fn pub_blob<TargetKeyInfo: CngEccKeyInfo>(
        mut self,
    ) -> Result<CngEccKeyBlob<TargetKeyInfo>, CryptoError> {
        let magic = KeyInfo::priv_magic_from_pub(Self::header(&self.data)?.dwMagic)?;
        let header = Self::header_mut(&mut self.data)?;
        header.dwMagic = magic;
        self.data
            .truncate(Self::HEADER_SIZE + 2 * self.curve().point_size());
        CngEccKeyBlob::<TargetKeyInfo>::new(self.data)
    }

    /// Returns a reference to the blob header.
    ///
    /// # Safety
    ///
    /// Validates blob size before casting.
    #[allow(unsafe_code)]
    fn header(blob: &[u8]) -> Result<&BCRYPT_ECCKEY_BLOB, CryptoError> {
        if blob.len() < Self::HEADER_SIZE {
            Err(CryptoError::EccKeyImportError)?;
        }
        // SAFETY: Casting blob bytes to BCRYPT_ECCKEY_BLOB pointer.
        // - Blob size is validated to be at least HEADER_SIZE bytes
        // - BCRYPT_ECCKEY_BLOB is a C struct with defined layout
        // - The reference lifetime is tied to the blob slice lifetime
        let header = unsafe { &*(blob.as_ptr() as *const BCRYPT_ECCKEY_BLOB) };
        Ok(header)
    }

    /// Returns a mutable reference to the blob header.
    ///
    /// # Safety
    ///
    /// Validates blob size before casting.
    #[allow(unsafe_code)]
    fn header_mut(blob: &mut [u8]) -> Result<&mut BCRYPT_ECCKEY_BLOB, CryptoError> {
        if blob.len() < Self::HEADER_SIZE {
            Err(CryptoError::EccKeyImportError)?;
        }
        // SAFETY: Casting blob bytes to mutable BCRYPT_ECCKEY_BLOB pointer.
        // - Blob size is validated to be at least HEADER_SIZE bytes
        // - BCRYPT_ECCKEY_BLOB is a C struct with defined layout
        // - The mutable reference lifetime is tied to the blob slice lifetime
        let header = unsafe { &mut *(blob.as_mut_ptr() as *mut BCRYPT_ECCKEY_BLOB) };
        Ok(header)
    }
}

/// Key info for ECDSA private keys.
///
/// Provides algorithm handles, blob types, and magic numbers specific to
/// ECDSA private key operations on Windows CNG.
#[derive(Debug, Clone)]
struct CngEcdsaPrivateKeyInfo;

impl CngEccKeyInfo for CngEcdsaPrivateKeyInfo {
    fn algo_handle(curve: EccCurve) -> BCRYPT_ALG_HANDLE {
        match curve {
            EccCurve::P256 => BCRYPT_ECDSA_P256_ALG_HANDLE,
            EccCurve::P384 => BCRYPT_ECDSA_P384_ALG_HANDLE,
            EccCurve::P521 => BCRYPT_ECDSA_P521_ALG_HANDLE,
        }
    }

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_ECCPRIVATE_BLOB
    }

    fn curve_from_magic(magic: u32) -> Result<EccCurve, CryptoError> {
        match magic {
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC => Ok(EccCurve::P256),
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC => Ok(EccCurve::P384),
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn ecdh_magic_from_ecdsa(magic: u32) -> Result<u32, CryptoError> {
        match magic {
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC => Ok(BCRYPT_ECDH_PRIVATE_P256_MAGIC),
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC => Ok(BCRYPT_ECDH_PRIVATE_P384_MAGIC),
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC => Ok(BCRYPT_ECDH_PRIVATE_P521_MAGIC),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn priv_magic_from_pub(magic: u32) -> Result<u32, CryptoError> {
        match magic {
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC => Ok(BCRYPT_ECDSA_PUBLIC_P256_MAGIC),
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC => Ok(BCRYPT_ECDSA_PUBLIC_P384_MAGIC),
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC => Ok(BCRYPT_ECDSA_PUBLIC_P521_MAGIC),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn blob_component_count() -> usize {
        3
    }
}

/// Key info for ECDSA public keys.
///
/// Provides algorithm handles, blob types, and magic numbers specific to
/// ECDSA public key operations on Windows CNG.
#[derive(Debug, Clone)]
struct CngEcdsaPublicKeyInfo;

impl CngEccKeyInfo for CngEcdsaPublicKeyInfo {
    fn algo_handle(curve: EccCurve) -> BCRYPT_ALG_HANDLE {
        match curve {
            EccCurve::P256 => BCRYPT_ECDSA_P256_ALG_HANDLE,
            EccCurve::P384 => BCRYPT_ECDSA_P384_ALG_HANDLE,
            EccCurve::P521 => BCRYPT_ECDSA_P521_ALG_HANDLE,
        }
    }

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_ECCPUBLIC_BLOB
    }

    fn curve_from_magic(magic: u32) -> Result<EccCurve, CryptoError> {
        match magic {
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC => Ok(EccCurve::P256),
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC => Ok(EccCurve::P384),
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn ecdh_magic_from_ecdsa(magic: u32) -> Result<u32, CryptoError> {
        match magic {
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P256_MAGIC),
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P384_MAGIC),
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P521_MAGIC),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn priv_magic_from_pub(_magic: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::EccKeyImportError)
    }

    fn blob_component_count() -> usize {
        2
    }
}

/// Key info for ECDH private keys.
///
/// Provides algorithm handles, blob types, and magic numbers specific to
/// ECDH private key operations on Windows CNG.
#[derive(Debug, Clone)]
struct CngEcdhPrivateKeyInfo;

impl CngEccKeyInfo for CngEcdhPrivateKeyInfo {
    fn algo_handle(curve: EccCurve) -> BCRYPT_ALG_HANDLE {
        match curve {
            EccCurve::P256 => BCRYPT_ECDH_P256_ALG_HANDLE,
            EccCurve::P384 => BCRYPT_ECDH_P384_ALG_HANDLE,
            EccCurve::P521 => BCRYPT_ECDH_P521_ALG_HANDLE,
        }
    }

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_ECCPRIVATE_BLOB
    }

    fn curve_from_magic(magic: u32) -> Result<EccCurve, CryptoError> {
        match magic {
            BCRYPT_ECDH_PRIVATE_P256_MAGIC => Ok(EccCurve::P256),
            BCRYPT_ECDH_PRIVATE_P384_MAGIC => Ok(EccCurve::P384),
            BCRYPT_ECDH_PRIVATE_P521_MAGIC => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn ecdh_magic_from_ecdsa(_magic: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::EccKeyImportError)
    }

    fn priv_magic_from_pub(magic: u32) -> Result<u32, CryptoError> {
        match magic {
            BCRYPT_ECDH_PRIVATE_P256_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P256_MAGIC),
            BCRYPT_ECDH_PRIVATE_P384_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P384_MAGIC),
            BCRYPT_ECDH_PRIVATE_P521_MAGIC => Ok(BCRYPT_ECDH_PUBLIC_P521_MAGIC),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn blob_component_count() -> usize {
        3
    }
}

/// Key info for ECDH public keys.
///
/// Provides algorithm handles, blob types, and magic numbers specific to
/// ECDH public key operations on Windows CNG.
#[derive(Debug, Clone)]
struct CngEcdhPublicKeyInfo;

impl CngEccKeyInfo for CngEcdhPublicKeyInfo {
    fn algo_handle(curve: EccCurve) -> BCRYPT_ALG_HANDLE {
        match curve {
            EccCurve::P256 => BCRYPT_ECDH_P256_ALG_HANDLE,
            EccCurve::P384 => BCRYPT_ECDH_P384_ALG_HANDLE,
            EccCurve::P521 => BCRYPT_ECDH_P521_ALG_HANDLE,
        }
    }

    fn blob_type() -> windows::core::PCWSTR {
        BCRYPT_ECCPUBLIC_BLOB
    }

    fn curve_from_magic(magic: u32) -> Result<EccCurve, CryptoError> {
        match magic {
            BCRYPT_ECDH_PUBLIC_P256_MAGIC => Ok(EccCurve::P256),
            BCRYPT_ECDH_PUBLIC_P384_MAGIC => Ok(EccCurve::P384),
            BCRYPT_ECDH_PUBLIC_P521_MAGIC => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccKeyImportError),
        }
    }

    fn ecdh_magic_from_ecdsa(_magic: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::EccKeyImportError)
    }

    fn priv_magic_from_pub(_magic: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::EccKeyImportError)
    }

    fn blob_component_count() -> usize {
        2
    }
}

impl TryFrom<&CngEcdsaPrivateKeyHandle> for CngEcdhPrivateKeyHandle {
    type Error = CryptoError;

    /// Converts an ECDSA private key handle to an ECDH private key handle.
    ///
    /// The key material remains the same; only the handle type changes.
    fn try_from(key: &CngEcdsaPrivateKeyHandle) -> Result<Self, Self::Error> {
        CngEcdhPrivateKeyHandle::from_blob(&key.to_blob()?.ecdh_blob()?)
    }
}

impl TryFrom<&CngEcdsaPrivateKeyHandle> for CngEcdsaPublicKeyHandle {
    type Error = CryptoError;

    /// Derives the public key handle from an ECDSA private key handle.
    fn try_from(key: &CngEcdsaPrivateKeyHandle) -> Result<Self, Self::Error> {
        CngEcdsaPublicKeyHandle::from_blob(&key.to_blob()?.pub_blob()?)
    }
}

impl TryFrom<&CngEcdhPrivateKeyHandle> for CngEcdhPublicKeyHandle {
    type Error = CryptoError;

    /// Derives the public key handle from an ECDH private key handle.
    fn try_from(key: &CngEcdhPrivateKeyHandle) -> Result<Self, Self::Error> {
        CngEcdhPublicKeyHandle::from_blob(&key.to_blob()?.pub_blob()?)
    }
}

impl TryFrom<&CngEcdsaPublicKeyHandle> for CngEcdhPublicKeyHandle {
    type Error = CryptoError;

    /// Converts an ECDSA public key handle to an ECDH public key handle.
    ///
    /// The key material remains the same; only the handle type changes.
    fn try_from(key: &CngEcdsaPublicKeyHandle) -> Result<Self, Self::Error> {
        CngEcdhPublicKeyHandle::from_blob(&key.to_blob()?.ecdh_blob()?)
    }
}

impl TryFrom<&CngEcdsaPrivateKeyHandle> for DerEccPrivateKey {
    type Error = CryptoError;

    /// Converts a CNG ECDSA private key handle to DER format.
    fn try_from(key: &CngEcdsaPrivateKeyHandle) -> Result<Self, Self::Error> {
        let blob = key.to_blob()?;
        let point_size = blob.curve().point_size();
        let priv_key_offset = CngEccKeyBlob::<CngEcdsaPrivateKeyInfo>::HEADER_SIZE + 2 * point_size;
        DerEccPrivateKey::new_with_pub_key(
            blob.curve(),
            &blob.as_slice()[priv_key_offset..],
            blob.x(),
            blob.y(),
        )
    }
}

impl TryFrom<&CngEcdsaPublicKeyHandle> for DerEccPublicKey {
    type Error = CryptoError;

    /// Converts a CNG ECDSA public key handle to DER format.
    fn try_from(key: &CngEcdsaPublicKeyHandle) -> Result<Self, Self::Error> {
        let blob = key.to_blob()?;
        DerEccPublicKey::new(blob.curve(), blob.x(), blob.y())
    }
}

impl TryFrom<&DerEccPrivateKey> for CngEcdsaPrivateKeyHandle {
    type Error = CryptoError;

    /// Converts a DER-encoded private key to a CNG ECDSA private key handle.
    fn try_from(der_key: &DerEccPrivateKey) -> Result<Self, Self::Error> {
        let point_size = der_key.curve().point_size();
        let mut data =
            vec![0u8; CngEccKeyBlob::<CngEcdsaPrivateKeyInfo>::HEADER_SIZE + 3 * point_size];

        // Fill in header
        let header = CngEccKeyBlob::<CngEcdsaPrivateKeyInfo>::header_mut(&mut data)?;
        header.dwMagic = match der_key.curve() {
            EccCurve::P256 => BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
            EccCurve::P384 => BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
            EccCurve::P521 => BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
        };
        header.cbKey = der_key.curve().point_size() as u32;

        // Fill in points
        let x_offset = CngEccKeyBlob::<CngEcdsaPrivateKeyInfo>::HEADER_SIZE;
        let y_offset = x_offset + point_size;
        let priv_key_offset = y_offset + point_size;

        if let Some(x) = der_key.x() {
            data[x_offset..x_offset + point_size].copy_from_slice(x);
        }

        if let Some(y) = der_key.y() {
            data[y_offset..y_offset + point_size].copy_from_slice(y);
        }

        data[priv_key_offset..priv_key_offset + point_size].copy_from_slice(der_key.priv_key());

        CngEccKeyHandle::<CngEcdsaPrivateKeyInfo>::from_blob(&CngEccKeyBlob::new(data)?)
    }
}

impl TryFrom<&DerEccPrivateKey> for CngEcdhPrivateKeyHandle {
    type Error = CryptoError;

    /// Converts a DER-encoded private key to a CNG ECDH private key handle.
    fn try_from(der_key: &DerEccPrivateKey) -> Result<Self, Self::Error> {
        let ecdsa_key = CngEcdsaPrivateKeyHandle::try_from(der_key)?;
        CngEcdhPrivateKeyHandle::try_from(&ecdsa_key)
    }
}
impl TryFrom<&DerEccPublicKey> for CngEcdsaPublicKeyHandle {
    type Error = CryptoError;

    /// Converts a DER-encoded public key to a CNG ECDSA public key handle.
    fn try_from(der_key: &DerEccPublicKey) -> Result<Self, Self::Error> {
        let point_size = der_key.curve().point_size();
        let mut data =
            vec![0u8; CngEccKeyBlob::<CngEcdsaPublicKeyInfo>::HEADER_SIZE + 2 * point_size];

        // Fill in header
        let header = CngEccKeyBlob::<CngEcdsaPublicKeyInfo>::header_mut(&mut data)?;
        header.dwMagic = match der_key.curve() {
            EccCurve::P256 => BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            EccCurve::P384 => BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
            EccCurve::P521 => BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
        };
        header.cbKey = der_key.curve().point_size() as u32;

        // Fill in points
        let x_offset = CngEccKeyBlob::<CngEcdsaPublicKeyInfo>::HEADER_SIZE;
        let y_offset = x_offset + point_size;

        data[x_offset..x_offset + point_size].copy_from_slice(der_key.x());
        data[y_offset..y_offset + point_size].copy_from_slice(der_key.y());

        CngEccKeyHandle::<CngEcdsaPublicKeyInfo>::from_blob(&CngEccKeyBlob::new(data)?)
    }
}

impl TryFrom<&DerEccPublicKey> for CngEcdhPublicKeyHandle {
    type Error = CryptoError;

    /// Converts a DER-encoded public key to a CNG ECDH public key handle.
    fn try_from(der_key: &DerEccPublicKey) -> Result<Self, Self::Error> {
        let ecdsa_key = CngEcdsaPublicKeyHandle::try_from(der_key)?;
        CngEcdhPublicKeyHandle::try_from(&ecdsa_key)
    }
}
