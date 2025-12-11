// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! EC Key Generation backend for windows environment using CNG.

/// This module provides Windows CNG (Cryptography Next Generation) backend implementations for elliptic curve cryptography (ECC) key operations,
/// including key generation, import/export, and signature encoding/decoding for ECDSA keys on the supported NIST curves (P-256, P-384, P-521).
///
/// It defines safe Rust wrappers around CNG handles for algorithm providers and key objects, ensuring proper resource management and thread safety.
/// The module also includes utilities for converting between DER/ASN.1 encoded keys and signatures and the binary blob formats required by CNG,
/// enabling interoperability with standard formats such as PKCS#8, SPKI, and DER-encoded ECDSA signatures.
///
/// # Features
/// - Mapping between `EcCurveId` and CNG algorithm identifiers.
/// - Safe wrappers for CNG algorithm and key handles with automatic cleanup.
/// - Import/export of EC private and public keys from/to DER-encoded formats.
/// - Conversion between raw and DER-encoded ECDSA signatures.
/// - ASN.1 parsing and encoding for EC key and signature structures.
/// - Thread-safe key handle management using `Arc<Mutex<...>>`.
///
/// # Safety
/// All FFI calls to Windows CNG APIs are encapsulated in safe abstractions, with careful resource management and error handling.
/// Unsafe code is used only where necessary to interact with CNG, and is documented accordingly.
///
/// # Limitations
/// - Keys generated or stored in non-exportable CNG providers (e.g., TPM, smart cards) cannot be exported.
/// - Only NIST P-256, P-384, and P-521 curves are supported.
/// - The module is intended for use on Windows platforms with CNG support.
///
/// # Example
/// ```rust
/// // Generate a new EC key pair
/// let (private_key, public_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP256)?;
///
/// // Export public key to DER
/// let mut der_buf = vec![0u8; 128];
/// let der_len = public_key.ec_key_to_der(&mut der_buf)?;
/// let der = &der_buf[..der_len];
///
/// // Import public key from DER
/// let imported_pub = EcPublicKey::ec_key_from_der(der, EcCurveId::EccP256)?;
/// ```
use std::sync::Arc;
use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;

/// Maps an [`EcCurveId`] to the corresponding CNG algorithm identifier.
///
/// # Arguments
/// * `curve` - The elliptic curve identifier.
///
/// # Returns
/// * `Ok(PCWSTR)` - The Windows CNG algorithm identifier for the curve.
/// * `Err(CryptoError)` - If the curve is not supported.
fn curve_to_algo_id(curve: EcCurveId) -> Result<PCWSTR, CryptoError> {
    match curve {
        EcCurveId::EccP256 => Ok(BCRYPT_ECDSA_P256_ALGORITHM),
        EcCurveId::EccP384 => Ok(BCRYPT_ECDSA_P384_ALGORITHM),
        EcCurveId::EccP521 => Ok(BCRYPT_ECDSA_P521_ALGORITHM),
    }
}

fn curve_to_ecdh_algo_id(curve: EcCurveId) -> Result<PCWSTR, CryptoError> {
    match curve {
        EcCurveId::EccP256 => Ok(BCRYPT_ECDH_P256_ALGORITHM),
        EcCurveId::EccP384 => Ok(BCRYPT_ECDH_P384_ALGORITHM),
        EcCurveId::EccP521 => Ok(BCRYPT_ECDH_P521_ALGORITHM),
    }
}

/// Wrapper for a CNG algorithm provider handle.
pub struct CngAlgoHandle {
    cng_algo_handle: BCRYPT_ALG_HANDLE,
}

impl CngAlgoHandle {
    /// Opens a CNG algorithm provider handle for the specified algorithm ID and flags.
    ///
    /// # Arguments
    /// * `alg_id` - The CNG algorithm identifier.
    /// * `flags` - Flags for opening the algorithm provider.
    ///
    /// # Returns
    /// * `Ok(CngAlgoHandle)` on success.
    /// * `Err(CryptoError)` if the provider cannot be opened.
    #[allow(unsafe_code)]
    pub fn open(
        alg_id: PCWSTR,
        flags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    ) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_ALG_HANDLE::default();
        // SAFETY: calls BCryptOpenAlgorithmProvider; all pointers and handles are valid
        let status = unsafe { BCryptOpenAlgorithmProvider(&mut handle, alg_id, None, flags) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptOpenAlgorithmProvider failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        let cng_algo_handle = handle;
        tracing::debug!("DROP: Algo Handle ");
        Ok(CngAlgoHandle { cng_algo_handle })
    }

    /// Returns the underlying CNG algorithm handle.
    ///
    /// # Returns
    /// * `BCRYPT_ALG_HANDLE` - The raw algorithm handle.
    pub fn handle(&self) -> BCRYPT_ALG_HANDLE {
        self.cng_algo_handle
    }
}

impl Drop for CngAlgoHandle {
    /// Drops the CngAlgoHandle, releasing the CNG algorithm provider handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to close the algorithm provider handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptCloseAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe { BCryptCloseAlgorithmProvider(self.cng_algo_handle, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptCloseAlgorithmProvider failed: {status:?}");
        }
    }
}

/// Wrapper for a CNG private key handle.
pub struct CngPrivateKeyHandle {
    /// Handle to the private key managed by the Windows Cryptography API: Next Generation (CNG).
    /// This handle is used for cryptographic operations involving the associated ECC private key.
    ///
    /// # Safety
    /// The handle must be properly released using the appropriate CNG API to avoid resource leaks.
    pub cng_private_key: BCRYPT_KEY_HANDLE,
    pub cng_ecdh_private_key: BCRYPT_KEY_HANDLE,
}

#[allow(unsafe_code)]
// SAFETY: CngPrivateKeyHandle only contains a BCRYPT_KEY_HANDLE, which is safe to send between threads because the handle is managed and synchronized via Arc<Mutex<...>> in higher-level types.
unsafe impl Send for CngPrivateKeyHandle {}

#[allow(unsafe_code)]
/// SAFETY: CngPrivateKeyHandle only contains a BCRYPT_KEY_HANDLE, which is safe to share between threads because the handle is managed and synchronized via Arc<Mutex<...>> in higher-level types.
unsafe impl Sync for CngPrivateKeyHandle {}

impl CngPrivateKeyHandle {
    /// Returns the degree (key size in bits) of the EC private key.
    ///
    /// # Returns
    /// * `Ok(u32)` - The key size in bits.
    /// * `Err(CryptoError)` - If the property cannot be queried.
    #[allow(unsafe_code)]
    pub fn curve_degree(&self) -> Result<u32, CryptoError> {
        curve_degree(self.cng_private_key)
    }
}
impl Drop for CngPrivateKeyHandle {
    /// Drops the CngPrivateKeyHandle, releasing the CNG private key handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to destroy the key handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.cng_private_key) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (private) failed: {status:?}");
        } else {
            tracing::debug!("DROP: Private Key Handle ");
        }

        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.cng_ecdh_private_key) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (ecdh private) failed: {status:?}");
        } else {
            tracing::debug!("DROP: ECDH Private Key Handle ");
        }
    }
}

/// Wrapper for a CNG public key handle (ECDSA and ECDH).
pub struct CngPublicKeyHandle {
    /// Handle to the public key managed by the Windows Cryptography API: Next Generation (CNG).
    /// This handle is used for cryptographic operations involving the public portion of an ECC key.
    ///
    /// # Safety
    /// The handle must be properly managed and released to avoid resource leaks.
    ///
    /// # Platform
    /// This field is only relevant on Windows platforms where CNG is available.
    pub cng_public_key: BCRYPT_KEY_HANDLE,
    pub cng_ecdh_public_key: BCRYPT_KEY_HANDLE,
}

#[allow(unsafe_code)]
/// SAFETY: CngPublicKeyHandle only contains a BCRYPT_KEY_HANDLE, which is safe to send between threads because the handle is managed and synchronized via Arc<Mutex<...>> in higher-level types.
unsafe impl Send for CngPublicKeyHandle {}

#[allow(unsafe_code)]
/// SAFETY: CngPublicKeyHandle only contains a BCRYPT_KEY_HANDLE, which is safe to share between threads because the handle is managed and synchronized via Arc<Mutex<...>> in higher-level types.
unsafe impl Sync for CngPublicKeyHandle {}

#[allow(unsafe_code)]
fn curve_degree(handle_object: BCRYPT_KEY_HANDLE) -> Result<u32, CryptoError> {
    let mut key_length: u32 = 0;
    let mut result_len: u32 = 0;
    // SAFETY: BCryptGetProperty is called with valid parameters to get key size
    let status = unsafe {
        BCryptGetProperty(
            handle_object,
            BCRYPT_KEY_LENGTH,
            Some(std::slice::from_raw_parts_mut(
                (&mut key_length) as *mut u32 as *mut u8,
                4,
            )),
            &mut result_len,
            0,
        )
    };
    if status != STATUS_SUCCESS {
        tracing::error!("BCryptGetProperty (BCRYPT_KEY_LENGTH, private) failed: {status:?}");
        return Err(CryptoError::EccError);
    }
    Ok(key_length)
}

impl CngPublicKeyHandle {
    /// Returns the degree (key size in bits) of the EC public key.
    ///
    /// # Returns
    /// * `Ok(u32)` - The key size in bits.
    /// * `Err(CryptoError)` - If the property cannot be queried.
    #[allow(unsafe_code)]
    pub fn curve_degree(&self) -> Result<u32, CryptoError> {
        curve_degree(self.cng_public_key)
    }
}

impl Drop for CngPublicKeyHandle {
    /// Drops the CngPublicKeyHandle, releasing the CNG public key handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to destroy the key handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.cng_public_key) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (ecdsa public) failed: {status:?}");
        }

        //  ECDH public key handle, destroy it as well

        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.cng_ecdh_public_key) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (ecdh public) failed: {status:?}");
        }
    }
}

impl EcKeyGen {
    /// Helper to generate a CNG private key handle for ECDSA or ECDH.
    #[allow(unsafe_code)]
    fn generate_cng_private_key_handle(
        curve_id: EcCurveId,
        kind: EcBlobKind,
    ) -> Result<BCRYPT_KEY_HANDLE, CryptoError> {
        let alg_id = match kind {
            EcBlobKind::Ecdsa => curve_to_algo_id(curve_id)?,
            EcBlobKind::Ecdh => curve_to_ecdh_algo_id(curve_id)?,
        };
        let algo_handle = CngAlgoHandle::open(alg_id, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: The private_key is valid and the output pointer is valid for the size query. This call queries the size of the exported public key blob.
        let status = unsafe {
            BCryptGenerateKeyPair(
                algo_handle.handle(),
                &mut key_handle,
                0, // Use default key length for the curve
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptGenerateKeyPair failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        // SAFETY: call unsafe BCRYPT call to finalize the key pair before using
        // SAFETY: BCryptFinalizeKeyPair is called with a valid key handle to finalize the key generation process.
        let status = unsafe { BCryptFinalizeKeyPair(key_handle, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptFinalizeKeyPair failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        Ok(key_handle)
    }

    ///Helper function to create a new ECDH key handle from the exported ECDSA private key
    #[allow(unsafe_code)]
    fn import_cng_ecdh_private_key_handle(
        curve_id: EcCurveId,
        exported_blob: &[u8],
    ) -> Result<BCRYPT_KEY_HANDLE, CryptoError> {
        let alg_id = curve_to_ecdh_algo_id(curve_id)?;
        let algo_handle = CngAlgoHandle::open(alg_id, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;

        // Convert ECDSA blob magic to ECDH blob magic
        let mut ecdh_blob = exported_blob.to_vec();
        if ecdh_blob.len() < 4 {
            tracing::error!("Blob too short to contain magic number");
            return Err(CryptoError::EccError);
        }

        // Update the magic number for ECDH
        let ecdh_magic = match curve_id {
            EcCurveId::EccP256 => BCRYPT_ECDH_PRIVATE_P256_MAGIC,
            EcCurveId::EccP384 => BCRYPT_ECDH_PRIVATE_P384_MAGIC,
            EcCurveId::EccP521 => BCRYPT_ECDH_PRIVATE_P521_MAGIC,
        };
        ecdh_blob[0..4].copy_from_slice(&ecdh_magic.to_le_bytes());

        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: BCryptImportKeyPair is called with valid parameters: algorithm handle, key handle pointer, blob type, and blob data are all valid.
        let status = unsafe {
            BCryptImportKeyPair(
                algo_handle.handle(),
                None,
                BCRYPT_ECCFULLPRIVATE_BLOB,
                &mut key_handle,
                &ecdh_blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        // Note: BCryptFinalizeKeyPair is not needed for imported keys, only for generated keys
        Ok(key_handle)
    }

    /// Helper to generate a CNG public key handle from a private key handle.
    #[allow(unsafe_code)]
    fn generate_cng_public_key_handle(
        private_key: BCRYPT_KEY_HANDLE,
        curve_id: EcCurveId,
        kind: EcBlobKind,
    ) -> Result<BCRYPT_KEY_HANDLE, CryptoError> {
        let mut pub_blob_len: u32 = 0;
        // SAFETY: The private_key is valid and the output pointer is valid for the size query. This call queries the size of the exported public key blob.
        let status = unsafe {
            BCryptExportKey(
                private_key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                &mut pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptExportKey (size query) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        let mut pub_blob = vec![0u8; pub_blob_len as usize];
        // SAFETY: The private_key is valid, pub_blob is allocated, and the output pointer is valid. This call exports the actual public key blob.
        let status = unsafe {
            BCryptExportKey(
                private_key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                Some(pub_blob.as_mut_slice()),
                &mut pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptExportKey (export) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        let alg_id = match kind {
            EcBlobKind::Ecdsa => curve_to_algo_id(curve_id)?,
            EcBlobKind::Ecdh => curve_to_ecdh_algo_id(curve_id)?,
        };
        let algo_handle = CngAlgoHandle::open(alg_id, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut pub_key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: The algorithm handle, pub_key_handle pointer, and pub_blob are valid for import. This call imports the public key blob into a CNG key handle.
        let status = unsafe {
            BCryptImportKeyPair(
                algo_handle.handle(),
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut pub_key_handle,
                &pub_blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair (public) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        Ok(pub_key_handle)
    }
}

impl EcKeyGenOp for EcKeyGen {
    /// Generates an EC key pair (private and public keys) for the specified curve.
    ///
    /// # Arguments
    /// * `curve_id` - The elliptic curve identifier (EcCurveId).
    ///
    /// # Returns
    /// * `Result<(PrivateKey, PublicKey), CryptoError>` - The generated key pair, or an error if generation fails.
    #[allow(unsafe_code)]
    fn ec_key_gen_pair(
        &self,
        curve_id: EcCurveId,
    ) -> Result<(EcPrivateKey, EcPublicKey), CryptoError> {
        // Generate ECDSA private key handle
        let ecdsa_key_handle = Self::generate_cng_private_key_handle(curve_id, EcBlobKind::Ecdsa)?;
        // Export ECC private key blob
        let mut private_blob_len: u32 = 0;
        // SAFETY: BCryptExportKey is called with valid parameters to query the size of the private key blob.
        let status = unsafe {
            BCryptExportKey(
                ecdsa_key_handle,
                None,
                BCRYPT_ECCFULLPRIVATE_BLOB,
                None,
                &mut private_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get EC private key blob len");
            return Err(CryptoError::EcExportFailed);
        }
        let mut pri_blob = vec![0u8; private_blob_len as usize];
        // SAFETY: Calls BCryptExportKey to get actual blob; all pointers and handles are valid.
        let status = unsafe {
            BCryptExportKey(
                ecdsa_key_handle,
                None,
                BCRYPT_ECCFULLPRIVATE_BLOB,
                Some(pri_blob.as_mut_slice()),
                &mut private_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to export private key");
            return Err(CryptoError::EcExportFailed);
        }
        // Generate ECDH private key handle
        // let ecdh_key_handle = Self::generate_cng_private_key_handle(curve_id, EcBlobKind::Ecdh)?;
        let ecdh_key_handle =
            Self::import_cng_ecdh_private_key_handle(curve_id, pri_blob.as_slice())?;
        // Generate public key handle from ECDSA private key
        let ecdsa_pub_key_handle =
            Self::generate_cng_public_key_handle(ecdsa_key_handle, curve_id, EcBlobKind::Ecdsa)?;
        // Generate public key handle from ECDH private key
        let ecdh_pub_key_handle =
            Self::generate_cng_public_key_handle(ecdh_key_handle, curve_id, EcBlobKind::Ecdh)?;
        let pri_key_handle: CngPrivateKeyHandle = CngPrivateKeyHandle {
            cng_private_key: ecdsa_key_handle,
            cng_ecdh_private_key: ecdh_key_handle,
        };
        let pub_key_handle = CngPublicKeyHandle {
            cng_public_key: ecdsa_pub_key_handle,
            cng_ecdh_public_key: ecdh_pub_key_handle,
        };
        Ok((
            EcPrivateKey {
                private_key_handle: Arc::new(Mutex::new(pri_key_handle)),
            },
            EcPublicKey {
                public_key_handle: Arc::new(Mutex::new(pub_key_handle)),
            },
        ))
    }
}

impl EckeyOps<EcPrivateKey> for EcPrivateKey {
    /// Creates an EC key from a DER-encoded byte slice.
    ///
    /// # Parameters
    /// - `der`: DER-encoded key data as a byte slice.
    /// - `curveid`: The elliptic curve identifier to use.
    ///
    /// # Returns
    /// - `Ok(Self::Key)`: The constructed key object on success.
    /// - `Err(CryptoError)`: An error if the key could not be created.
    #[allow(unsafe_code)]
    fn ec_key_from_der(der: &[u8], curveid: EcCurveId) -> Result<Self, CryptoError> {
        // Debug: Print DER input as hex
        tracing::debug!("DER input (hex): {:x?}", der);
        // Step 1: Convert PKCS#8 DER to CNG ECCPRIVATE_BLOB
        let cng_ecc_blob = match pkcs8_ecprivatekey_to_cng_blob(der, curveid, EcBlobKind::Ecdsa) {
            Ok(blob) => blob,
            Err(e) => {
                tracing::error!("pkcs8_ecprivatekey_to_cng_blob failed(ecdsa) : {}", e);
                return Err(CryptoError::EccError);
            }
        };

        // Step 2: Import the key blob into a CNG key handle
        let alg_id = curve_to_algo_id(curveid)?;
        let algo_handle = CngAlgoHandle::open(alg_id, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Import CNG ECCPRIVATE_BLOB to new key
        let status = unsafe {
            BCryptImportKeyPair(
                algo_handle.handle(),
                None,
                BCRYPT_ECCPRIVATE_BLOB,
                &mut key_handle,
                &cng_ecc_blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair failed: {status:?}");

            return Err(CryptoError::EccError);
        }

        //step3 : Import the ECDH keyblob into a CNG keyhandle for ECDH operations
        let cng_ecdh_blob = match pkcs8_ecprivatekey_to_cng_blob(der, curveid, EcBlobKind::Ecdh) {
            Ok(blob) => blob,
            Err(e) => {
                tracing::error!("pkcs8_ecprivatekey_to_cng_blob failed(ecdh) : {}", e);
                return Err(CryptoError::EccError);
            }
        };
        let alg_id = curve_to_ecdh_algo_id(curveid)?;
        let ecdh_algo_handle =
            CngAlgoHandle::open(alg_id, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut ecdh_key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: Import CNG ECCPRIVATE_BLOB to new key
        let status = unsafe {
            BCryptImportKeyPair(
                ecdh_algo_handle.handle(),
                None,
                BCRYPT_ECCPRIVATE_BLOB,
                &mut ecdh_key_handle,
                &cng_ecdh_blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair failed(ECDH): {status:?}");

            return Err(CryptoError::EccError);
        }

        let cng_key_handle = CngPrivateKeyHandle {
            cng_private_key: key_handle,
            cng_ecdh_private_key: ecdh_key_handle,
        };

        Ok(EcPrivateKey {
            private_key_handle: Arc::new(Mutex::new(cng_key_handle)),
        })
    }

    /// Serializes the ECDSA key to DER format.
    ///
    /// # Parameters
    /// - `der`: Mutable byte slice to write the DER-encoded key into.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written on success.
    /// - `Err(CryptoError)`: An error if serialization fails.
    ///
    /// # Details
    /// This function exports the EC private key from CNG using `BCRYPT_ECCFULLPRIVATE_BLOB`,
    /// then converts it to PKCS#8 DER format. The export works for keys that were generated
    /// with exportable flags or imported from external sources.
    ///
    /// # Limitations
    /// Keys stored in non-exportable providers (e.g., TPM, smart cards) cannot be exported.
    #[allow(unsafe_code)]
    fn ec_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        // Step 1: Export the private key using CNG
        let mut private_blob_len: u32 = 0;
        let private_key_handle = self.private_key_handle.lock().unwrap();

        // SAFETY: BCryptExportKey is called with valid parameters to query the size of the private key blob.
        let status = unsafe {
            BCryptExportKey(
                private_key_handle.cng_private_key,
                None,
                BCRYPT_ECCPRIVATE_BLOB, // Use simple format instead of FULL format
                None,
                &mut private_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get EC private key blob size: {status:?}");
            return Err(CryptoError::EcExportFailed);
        }

        let mut private_blob = vec![0u8; private_blob_len as usize];

        // SAFETY: BCryptExportKey is called with valid parameters to export the private key blob.
        let status = unsafe {
            BCryptExportKey(
                private_key_handle.cng_private_key,
                None,
                BCRYPT_ECCPRIVATE_BLOB, // Use simple format instead of FULL format
                Some(private_blob.as_mut_slice()),
                &mut private_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to export EC private key blob: {status:?}");
            return Err(CryptoError::EcExportFailed);
        }

        drop(private_key_handle); // Release the lock

        // Step 2: Parse the CNG blob to extract components
        if private_blob.len() < 8 {
            tracing::error!("Private key blob too short");
            return Err(CryptoError::EcExportFailed);
        }

        let magic = u32::from_le_bytes([
            private_blob[0],
            private_blob[1],
            private_blob[2],
            private_blob[3],
        ]);
        let key_size = u32::from_le_bytes([
            private_blob[4],
            private_blob[5],
            private_blob[6],
            private_blob[7],
        ]) as usize;

        // Validate magic and determine curve from key size and magic
        let curve_oid = match (key_size, magic) {
            (32, BCRYPT_ECDSA_PRIVATE_P256_MAGIC) => {
                asn1::ObjectIdentifier::from_string("1.2.840.10045.3.1.7").unwrap()
            } // P-256
            (48, BCRYPT_ECDSA_PRIVATE_P384_MAGIC) => {
                asn1::ObjectIdentifier::from_string("1.3.132.0.34").unwrap()
            } // P-384
            (66, BCRYPT_ECDSA_PRIVATE_P521_MAGIC) => {
                asn1::ObjectIdentifier::from_string("1.3.132.0.35").unwrap()
            } // P-521
            _ => {
                tracing::error!(
                    "Invalid magic value {:x} for key size {} in ECDSA private key blob",
                    magic,
                    key_size
                );
                return Err(CryptoError::EcExportFailed);
            }
        };

        // Validate blob structure: should contain X, Y, and D
        let expected_blob_size = 8 + 3 * key_size; // magic(4) + key_size(4) + X + Y + D
        if private_blob.len() != expected_blob_size {
            tracing::error!(
                "Private key blob size mismatch: expected {} got {}",
                expected_blob_size,
                private_blob.len()
            );
            return Err(CryptoError::EcExportFailed);
        }

        // Extract components from CNG blob: X, Y, D
        let x = &private_blob[8..8 + key_size];
        let y = &private_blob[8 + key_size..8 + 2 * key_size];
        let d = &private_blob[8 + 2 * key_size..8 + 3 * key_size];

        // Step 3: Build the DER structures

        // Build uncompressed EC public key point (0x04 || X || Y)
        let mut public_key_point = Vec::with_capacity(1 + 2 * key_size);
        public_key_point.push(0x04); // Uncompressed point indicator
        public_key_point.extend_from_slice(x);
        public_key_point.extend_from_slice(y);

        // Remove leading zeros from private scalar for DER encoding
        let d_trimmed = {
            let mut start = 0;
            while start < d.len() && d[start] == 0 {
                start += 1;
            }
            if start == d.len() {
                &[0u8] // All zeros, keep at least one zero
            } else {
                &d[start..]
            }
        };

        // Create ASN.1 structures for PKCS#8 format
        #[derive(asn1::Asn1Write)]
        struct EcPrivateKeyWrite<'a> {
            version: u8,
            private_key: &'a [u8],
            #[explicit[1]]
            public_key: Option<asn1::BitString<'a>>,
        }

        #[derive(asn1::Asn1Write)]
        struct AlgorithmIdentifierWrite {
            algorithm: asn1::ObjectIdentifier,
            parameters: asn1::ObjectIdentifier,
        }

        #[derive(asn1::Asn1Write)]
        struct PrivateKeyInfoWrite<'a> {
            version: u8,
            algorithm: AlgorithmIdentifierWrite,
            private_key: &'a [u8],
        }

        // Build ECPrivateKey structure
        let public_key_bitstring = match asn1::BitString::new(&public_key_point, 0) {
            Some(bitstring) => bitstring,
            None => {
                tracing::error!("Failed to create public key BitString");
                return Err(CryptoError::EcExportFailed);
            }
        };

        let ec_private_key = EcPrivateKeyWrite {
            version: 1,
            private_key: d_trimmed,
            public_key: Some(public_key_bitstring),
        };

        // Encode ECPrivateKey to get the private key bytes for PKCS#8
        let ec_private_key_der = asn1::write_single(&ec_private_key).map_err(|e| {
            tracing::error!("Failed to encode ECPrivateKey: {:?}", e);
            CryptoError::EcExportFailed
        })?;

        // Build PKCS#8 PrivateKeyInfo structure
        let id_ec_public_key = asn1::ObjectIdentifier::from_string("1.2.840.10045.2.1").unwrap();
        let algorithm = AlgorithmIdentifierWrite {
            algorithm: id_ec_public_key,
            parameters: curve_oid,
        };

        let private_key_info = PrivateKeyInfoWrite {
            version: 0,
            algorithm,
            private_key: &ec_private_key_der,
        };

        // Step 4: Encode to DER
        let der_bytes = asn1::write_single(&private_key_info).map_err(|e| {
            tracing::error!("Failed to encode PrivateKeyInfo: {:?}", e);
            CryptoError::EcExportFailed
        })?;

        if der.len() < der_bytes.len() {
            tracing::error!(
                "DER output buffer too small: need {} bytes, have {}",
                der_bytes.len(),
                der.len()
            );
            return Err(CryptoError::EcExportFailed);
        }

        der[..der_bytes.len()].copy_from_slice(&der_bytes);
        tracing::debug!(
            "Successfully exported EC private key to DER format ({} bytes)",
            der_bytes.len()
        );
        Ok(der_bytes.len())
    }

    /// Returns the size of the EC private key in bytes.
    ///
    /// # Returns
    /// * `Ok(usize)` - The key size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn size(&self) -> Result<usize, CryptoError> {
        let bits = self.private_key_handle.lock().unwrap().curve_degree()?;
        Ok(bits as usize)
    }
}

impl EckeyOps<EcPublicKey> for EcPublicKey {
    /// Imports an EC public key from DER-encoded data.
    ///
    /// # Arguments
    /// * `der` - The DER-encoded public key data.
    /// * `curveid` - The elliptic curve identifier (EcCurveId).
    ///
    /// # Returns
    /// * `Result<CngPublicKeyHandle, CryptoError>` - The imported public key handle, or an error if import fails.
    #[allow(unsafe_code)]
    fn ec_key_from_der(der: &[u8], curveid: EcCurveId) -> Result<EcPublicKey, CryptoError> {
        // Convert DER/SPKI to CNG ECCPUBLIC_BLOB for ECDSA
        let cng_blob_ecdsa = match spki_to_cng_public_blob(der, curveid, EcBlobKind::Ecdsa) {
            Ok(blob) => blob,
            Err(e) => {
                tracing::error!("spki_to_cng_public_blob failed (ecdsa): {}", e);
                return Err(CryptoError::EcImportFailed);
            }
        };
        // Import the blob into a CNG key handle for ECDSA
        let alg_id_ecdsa = curve_to_algo_id(curveid)?;
        let algo_handle_ecdsa =
            CngAlgoHandle::open(alg_id_ecdsa, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut key_handle_ecdsa = BCRYPT_KEY_HANDLE::default();
        // SAFETY: The algorithm handle, key_handle_ecdsa pointer, and cng_blob_ecdsa are valid for import. This call imports the public key blob into a CNG key handle.
        let status_ecdsa = unsafe {
            BCryptImportKeyPair(
                algo_handle_ecdsa.handle(),
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut key_handle_ecdsa,
                &cng_blob_ecdsa,
                0,
            )
        };
        if status_ecdsa != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair (ecdsa public) failed: {status_ecdsa:?}");
            tracing::error!(
                "Blob passed to BCryptImportKeyPair (hex): {:x?}",
                cng_blob_ecdsa
            );
            return Err(CryptoError::EcImportFailed);
        }
        // Convert DER/SPKI to CNG ECCPUBLIC_BLOB for ECDH
        let cng_blob_ecdh = match spki_to_cng_public_blob(der, curveid, EcBlobKind::Ecdh) {
            Ok(blob) => blob,
            Err(e) => {
                tracing::error!("spki_to_cng_public_blob failed (ecdh): {}", e);
                return Err(CryptoError::EcImportFailed);
            }
        };
        // Import the blob into a CNG key handle for ECDH
        let alg_id_ecdh = curve_to_ecdh_algo_id(curveid)?;
        let algo_handle_ecdh =
            CngAlgoHandle::open(alg_id_ecdh, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0))?;
        let mut key_handle_ecdh = BCRYPT_KEY_HANDLE::default();
        // SAFETY: The algorithm handle, key_handle_ecdh pointer, and cng_blob_ecdh are valid for import. This call imports the public key blob into a CNG key handle.
        let status_ecdh = unsafe {
            BCryptImportKeyPair(
                algo_handle_ecdh.handle(),
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut key_handle_ecdh,
                &cng_blob_ecdh,
                0,
            )
        };
        if status_ecdh != STATUS_SUCCESS {
            tracing::error!("BCryptImportKeyPair (ecdh public) failed: {status_ecdh:?}");
            tracing::error!(
                "Blob passed to BCryptImportKeyPair (hex): {:x?}",
                cng_blob_ecdh
            );
            return Err(CryptoError::EcImportFailed);
        }
        Ok(EcPublicKey {
            public_key_handle: Arc::new(Mutex::new(CngPublicKeyHandle {
                cng_public_key: key_handle_ecdsa,
                cng_ecdh_public_key: key_handle_ecdh,
            })),
        })
    }

    /// Exports the EC public key to DER-encoded data.
    ///
    /// # Returns
    /// * `Result<Vec<u8>, CryptoError>` - The DER-encoded public key data, or an error if export fails.
    #[allow(unsafe_code)]
    fn ec_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        let mut pub_blob_len: u32 = 0;
        // SAFETY: Calls BCryptExportKey to query the size of the public key blob; all pointers and handles are valid.
        let status = unsafe {
            BCryptExportKey(
                self.public_key_handle.lock().unwrap().cng_public_key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                &mut pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptExportKey (size query) failed: {status:?}");
            return Err(CryptoError::EcExportFailed);
        }
        let mut pub_blob = vec![0u8; pub_blob_len as usize];
        // SAFETY: Calls BCryptExportKey to get actual blob; all pointers and handles are valid.
        let status = unsafe {
            BCryptExportKey(
                self.public_key_handle.lock().unwrap().cng_public_key,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                Some(pub_blob.as_mut_slice()),
                &mut pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptExportKey (export) failed: {status:?}");
            return Err(CryptoError::EcExportFailed);
        }
        if pub_blob.len() < 8 {
            tracing::error!("ECCPUBLIC_BLOB too short");
            return Err(CryptoError::EcExportFailed);
        }
        let key_size =
            u32::from_le_bytes([pub_blob[4], pub_blob[5], pub_blob[6], pub_blob[7]]) as usize;
        let (x, y) = if pub_blob.len() == 8 + 2 * key_size {
            (
                &pub_blob[8..8 + key_size],
                &pub_blob[8 + key_size..8 + 2 * key_size],
            )
        } else {
            tracing::error!(
                "ECCPUBLIC_BLOB size mismatch: expected {} got {}",
                8 + 2 * key_size,
                pub_blob.len()
            );
            return Err(CryptoError::EcExportFailed);
        };
        // Build uncompressed EC point
        let mut ec_point = Vec::with_capacity(1 + 2 * key_size);
        ec_point.push(0x04);
        ec_point.extend_from_slice(x);
        ec_point.extend_from_slice(y);
        // Determine curve OID
        let curve_oid = match key_size {
            32 => asn1::ObjectIdentifier::from_string("1.2.840.10045.3.1.7").unwrap(), // P-256
            48 => asn1::ObjectIdentifier::from_string("1.3.132.0.34").unwrap(),        // P-384
            66 => asn1::ObjectIdentifier::from_string("1.3.132.0.35").unwrap(),        // P-521
            _ => {
                tracing::error!("Unknown key size for curve OID: {}", key_size);
                return Err(CryptoError::EcExportFailed);
            }
        };
        // id-ecPublicKey OID
        let id_ec_public_key = asn1::ObjectIdentifier::from_string("1.2.840.10045.2.1").unwrap();
        #[derive(asn1::Asn1Write)]
        struct AlgorithmIdentifier {
            algorithm: asn1::ObjectIdentifier,
            parameters: asn1::ObjectIdentifier,
        }
        #[derive(asn1::Asn1Write)]
        struct SubjectPublicKeyInfo<'a> {
            algorithm: AlgorithmIdentifier,
            public_key: asn1::BitString<'a>,
        }
        let algorithm = AlgorithmIdentifier {
            algorithm: id_ec_public_key,
            parameters: curve_oid,
        };
        let public_key = asn1::BitString::new(&ec_point, 0).unwrap();
        let spki = SubjectPublicKeyInfo {
            algorithm,
            public_key,
        };
        let der_bytes = match asn1::write_single(&spki) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("ASN.1 DER encoding failed: {:?}", e);
                return Err(CryptoError::EcExportFailed);
            }
        };
        if der.len() < der_bytes.len() {
            tracing::error!(
                "DER output buffer too small: need {} bytes",
                der_bytes.len()
            );
            return Err(CryptoError::EcExportFailed);
        }
        der[..der_bytes.len()].copy_from_slice(&der_bytes);
        Ok(der_bytes.len())
    }

    /// Returns the size of the EC public key in bytes.
    ///
    /// # Returns
    /// * `Ok(usize)` - The key size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn size(&self) -> Result<usize, CryptoError> {
        let bits = self.public_key_handle.lock().unwrap().curve_degree()?;
        Ok(bits as usize)
    }
}

/// Helper to calculate the parsed length of a DER SEQUENCE
fn der_sequence_parsed_len(der: &[u8]) -> usize {
    if der.len() > 1 && der[0] == 0x30 {
        let len_byte = der[1] as usize;
        if len_byte & 0x80 == 0 {
            // Short form
            2 + len_byte
        } else {
            // Long form
            let num_len_bytes = len_byte & 0x7F;
            let mut len_val = 0usize;
            for i in 0..num_len_bytes {
                len_val = (len_val << 8) | der[2 + i] as usize;
            }
            2 + num_len_bytes + len_val
        }
    } else {
        0
    }
}

// These ASN.1 struct definitions are required for parsing and encoding EC keys and signatures
// using the `asn1` crate. They map directly to the ASN.1 structures defined in RFC 5915 (ECPrivateKey),
// RFC 5208 (PrivateKeyInfo), and X.509 SubjectPublicKeyInfo. The `Asn1Read`/`Asn1Write` derives
// allow the Rust code to serialize/deserialize DER-encoded keys and signatures for robust
// cross-platform interoperability.
#[derive(asn1::Asn1Read)]
struct PrivateKeyInfo<'a> {
    _version: u8,
    _algorithm: AlgorithmIdentifier<'a>,
    private_key: &'a [u8],
}

#[derive(asn1::Asn1Read)]
struct AlgorithmIdentifier<'a> {
    algorithm: asn1::ObjectIdentifier,
    _parameters: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read)]
struct ECPrivateKey<'a> {
    _version: u8,
    private_key: &'a [u8],
    #[implicit[0]]
    _parameters: Option<&'a [u8]>,
    #[explicit[1]]
    public_key: Option<asn1::BitString<'a>>,
}

// SubjectPublicKeyInfo
// ├── AlgorithmIdentifier
// │├── algorithm: id-ecPublicKey (1.2.840.10045.2.1)
// │└── parameters: secp256r1 (1.2.840.10045.3.1.7)
// └── subjectPublicKey: BIT STRING
// └── 04 || X || Y(Uncompressed EC point)
#[derive(asn1::Asn1Read)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    public_key: Option<asn1::BitString<'a>>,
}

/// Specifies the type of CNG blob to generate for EC private key import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcBlobKind {
    Ecdsa,
    Ecdh,
}

/// Converts a PKCS#8 DER-encoded EC private key to a CNG ECCPRIVATE_BLOB or ECDH blob.
///
/// # Arguments
/// * `der` - DER-encoded PKCS#8 private key as a byte slice.
/// * `curveid` - The elliptic curve identifier to use.
/// * `kind` - The blob kind (Ecdsa or Ecdh).
///
/// # Returns
/// * `Ok(Vec<u8>)` - CNG ECCPRIVATE_BLOB or ECDH blob bytes on success.
/// * `Err(CryptoError)` - If parsing or conversion fails.
pub fn pkcs8_ecprivatekey_to_cng_blob(
    der: &[u8],
    curveid: EcCurveId,
    kind: EcBlobKind,
) -> Result<Vec<u8>, CryptoError> {
    let pkcs8 = match asn1::parse_single::<PrivateKeyInfo<'_>>(der) {
        Ok(pkey_info) => pkey_info,
        Err(e) => {
            tracing::error!("Failed to parse, :{:?}", e);
            return Err(CryptoError::EcBackendError);
        }
    };
    match asn1::parse_single::<ECPrivateKey<'_>>(pkcs8.private_key) {
        Ok(ec_key) => {
            let pub_bytes = match &ec_key.public_key {
                Some(bitstring) => {
                    let bytes = bitstring.as_bytes();
                    if bytes.is_empty() {
                        tracing::error!("Public key BIT STRING is empty");
                        return Err(CryptoError::EcImportFailed);
                    }
                    if bytes[0] != 0x04 {
                        tracing::error!(
                            "Public key is not uncompressed (first byte: {:x})",
                            bytes[0]
                        );
                        return Err(CryptoError::EcImportFailed);
                    }
                    bytes
                }
                None => {
                    tracing::error!("No public key found in ECPrivateKey");
                    return Err(CryptoError::EcImportFailed);
                }
            };
            let (key_size, magic) = match (curveid, kind) {
                (EcCurveId::EccP256, EcBlobKind::Ecdsa) => (32, BCRYPT_ECDSA_PRIVATE_P256_MAGIC),
                (EcCurveId::EccP384, EcBlobKind::Ecdsa) => (48, BCRYPT_ECDSA_PRIVATE_P384_MAGIC),
                (EcCurveId::EccP521, EcBlobKind::Ecdsa) => (66, BCRYPT_ECDSA_PRIVATE_P521_MAGIC),
                (EcCurveId::EccP256, EcBlobKind::Ecdh) => (32, BCRYPT_ECDH_PRIVATE_P256_MAGIC),
                (EcCurveId::EccP384, EcBlobKind::Ecdh) => (48, BCRYPT_ECDH_PRIVATE_P384_MAGIC),
                (EcCurveId::EccP521, EcBlobKind::Ecdh) => (66, BCRYPT_ECDH_PRIVATE_P521_MAGIC),
            };
            if pub_bytes.len() != 1 + 2 * key_size {
                tracing::error!(
                    "Public key length mismatch: expected {} got {}",
                    1 + 2 * key_size,
                    pub_bytes.len()
                );
                return Err(CryptoError::EcImportFailed);
            }
            let x = &pub_bytes[1..1 + key_size];
            let y = &pub_bytes[1 + key_size..1 + 2 * key_size];
            let mut d = vec![0u8; key_size];
            let priv_bytes = ec_key.private_key;
            if priv_bytes.len() > key_size {
                tracing::error!("Private scalar too large: {} bytes", priv_bytes.len());
                return Err(CryptoError::EcImportFailed);
            }
            d[key_size - priv_bytes.len()..].copy_from_slice(priv_bytes);
            let mut blob = Vec::with_capacity(4 + 4 + 3 * key_size);
            blob.extend_from_slice(&magic.to_le_bytes());
            blob.extend_from_slice(&(key_size as u32).to_le_bytes());
            blob.extend_from_slice(x);
            blob.extend_from_slice(y);
            blob.extend_from_slice(&d);
            tracing::debug!("CNG ECCPRIVATE_BLOB (hex): {:x?}", blob);
            Ok(blob)
        }
        Err(e) => {
            tracing::error!("Failed to parse the pkcs8.private key : {:?}", e);
            tracing::error!(
                "Extra data if available: {:02X?}",
                der_sequence_parsed_len(pkcs8.private_key)
            );
            Err(CryptoError::EcBackendError)
        }
    }
}

/// Converts a DER-encoded ECDSA public key (SPKI) to a CNG-compatible ECCPUBLIC_BLOB.
///
/// # Arguments
/// * `der` - DER-encoded SubjectPublicKeyInfo (SPKI) as a byte slice.
/// * `curveid` - The elliptic curve identifier to use (EcdsaCurveId).
/// * `kind` - The blob kind (Ecdsa or Ecdh).
///
/// # Returns
/// * `Ok(Vec<u8>)` - The CNG ECCPUBLIC_BLOB bytes on success.
/// * `Err(CryptoError)` - If parsing or conversion fails.
///
/// # Details
/// - Parses the ASN.1 SPKI structure to extract the EC public key.
/// - Validates the key format and curve size.
/// - Converts the uncompressed EC point to the CNG ECCPUBLIC_BLOB format required by Windows CNG.
/// - Supports P-256, P-384, and P-521 curves.
fn spki_to_cng_public_blob(
    der: &[u8],
    curveid: EcCurveId,
    kind: EcBlobKind,
) -> Result<Vec<u8>, CryptoError> {
    // Parse the SubjectPublicKeyInfo
    let spki = match asn1::parse_single::<SubjectPublicKeyInfo<'_>>(der) {
        Ok(spki) => spki,
        Err(e) => {
            tracing::error!("Failed to parse SPKI: {:?}", e);
            return Err(CryptoError::EcImportFailed);
        }
    };
    tracing::debug!("SPKI public key Algo Id:{:?}", spki.algorithm.algorithm);
    // The public key is a BIT STRING, usually with 0x04 prefix for uncompressed
    let pub_bytes = match &spki.public_key {
        Some(bitstring) => bitstring.as_bytes(),
        None => {
            tracing::error!("No public key BIT STRING found in SPKI");
            return Err(CryptoError::EcImportFailed);
        }
    };
    let (key_size, magic) = match (curveid, kind) {
        (EcCurveId::EccP256, EcBlobKind::Ecdsa) => (32, BCRYPT_ECDSA_PUBLIC_P256_MAGIC),
        (EcCurveId::EccP384, EcBlobKind::Ecdsa) => (48, BCRYPT_ECDSA_PUBLIC_P384_MAGIC),
        (EcCurveId::EccP521, EcBlobKind::Ecdsa) => (66, BCRYPT_ECDSA_PUBLIC_P521_MAGIC),
        (EcCurveId::EccP256, EcBlobKind::Ecdh) => (32, BCRYPT_ECDH_PUBLIC_P256_MAGIC),
        (EcCurveId::EccP384, EcBlobKind::Ecdh) => (48, BCRYPT_ECDH_PUBLIC_P384_MAGIC),
        (EcCurveId::EccP521, EcBlobKind::Ecdh) => (66, BCRYPT_ECDH_PUBLIC_P521_MAGIC),
    };
    if pub_bytes.len() != 1 + 2 * key_size || pub_bytes[0] != 0x04 {
        tracing::error!(
            "SPKI public key length or format mismatch: expected {} got {}, first byte: {:x}",
            1 + 2 * key_size,
            pub_bytes.len(),
            pub_bytes.first().unwrap_or(&0)
        );
        return Err(CryptoError::EcImportFailed);
    }
    let x = &pub_bytes[1..1 + key_size];
    let y = &pub_bytes[1 + key_size..1 + 2 * key_size];
    // Build the CNG ECCPUBLIC_BLOB
    let mut blob = Vec::with_capacity(4 + 4 + 2 * key_size);
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&(key_size as u32).to_le_bytes());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);
    tracing::debug!("CNG ECCPUBLIC_BLOB (hex): {:x?}", blob);
    Ok(blob)
}
