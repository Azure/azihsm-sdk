// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
use std::slice;

use asn1::*;
use windows::core::PCWSTR;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::sha::*;

/// Creates the RSA encryption algorithm OID: 1.2.840.113549.1.1.1
fn rsa_encryption_oid() -> asn1::ObjectIdentifier {
    asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.1").unwrap()
}

/// Minimum supported RSA key size in bits.
const RSA_MIN_KEY_SIZE_BITS: usize = 512;
/// Maximum supported RSA key size in bits.
const RSA_MAX_KEY_SIZE_BITS: usize = 16384;
/// RSA key size step in bits.
const RSA_KEY_SIZE_STEP_BITS: usize = 64;

fn get_hash_algo_id(algo: HashAlgo) -> PCWSTR {
    match algo {
        HashAlgo::Sha1 => BCRYPT_SHA1_ALGORITHM,
        HashAlgo::Sha256 => BCRYPT_SHA256_ALGORITHM,
        HashAlgo::Sha384 => BCRYPT_SHA384_ALGORITHM,
        HashAlgo::Sha512 => BCRYPT_SHA512_ALGORITHM,
    }
}

/// Wrapper for a CNG private key handle.
pub struct CngRsaPrivateKeyHandle {
    private_key_handle: BCRYPT_KEY_HANDLE,
}

pub struct CngRsaPublicKeyHandle {
    public_key_handle: BCRYPT_KEY_HANDLE,
}
/// Wrapper for a CNG algorithm provider handle.
struct CngAlgoHandle {
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
    fn open(
        alg_id: PCWSTR,
        flags: BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    ) -> Result<Self, CryptoError> {
        let mut handle = BCRYPT_ALG_HANDLE::default();
        // SAFETY: calls BCryptOpenAlgorithmProvider; all pointers and handles are valid
        let status = unsafe { BCryptOpenAlgorithmProvider(&mut handle, alg_id, None, flags) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptOpenAlgorithmProvider failed: {status:?}");
            return Err(CryptoError::RsaError);
        }
        let cng_algo_handle = handle;
        Ok(CngAlgoHandle { cng_algo_handle })
    }

    /// Returns the underlying CNG algorithm handle.
    ///
    /// # Returns
    /// * `BCRYPT_ALG_HANDLE` - The raw algorithm handle.
    fn handle(&self) -> BCRYPT_ALG_HANDLE {
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
impl Drop for CngRsaPrivateKeyHandle {
    /// Drops the CngPrivateKeyHandle, releasing the CNG private key handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to destroy the key handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.private_key_handle) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (private) failed: {status:?}");
        } else {
            tracing::debug!("DROP: RSA Private Key Handle ");
        }
    }
}

impl Drop for CngRsaPublicKeyHandle {
    /// Drops the CngRsaPublicKeyHandle, releasing the CNG private key handle.
    ///
    /// # Safety
    /// Calls unsafe CNG function to destroy the key handle.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroyKey; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.public_key_handle) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyKey (public) failed: {status:?}");
        } else {
            tracing::debug!("DROP: RSA Public Key Handle ");
        }
    }
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
    #[allow(unsafe_code)]
    fn rsa_key_gen_pair(
        &self,
        size: usize,
    ) -> Result<(RsaPrivateKeyHandle, RsaPublicKeyHandle), CryptoError> {
        //Check if size is in increments of 64 bits > 512
        if size < RSA_MIN_KEY_SIZE_BITS {
            tracing::error!("RSA key size {size} is less than minimum {RSA_MIN_KEY_SIZE_BITS}");
            return Err(CryptoError::RsaKeySizeTooSmall);
        } else if size > RSA_MAX_KEY_SIZE_BITS {
            tracing::error!("RSA key size {size} is greater than maximum {RSA_MAX_KEY_SIZE_BITS}");
            return Err(CryptoError::RsaKeySizeTooLarge);
        } else if !size.is_multiple_of(RSA_KEY_SIZE_STEP_BITS) {
            tracing::error!("RSA key size {size} is not in steps of {RSA_KEY_SIZE_STEP_BITS}");
            return Err(CryptoError::RsaKeySizeInvalidStep);
        } else {
            tracing::debug!("Requested RSA KeySize : {:?}", size);
        }

        //Step1: Open algorithm provider
        let algo_handle: CngAlgoHandle = match CngAlgoHandle::open(
            BCRYPT_RSA_ALGORITHM,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ) {
            Ok(handle) => handle,
            Err(e) => {
                tracing::error!("Failed to open RSA backend Algo handle: {e:?} ");
                return Err(CryptoError::RsaAlgoOpenFailed);
            }
        };
        //Step2 : Generate Key pair
        let mut key_handle: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE::default();
        // SAFETY: algo_handle is a valid algorithm handle, key_handle is a valid mutable pointer, size is checked above, and flags are set to 0.
        let status: NTSTATUS =
            unsafe { BCryptGenerateKeyPair(algo_handle.handle(), &mut key_handle, size as u32, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptGenerateKeyPair failed: {status:?}");
            return Err(CryptoError::RsaKeyPairGenFailed);
        }
        // SAFETY: key_handle is a valid key handle returned by BCryptGenerateKeyPair, and flags are set to 0.
        let status = unsafe { BCryptFinalizeKeyPair(key_handle, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptFinalizeKeyPair failed: {status:?}");
            // SAFETY: key_handle is a valid key handle returned by BCryptGenerateKeyPair and needs to be destroyed if finalization failed.
            let destroy_status = unsafe { BCryptDestroyKey(key_handle) };
            if destroy_status != STATUS_SUCCESS {
                tracing::error!(
                    "BCryptDestroyKey (cleanup after finalize failure) failed: {destroy_status:?}"
                );
                return Err(CryptoError::RsaKeyPairCleanupFailed);
            }
            return Err(CryptoError::RsaKeyPairFinalizeFailed);
        }
        // Wrap the private key handle
        let priv_handle = RsaPrivateKeyHandle {
            private_key_handle: CngRsaPrivateKeyHandle {
                private_key_handle: key_handle,
            },
        };
        // Export public key as CNG blob
        let mut pub_blob_len = 0;
        // SAFETY: calls BCryptExportKey to query the size of the public key blob; all pointers and handles are valid
        let status = unsafe {
            BCryptExportKey(
                key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAPUBLIC_BLOB,
                None,
                &mut pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get public key blob size: {:?}", status);
            return Err(CryptoError::RsaExportBlobSizeFailed);
        }
        let mut pub_blob = vec![0u8; pub_blob_len as usize];
        let mut actual_pub_blob_len = 0;
        // SAFETY: calls BCryptExportKey to get public key blob; all pointers and handles are valid
        let status = unsafe {
            BCryptExportKey(
                key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAPUBLIC_BLOB,
                Some(&mut pub_blob),
                &mut actual_pub_blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to export public key blob: {:?}", status);
            return Err(CryptoError::RsaExportBlobFailed);
        }
        // Import public key blob as a new handle
        let mut pub_key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: calls BCryptImportKeyPair import the key blob and get handle; all pointers and handles are valid
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut pub_key_handle,
                &pub_blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to import public key blob: {:?}", status);
            return Err(CryptoError::RsaImportKeyFailed);
        }
        let pub_handle = RsaPublicKeyHandle {
            public_key_handle: CngRsaPublicKeyHandle {
                public_key_handle: pub_key_handle,
            },
        };
        Ok((priv_handle, pub_handle))
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
    #[allow(unsafe_code)]
    fn rsa_key_from_der(der: &[u8]) -> Result<RsaPrivateKeyHandle, CryptoError> {
        // Step 1: Decode as PKCS#8 PrivateKeyInfo (no fallback to PKCS#1)
        let private_key_info = match asn1::parse_single::<PrivateKeyInfo<'_>>(der) {
            Ok(private_key_info) => {
                tracing::debug!("[IMPORT] Detected PKCS#8 PrivateKeyInfo format");
                private_key_info
            }
            Err(_) => {
                tracing::error!("[IMPORT] Failed to parse PKCS#8 PrivateKeyInfo - only PKCS#8 format is supported");
                return Err(CryptoError::RsaDecodeFailed);
            }
        };

        // Verify this is an RSA key by checking the algorithm OID
        if private_key_info.algorithm.algorithm != rsa_encryption_oid() {
            tracing::error!(
                "[IMPORT] PKCS#8 key is not RSA (OID: {:?})",
                private_key_info.algorithm.algorithm
            );
            return Err(CryptoError::RsaDecodeFailed);
        }

        // Extract the PKCS#1 RSAPrivateKey from the privateKey OCTET STRING
        let pkcs1_der = private_key_info.private_key;

        // Step 2: Decode PKCS#1 DER private key using ASN.1 struct
        let pk = match asn1::parse_single::<RsaPrivateKey<'_>>(pkcs1_der) {
            Ok(pk) => pk,
            Err(_) => {
                tracing::error!("[IMPORT] ASN.1 DER decode failed for RSA private key");
                return Err(CryptoError::RsaDecodeFailed);
            }
        };
        // Step 3: Extract fields as big-endian bytes and trim leading zeros
        let n = trim_leading_zeros(pk.modulus.as_bytes());
        let e = trim_leading_zeros(pk.public_exponent.as_bytes());
        let d = trim_leading_zeros(pk.private_exponent.as_bytes());
        let p = trim_leading_zeros(pk.prime1.as_bytes());
        let q = trim_leading_zeros(pk.prime2.as_bytes());

        // Step 4: Extract CRT params directly from PKCS#1 DER (already computed)
        let dp = trim_leading_zeros(pk.exponent1.as_bytes());
        let dq = trim_leading_zeros(pk.exponent2.as_bytes());
        let qinv = trim_leading_zeros(pk.coefficient.as_bytes());

        tracing::debug!(
            "[IMPORT] Parsed private key field sizes: n={}, e={}, d={}, p={}, q={}, dp={}, dq={}, qinv={}",
            n.len(),
            e.len(),
            d.len(),
            p.len(),
            q.len(),
            dp.len(),
            dq.len(),
            qinv.len()
        );
        // Step 5: Calculate CNG blob sizes
        let (cb_modulus, cb_public_exp, cb_prime1, cb_prime2) = get_cng_blob_sizes(n, p, q, e);
        tracing::debug!(
            "[IMPORT] CNG blob sizes: cb_modulus={}, cb_public_exp={}, cb_prime1={}, cb_prime2={}",
            cb_modulus,
            cb_public_exp,
            cb_prime1,
            cb_prime2
        );
        // Step 6: Pad all fields to their expected CNG size (big-endian)
        let n_be = pad_left_be(n, cb_modulus);
        let e_trimmed = trim_leading_zeros(e);
        let e_be = pad_left_be(e_trimmed, cb_public_exp);
        let d_be = pad_left_be(d, cb_modulus);
        let p_be = pad_left_be(p, cb_prime1);
        let q_be = pad_left_be(q, cb_prime2);
        let dp_be = pad_left_be(dp, cb_prime1);
        let dq_be = pad_left_be(dq, cb_prime2);
        let qinv_be = pad_left_be(qinv, cb_prime1);
        // Step 7: Build the BCRYPT_RSAFULLPRIVATE_BLOB
        let mut blob = Vec::with_capacity(
            std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
                + cb_public_exp
                + cb_modulus
                + cb_prime1
                + cb_prime2
                + cb_prime1
                + cb_prime2
                + cb_prime1
                + cb_modulus,
        );
        let magic = BCRYPT_RSAFULLPRIVATE_MAGIC.0;
        let bitlen = cb_modulus as u32 * 8;
        let cb_pubexp = cb_public_exp as u32;
        let cb_mod = cb_modulus as u32;
        let cb_p1 = cb_prime1 as u32;
        let cb_p2 = cb_prime2 as u32;
        let total_blob_len = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>()
            + cb_public_exp
            + cb_modulus
            + cb_prime1
            + cb_prime2
            + cb_prime1
            + cb_prime2
            + cb_prime1
            + cb_modulus;
        tracing::debug!(
            "[IMPORT] CNG blob header: magic=0x{:08x}, bitlen={}, cb_pubexp={}, cb_mod={}, cb_p1={}, cb_p2={}, total_blob_len={}",
            magic, bitlen, cb_pubexp, cb_mod, cb_p1, cb_p2, total_blob_len
        );
        blob.extend_from_slice(&magic.to_le_bytes());
        blob.extend_from_slice(&bitlen.to_le_bytes());
        blob.extend_from_slice(&cb_pubexp.to_le_bytes());
        blob.extend_from_slice(&cb_mod.to_le_bytes());
        blob.extend_from_slice(&cb_p1.to_le_bytes());
        blob.extend_from_slice(&cb_p2.to_le_bytes());
        blob.extend_from_slice(&e_be);
        blob.extend_from_slice(&n_be);
        blob.extend_from_slice(&p_be);
        blob.extend_from_slice(&q_be);
        blob.extend_from_slice(&dp_be);
        blob.extend_from_slice(&dq_be);
        blob.extend_from_slice(&qinv_be);
        blob.extend_from_slice(&d_be);
        debug_assert_eq!(
            blob.len(),
            total_blob_len,
            "CNG blob length mismatch: got {}, expected {}",
            blob.len(),
            total_blob_len
        );
        // Step 8: Import into CNG
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: key_handle is a valid mutable pointer, blob is a valid CNG private key blob, algorithm handle is correct, and all pointers are valid for BCryptImportKeyPair.
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAFULLPRIVATE_BLOB,
                &mut key_handle,
                &blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[IMPORT] BCryptImportKeyPair failed: {:?}", status);
            return Err(CryptoError::RsaImportKeyFailed);
        }
        Ok(RsaPrivateKeyHandle {
            private_key_handle: CngRsaPrivateKeyHandle {
                private_key_handle: key_handle,
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
    #[allow(unsafe_code)]
    fn size(&self) -> Result<usize, CryptoError> {
        let mut key_bits_buf = [0u8; 4];
        let mut result_len: u32 = 0;
        // SAFETY: self.private_key_handle.cng_private_key is a valid key handle, key_bits_buf is a valid buffer, and all pointers are valid for BCryptGetProperty.
        let status = unsafe {
            BCryptGetProperty(
                self.private_key_handle.private_key_handle,
                BCRYPT_KEY_LENGTH,
                Some(&mut key_bits_buf[..]),
                &mut result_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!(
                "BCryptGetProperty(BCRYPT_KEY_LENGTH) failed for private key: {:?}",
                status
            );
            return Err(CryptoError::RsaError);
        }
        let key_bits = u32::from_le_bytes(key_bits_buf);
        Ok(key_bits as usize)
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
    #[allow(unsafe_code)]
    fn rsa_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        // Step 1: Export the private key as a CNG BCRYPT_RSAFULLPRIVATE_BLOB
        let mut blob_len = 0u32;
        // SAFETY: self.private_key_handle.cng_private_key is a valid key handle, blob_len is a valid pointer, and all pointers are valid for BCryptExportKey.
        let status = unsafe {
            BCryptExportKey(
                self.private_key_handle.private_key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAFULLPRIVATE_BLOB,
                None,
                &mut blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[EXPORT] BCryptExportKey (size) failed: {:?}", status);
            return Err(CryptoError::RsaExportBlobSizeFailed);
        }
        let mut blob = vec![0u8; blob_len as usize];
        let mut actual_len = 0u32;
        // SAFETY: self.private_key_handle.cng_private_key is a valid key handle, blob is a valid buffer, actual_len is a valid pointer, and all pointers are valid for BCryptExportKey.
        let status = unsafe {
            BCryptExportKey(
                self.private_key_handle.private_key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAFULLPRIVATE_BLOB,
                Some(&mut blob),
                &mut actual_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[EXPORT] BCryptExportKey failed: {:?}", status);
            return Err(CryptoError::RsaExportBlobFailed);
        }
        // Step 2: Parse the blob fields (see BCRYPT_RSAFULLPRIVATE_BLOB layout)
        if blob.len() < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() {
            tracing::error!("[EXPORT] CNG blob too short: {} bytes", blob.len());
            return Err(CryptoError::RsaDerEncodeFailed);
        }
        let cb_public_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let cb_modulus = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        let cb_prime1 = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]) as usize;
        let cb_prime2 = u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]) as usize;
        let mut offset = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
        let e_be = &blob[offset..offset + cb_public_exp];
        offset += cb_public_exp;
        let n_be = &blob[offset..offset + cb_modulus];
        offset += cb_modulus;
        let p_be = &blob[offset..offset + cb_prime1];
        offset += cb_prime1;
        let q_be = &blob[offset..offset + cb_prime2];
        offset += cb_prime2;
        let dp_be = &blob[offset..offset + cb_prime1];
        offset += cb_prime1;
        let dq_be = &blob[offset..offset + cb_prime2];
        offset += cb_prime2;
        let qinv_be = &blob[offset..offset + cb_prime1];
        offset += cb_prime1;
        let d_be = &blob[offset..offset + cb_modulus];
        // Step 3: Trim leading zeros for DER encoding
        let e_be_der = prepend_zero_if_needed(e_be);
        let n_be_der = prepend_zero_if_needed(n_be);
        let d_be_der = prepend_zero_if_needed(d_be);
        let p_be_der = prepend_zero_if_needed(p_be);
        let q_be_der = prepend_zero_if_needed(q_be);
        let dp_be_der = prepend_zero_if_needed(dp_be);
        let dq_be_der = prepend_zero_if_needed(dq_be);
        let qinv_be_der = prepend_zero_if_needed(qinv_be);

        // Step 4: Build ASN.1 struct for PKCS#1 RSAPrivateKey
        let asn1_pk = {
            let modulus = match asn1::BigUint::new(&n_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for modulus");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let public_exponent = match asn1::BigUint::new(&e_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for public_exponent");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let private_exponent = match asn1::BigUint::new(&d_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for private_exponent");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let prime1 = match asn1::BigUint::new(&p_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for prime1");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let prime2 = match asn1::BigUint::new(&q_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for prime2");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let exponent1 = match asn1::BigUint::new(&dp_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for exponent1");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let exponent2 = match asn1::BigUint::new(&dq_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for exponent2");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let coefficient = match asn1::BigUint::new(&qinv_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for coefficient");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            RsaPrivateKey {
                version: 0,
                modulus,
                public_exponent,
                private_exponent,
                prime1,
                prime2,
                exponent1,
                exponent2,
                coefficient,
                other_prime_infos: None,
            }
        };

        // Step 5: Encode PKCS#1 RSAPrivateKey to DER
        let pkcs1_der = match asn1::write_single(&asn1_pk) {
            Ok(encoded) => encoded,
            Err(_) => {
                tracing::error!("[EXPORT] ASN.1 PKCS#1 DER encode failed");
                return Err(CryptoError::RsaDerEncodeFailed);
            }
        };

        // Step 6: Wrap PKCS#1 key in PKCS#8 PrivateKeyInfo
        let algorithm_id = AlgorithmIdentifier {
            algorithm: rsa_encryption_oid(),
            parameters: None,
        };

        let private_key_info = PrivateKeyInfo {
            version: 0,
            algorithm: algorithm_id,
            private_key: &pkcs1_der,
            attributes: None,
        };

        // Step 7: Encode PKCS#8 PrivateKeyInfo to DER
        match asn1::write_single(&private_key_info) {
            Ok(encoded) => {
                if encoded.len() > der.len() {
                    tracing::error!(
                        "[EXPORT] DER buffer too small: need {}, have {}",
                        encoded.len(),
                        der.len()
                    );
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
                der[..encoded.len()].copy_from_slice(&encoded);
                tracing::debug!("[EXPORT] PKCS#8 DER output size: {} bytes", encoded.len());
                Ok(encoded.len())
            }
            Err(_) => {
                tracing::error!("[EXPORT] PKCS#8 DER encode failed");
                Err(CryptoError::RsaDerEncodeFailed)
            }
        }
    }

    /// Returns the maximum size of the DER-encoded private key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum size in bytes needed for DER encoding.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_get_key_der_size(&self) -> Result<usize, CryptoError> {
        // Conservative estimate: DER encoding of PKCS#8 RSA private key.
        // For n-bit key, modulus and private exponent are n bits, primes are n/2 bits, plus overhead.
        // PKCS#8 wraps the PKCS#1 key, so we need to account for both layers:
        // 1. PKCS#1 RSAPrivateKey has 8 INTEGER fields, each can be up to modulus_bytes.
        // 2. PKCS#8 PrivateKeyInfo wraps the PKCS#1 data with additional overhead.
        let key_bits = self.size()?;
        let modulus_bytes = key_bits.div_ceil(8);
        // PKCS#1 private key has 8 INTEGER fields, each can be up to modulus_bytes.
        // Add 64 bytes for PKCS#1 DER overhead (headers, tags, etc).
        let pkcs1_estimated = 8 * (modulus_bytes + 8) + 64;
        // PKCS#8 adds PrivateKeyInfo wrapper: version, AlgorithmIdentifier, OCTET STRING wrapper
        // Add another 64 bytes for PKCS#8 overhead.
        let pkcs8_estimated = pkcs1_estimated + 64;
        Ok(pkcs8_estimated)
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
    #[allow(unsafe_code)]
    fn rsa_key_from_der(der: &[u8]) -> Result<RsaPublicKeyHandle, CryptoError> {
        tracing::debug!(
            "[IMPORT] DER input ({} bytes): {:x?}",
            der.len(),
            &der[..der.len().min(32)]
        );

        // Step 1: Decode as SubjectPublicKeyInfo (no fallback to PKCS#1)
        let subject_public_key_info = match asn1::parse_single::<SubjectPublicKeyInfo<'_>>(der) {
            Ok(subject_public_key_info) => {
                tracing::debug!("[IMPORT] Detected SubjectPublicKeyInfo format");
                subject_public_key_info
            }
            Err(_) => {
                tracing::error!("[IMPORT] Failed to parse SubjectPublicKeyInfo - only PKCS#8 format is supported");
                return Err(CryptoError::RsaDecodeFailed);
            }
        };

        // Verify this is an RSA key by checking the algorithm OID
        if subject_public_key_info.algorithm.algorithm != rsa_encryption_oid() {
            tracing::error!(
                "[IMPORT] SubjectPublicKeyInfo key is not RSA (OID: {:?})",
                subject_public_key_info.algorithm.algorithm
            );
            return Err(CryptoError::RsaDecodeFailed);
        }

        // Extract the PKCS#1 RSAPublicKey from the subjectPublicKey BIT STRING
        let pkcs1_der = subject_public_key_info.subject_public_key.as_bytes();

        // Step 2: Decode PKCS#1 DER public key using ASN.1 struct
        let pk = match asn1::parse_single::<RsaPublicKey<'_>>(pkcs1_der) {
            Ok(pk) => pk,
            Err(_) => {
                tracing::error!("[IMPORT] ASN.1 DER decode failed for RSA public key");
                return Err(CryptoError::RsaDecodeFailed);
            }
        };
        // Step 3: Extract modulus and exponent as big-endian bytes and trim leading zeros
        let n = trim_leading_zeros(pk.modulus.as_bytes());
        let e = trim_leading_zeros(pk.public_exponent.as_bytes());
        tracing::debug!(
            "[IMPORT] Parsed modulus n ({} bytes), exponent e ({} bytes)",
            n.len(),
            e.len()
        );
        let cb_modulus = n.len();
        let cb_public_exp = e.len();
        // Step 4: Pad fields to the left (big-endian, CNG expects left-padding)
        let mut n_be = vec![0u8; cb_modulus];
        n_be[(cb_modulus - n.len())..].copy_from_slice(n);
        let mut e_be = vec![0u8; cb_public_exp];
        e_be[(cb_public_exp - e.len())..].copy_from_slice(e);
        tracing::debug!(
            "[IMPORT] e_be.len() = {}, n_be.len() = {}",
            e_be.len(),
            n_be.len()
        );
        // Step 5: Build the BCRYPT_RSAPUBLIC_BLOB manually (big-endian fields)
        let mut blob = Vec::new();
        blob.extend_from_slice(&BCRYPT_RSAPUBLIC_MAGIC.0.to_le_bytes());
        blob.extend_from_slice(&(cb_modulus as u32 * 8).to_le_bytes());
        blob.extend_from_slice(&(cb_public_exp as u32).to_le_bytes());
        blob.extend_from_slice(&(cb_modulus as u32).to_le_bytes());
        blob.extend_from_slice(&(0u32).to_le_bytes());
        blob.extend_from_slice(&(0u32).to_le_bytes());
        blob.extend_from_slice(&e_be);
        blob.extend_from_slice(&n_be);
        tracing::debug!(
            "[IMPORT] CNG blob header: magic=0x{:08x}, bitlen={}, cbPublicExp={}, cbModulus={}, total_blob_len={}",
            BCRYPT_RSAPUBLIC_MAGIC.0,
            cb_modulus as u32 * 8,
            cb_public_exp,
            cb_modulus,
            16 + cb_public_exp + cb_modulus
        );
        tracing::debug!(
            "[IMPORT] CNG blob ({} bytes): {:x?}",
            blob.len(),
            &blob[..blob.len().min(32)]
        );
        // Step 6: Import into CNG
        let mut key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: key_handle is a valid mutable pointer, blob is a valid CNG public key blob, algorithm handle is correct, and all pointers are valid for BCryptImportKeyPair.
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut key_handle,
                &blob,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[IMPORT] BCryptImportKeyPair failed: {:?}", status);
            return Err(CryptoError::RsaImportKeyFailed);
        }
        Ok(RsaPublicKeyHandle {
            public_key_handle: CngRsaPublicKeyHandle {
                public_key_handle: key_handle,
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
    #[allow(unsafe_code)]
    fn rsa_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        // Step 1: Export the public key as a CNG BCRYPT_RSAPUBLIC_BLOB
        let mut blob_len = 0u32;
        // SAFETY: self.public_key_handle.cng_public_key is a valid key handle, blob_len is a valid pointer, and all pointers are valid for BCryptExportKey.
        let status = unsafe {
            BCryptExportKey(
                self.public_key_handle.public_key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAPUBLIC_BLOB,
                None,
                &mut blob_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[EXPORT] BCryptExportKey (size) failed: {:?}", status);
            return Err(CryptoError::RsaExportBlobSizeFailed);
        }
        let mut blob = vec![0u8; blob_len as usize];
        let mut actual_len = 0u32;
        // SAFETY: self.public_key_handle.cng_public_key is a valid key handle, blob is a valid buffer, actual_len is a valid pointer, and all pointers are valid for BCryptExportKey.
        let status = unsafe {
            BCryptExportKey(
                self.public_key_handle.public_key_handle,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_RSAPUBLIC_BLOB,
                Some(&mut blob),
                &mut actual_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("[EXPORT] BCryptExportKey failed: {:?}", status);
            return Err(CryptoError::RsaExportBlobFailed);
        }
        // Step 2: Parse the blob fields (see BCRYPT_RSAPUBLIC_BLOB layout)
        if blob.len() < std::mem::size_of::<BCRYPT_RSAKEY_BLOB>() {
            tracing::error!("[EXPORT] CNG blob too short: {} bytes", blob.len());
            return Err(CryptoError::RsaDerEncodeFailed);
        }
        let cb_public_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
        let cb_modulus = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
        let mut offset = 24;
        let e_be = &blob[offset..offset + cb_public_exp];
        offset += cb_public_exp;
        let n_be = &blob[offset..offset + cb_modulus];
        // Step 3: Trim leading zeros and prepend zero if needed for ASN.1 DER
        let e_be_der = prepend_zero_if_needed(e_be);
        let n_be_der = prepend_zero_if_needed(n_be);
        // Step 4: Build ASN.1 struct for PKCS#1 RSAPublicKey
        let asn1_pk = {
            let modulus = match asn1::BigUint::new(&n_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for modulus");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            let public_exponent = match asn1::BigUint::new(&e_be_der) {
                Some(v) => v,
                None => {
                    tracing::error!("[EXPORT] ASN.1 BigUint::new failed for public_exponent");
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
            };
            RsaPublicKey {
                modulus,
                public_exponent,
            }
        };

        // Step 5: Encode PKCS#1 RSAPublicKey to DER
        let pkcs1_der = match asn1::write_single(&asn1_pk) {
            Ok(encoded) => encoded,
            Err(_) => {
                tracing::error!("[EXPORT] ASN.1 PKCS#1 DER encode failed");
                return Err(CryptoError::RsaDerEncodeFailed);
            }
        };

        // Step 6: Wrap PKCS#1 key in SubjectPublicKeyInfo
        let algorithm_id = AlgorithmIdentifier {
            algorithm: rsa_encryption_oid(),
            parameters: None,
        };

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: algorithm_id,
            subject_public_key: asn1::BitString::new(&pkcs1_der, 0).ok_or_else(|| {
                tracing::error!("[EXPORT] Failed to create BitString for public key");
                CryptoError::RsaDerEncodeFailed
            })?,
        };

        // Step 7: Encode SubjectPublicKeyInfo to DER
        match asn1::write_single(&subject_public_key_info) {
            Ok(encoded) => {
                if encoded.len() > der.len() {
                    tracing::error!(
                        "[EXPORT] DER buffer too small: need {}, have {}",
                        encoded.len(),
                        der.len()
                    );
                    return Err(CryptoError::RsaDerEncodeFailed);
                }
                der[..encoded.len()].copy_from_slice(&encoded);
                tracing::debug!(
                    "[EXPORT] SubjectPublicKeyInfo DER output size: {} bytes",
                    encoded.len()
                );
                Ok(encoded.len())
            }
            Err(_) => {
                tracing::error!("[EXPORT] SubjectPublicKeyInfo DER encode failed");
                Err(CryptoError::RsaDerEncodeFailed)
            }
        }
    }

    /// Returns the size of the key in bits.
    ///
    /// # Parameters
    /// - `&self`: Reference to the key handle.
    ///
    /// # Returns
    /// - `Ok(usize)`: The size of the key in bits.
    /// - `Err(CryptoError)`: If the key size could not be determined.
    #[allow(unsafe_code)]
    fn size(&self) -> Result<usize, CryptoError> {
        let mut key_bits_buf = [0u8; 4];
        let mut result_len: u32 = 0;
        // SAFETY: self.public_key_handle.cng_public_key is a valid key handle, key_bits_buf is a valid buffer, and all pointers are valid for BCryptGetProperty.
        let status = unsafe {
            BCryptGetProperty(
                self.public_key_handle.public_key_handle,
                BCRYPT_KEY_LENGTH,
                Some(&mut key_bits_buf[..]),
                &mut result_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!(
                "BCryptGetProperty(BCRYPT_KEY_LENGTH) failed for public key: {:?}",
                status
            );
            return Err(CryptoError::RsaError);
        }
        let key_bits = u32::from_le_bytes(key_bits_buf);
        Ok(key_bits as usize)
    }
    /// Returns the size of the estimated RSA public key der in bytes.
    ///
    /// # Returns
    /// * `Ok(usize)` - The size of the key in bits.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_get_key_der_size(&self) -> Result<usize, CryptoError> {
        // Estimate the maximum DER-encoded size for a SubjectPublicKeyInfo RSA public key.
        // For n-bit key, modulus is n bits, exponent is usually small (3 or 4 bytes).
        // SubjectPublicKeyInfo wraps the PKCS#1 public key with AlgorithmIdentifier + BIT STRING wrapper.
        let key_bits = self.size()?;
        let modulus_bytes = key_bits.div_ceil(8);
        // PKCS#1 public key has 2 INTEGER fields (modulus, exponent), plus DER overhead.
        // Add 32 bytes for PKCS#1 DER headers/tags, and 8 bytes for exponent.
        let pkcs1_estimated = modulus_bytes + 8 + 32;
        // SubjectPublicKeyInfo adds AlgorithmIdentifier and BIT STRING wrapper.
        // Add another 64 bytes for SubjectPublicKeyInfo overhead.
        let spki_estimated = pkcs1_estimated + 64;
        Ok(spki_estimated)
    }
}
#[allow(unsafe_code)]
fn pcwstr_to_u8_vec(pcwstr: PCWSTR) -> Vec<u8> {
    //SAFETY: use unsafe section to convert PCWSTR to vec
    unsafe {
        let mut len = 0;
        let ptr = pcwstr.0;

        // Count UTF-16 code units until null terminator
        while *ptr.add(len) != 0 {
            len += 1;
        }

        // Include null terminator
        let u16_slice = slice::from_raw_parts(ptr, len + 1);

        // Convert &[u16] to &[u8] by reinterpreting the memory
        let byte_ptr = u16_slice.as_ptr() as *const u8;
        let byte_len = u16_slice.len() * 2;

        slice::from_raw_parts(byte_ptr, byte_len).to_vec()
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
    #[allow(unsafe_code)]
    fn rsa_encrypt<'a>(
        &self,
        data: &[u8],
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        cipher_data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Check input data
        if data.is_empty() {
            tracing::error!("Input data to encrypt is empty");
            return Err(CryptoError::RsaEncryptInputEmpty);
        }
        if cipher_data.is_empty() {
            tracing::error!("Output buffer for cipher data is empty");
            return Err(CryptoError::RsaEncryptOutputBufferEmpty);
        }

        // For None padding, input must be exactly modulus size
        if let RsaCryptPadding::None = padding {
            let mut key_bits_buf = [0u8; 4];
            let mut result_len: u32 = 0;
            //SAFETY: Call unsafe BCRYPT function to read modulus size
            let status = unsafe {
                BCryptGetProperty(
                    self.public_key_handle.public_key_handle,
                    BCRYPT_KEY_LENGTH,
                    Some(&mut key_bits_buf[..]),
                    &mut result_len,
                    0,
                )
            };
            if status != STATUS_SUCCESS {
                tracing::error!("Failed to get key length for raw RSA encrypt: {:?}", status);
                return Err(CryptoError::RsaError);
            }
            let modulus_size = u32::from_le_bytes(key_bits_buf) as usize / 8;
            if data.len() != modulus_size {
                tracing::error!(
                    "Raw RSA encrypt input must be exactly modulus size ({} bytes), got {} bytes",
                    modulus_size,
                    data.len()
                );
                return Err(CryptoError::RsaEncryptInputWrongSize);
            }
        }

        // Prepare padding info - ensure it lives for the entire function
        // Create padding info outside match to ensure lifetime
        let oaep_padding_info: Option<BCRYPT_OAEP_PADDING_INFO>;
        #[allow(unused_assignments)]
        let (padding_info_ptr, padding_flags) = match padding {
            RsaCryptPadding::Oaep => {
                let algo_id = get_hash_algo_id(hash_algo);
                let info = BCRYPT_OAEP_PADDING_INFO {
                    pszAlgId: algo_id,
                    pbLabel: label.map_or(std::ptr::null_mut(), |l| l.as_ptr() as *mut u8),
                    cbLabel: label.map_or(0, |l| l.len() as u32),
                };
                oaep_padding_info = Some(info);
                let padding_info_ptr =
                    oaep_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_OAEP)
            }
            // For None, flags must be BCRYPT_FLAGS(0) (not BCRYPT_PAD_NONE or 0)
            RsaCryptPadding::None => {
                oaep_padding_info = None;
                (None, BCRYPT_FLAGS(0))
            }
        };

        // Read required size
        let mut cipher_len = 0;
        // SAFETY:  call BCRYPT function to read expected cipher text length
        let status = unsafe {
            BCryptEncrypt(
                self.public_key_handle.public_key_handle,
                Some(data),
                padding_info_ptr,
                None,
                None,
                &mut cipher_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get expected cipher length: {:?}", status);
            return Err(CryptoError::RsaEncryptGetCipherLenFailed);
        }
        if cipher_len as usize > cipher_data.len() {
            tracing::error!(
                "Cipher buffer size is too small. expected: {:?}, actual: {:?}",
                cipher_len,
                cipher_data.len()
            );
            return Err(CryptoError::RsaEncryptOutputBufferTooSmall);
        }
        let mut actual_len = 0;
        // Do actual encryption
        // SAFETY:  call BCRYPT function to encrypt data
        let status = unsafe {
            BCryptEncrypt(
                self.public_key_handle.public_key_handle,
                Some(data),
                padding_info_ptr,
                None,
                Some(cipher_data),
                &mut actual_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to encrypt data: {:?}", status);
            return Err(CryptoError::RsaEncryptFailed);
        }
        if actual_len != cipher_len {
            tracing::error!(
                "Expected cipher text length not matching with actual length : Expected {:?}, actual :{:?}",
                cipher_len, actual_len
            );
            return Err(CryptoError::RsaEncryptLengthMismatch);
        }
        Ok(&cipher_data[..actual_len as usize])
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
    #[allow(unsafe_code)]
    fn rsa_verify(
        &self,
        data: &[u8],
        padding: RsaSignaturePadding,
        hash_algo: HashAlgo,
        salt_size: Option<usize>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if data.is_empty() {
            tracing::error!("Input data to verify is empty");
            return Err(CryptoError::RsaVerifyInputEmpty);
        }
        if signature.is_empty() {
            tracing::error!("Signature to verify is empty");
            return Err(CryptoError::RsaVerifySignatureEmpty);
        }
        tracing::debug!("Verifying signature: data.len={}, signature.len={}, padding={:?}, hash_algo={:?}, salt_size={:?}", data.len(), signature.len(), padding, hash_algo, salt_size);

        // Windows CNG does not support PKCS#1 v1.5 + SHA-512 + 3072-bit keys (NIST SP 800-131A, FIPS)
        if let RsaSignaturePadding::Pkcs1_5 = padding {
            if let HashAlgo::Sha512 = hash_algo {
                if self.size()? == 3072 {
                    tracing::error!("PKCS#1 v1.5 + SHA-512 + 3072-bit key is not supported by CNG (FIPS/NIST restriction)");
                    return Err(CryptoError::RsaNotSupported);
                }
            }
        }

        // Create padding structures outside match to ensure lifetime spans entire function
        let pss_padding_info: Option<BCRYPT_PSS_PADDING_INFO>;
        let pkcs1_padding_info: Option<BCRYPT_PKCS1_PADDING_INFO>;
        #[allow(unused_assignments)]
        let (padding_info_ptr, padding_flags) = match padding {
            RsaSignaturePadding::Pss => {
                let salt_len = match salt_size {
                    Some(sz) => sz,
                    None => {
                        tracing::error!("PSS padding selected but no salt_size provided");
                        return Err(CryptoError::RsaPssSaltlenInvalid);
                    }
                };
                validate_pss_salt_len_with_modulus(self.size()?, hash_algo, salt_len)?;
                let algo_id = get_hash_algo_id(hash_algo);
                pss_padding_info = Some(BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: algo_id,
                    cbSalt: salt_len as u32,
                });
                pkcs1_padding_info = None;
                let padding_info_ptr =
                    pss_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_PSS)
            }
            RsaSignaturePadding::Pkcs1_5 => {
                let algo_id = get_hash_algo_id(hash_algo);

                pss_padding_info = None; // Unused variable

                pkcs1_padding_info = Some(BCRYPT_PKCS1_PADDING_INFO { pszAlgId: algo_id });
                let padding_info_ptr =
                    pkcs1_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_PKCS1)
            }
        };
        let digest_len = get_digest_size(hash_algo);
        let mut digest_bytes = vec![0u8; digest_len];
        // get the digest
        hash_algo.hash(data, &mut digest_bytes)?;

        // SAFETY: All pointers and handles are valid, CNG API is used as intended
        let status = unsafe {
            BCryptVerifySignature(
                self.public_key_handle.public_key_handle,
                padding_info_ptr,
                &digest_bytes,
                signature,
                padding_flags,
            )
        };
        if status == STATUS_SUCCESS {
            tracing::debug!("Signature verification succeeded");
            Ok(())
        } else {
            tracing::error!("Signature verification failed: status={:?}", status);
            Err(CryptoError::RsaVerifyFailed)
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
    /// # Returns
    /// * `Ok(usize)` - The required output buffer size in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    #[allow(unsafe_code)]
    fn rsa_encrypt_len(
        &self,
        data_len: usize,
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
    ) -> Result<usize, CryptoError> {
        // Get modulus size in bytes
        let mut key_bits_buf = [0u8; 4];
        let mut result_len: u32 = 0;
        //SAFETY: Call BCRYPT GetProperty to read  the key length
        let status = unsafe {
            BCryptGetProperty(
                self.public_key_handle.public_key_handle,
                BCRYPT_KEY_LENGTH,
                Some(&mut key_bits_buf[..]),
                &mut result_len,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!(
                "BCryptGetProperty(BCRYPT_KEY_LENGTH) failed for public key: {:?}",
                status
            );
            return Err(CryptoError::RsaError);
        }
        let modulus_size = u32::from_le_bytes(key_bits_buf) as usize / 8;
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
                    return Err(CryptoError::RsaEncryptInputTooLarge);
                }
            }
            RsaCryptPadding::None => {
                if data_len != modulus_size {
                    return Err(CryptoError::RsaEncryptInputWrongSize);
                }
            }
        }
        Ok(modulus_size)
    }

    /// Wraps user data using RSA wrap encryption (AES-KW2 + RSA-OAEP).
    ///
    /// This function implements a RSA wrap encryption scheme:
    /// 1. Generates a random AES key-encryption-key (KEK)
    /// 2. Encrypts the user data with AES Key Wrap 2 (RFC 5649)
    /// 3. Encrypts the AES KEK with RSA-OAEP
    /// 4. Returns: [RSA-OAEP Encrypted AES KEK | AES-KW2 Encrypted User Data]
    ///
    /// # Arguments
    /// * `user_data` - The plaintext user data to wrap.
    /// * `aes_key_size` - The size of the AES KEK to generate.
    /// * `hash_algo` - The OAEP hash algorithm for RSA encryption.
    /// * `label` - Optional OAEP label.
    /// * `wrapped_data` - Output buffer for the complete wrapped blob.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The wrapped blob bytes.
    /// * `Err(CryptoError)` - If wrapping fails.
    #[allow(unsafe_code)]
    fn rsa_wrap<'a>(
        &self,
        user_data: &[u8],
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        wrapped_blob: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Input validation
        if user_data.is_empty() {
            tracing::error!("User data to wrap is empty");
            return Err(CryptoError::RsaWrapInputEmpty);
        }
        if wrapped_blob.is_empty() {
            tracing::error!("Output buffer for wrapped blob is empty");
            return Err(CryptoError::RsaWrapOutputBufferEmpty);
        }

        // Check if output buffer is large enough
        let required_size = self.rsa_wrap_len(user_data.len(), aes_key_size, hash_algo)?;
        if wrapped_blob.len() < required_size {
            tracing::error!(
                "Output buffer too small: required {}, got {}",
                required_size,
                wrapped_blob.len()
            );
            return Err(CryptoError::RsaWrapOutputBufferTooSmall);
        }

        // Step 1: Generate random AES KEK using Windows CNG
        let aes_kek_len = aes_key_size.key_len();
        let mut aes_kek = vec![0u8; aes_kek_len];
        // SAFETY: BCryptGenRandom with default provider is safe for generating random bytes
        let status = unsafe {
            BCryptGenRandom(
                BCRYPT_ALG_HANDLE::default(),
                &mut aes_kek,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to generate random AES KEK: {:?}", status);
            return Err(CryptoError::RsaWrapAesKeyGenFailed);
        }

        // Step 2: Open AES algorithm provider for Key Wrap
        let mut aes_alg_handle = BCRYPT_ALG_HANDLE::default();
        // SAFETY: BCryptOpenAlgorithmProvider is safe with valid parameters
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut aes_alg_handle,
                BCRYPT_AES_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open AES algorithm provider: {:?}", status);
            return Err(CryptoError::RsaWrapAesEncryptFailed);
        }

        // Step 3: Set AES chaining mode to ECB for manual Key Wrap implementation
        let ecb_mode_bytes = pcwstr_to_u8_vec(BCRYPT_CHAIN_MODE_ECB);

        // SAFETY: BCryptSetProperty is safe with valid handle and data
        let status = unsafe {
            BCryptSetProperty(
                aes_alg_handle.into(),
                BCRYPT_CHAINING_MODE,
                ecb_mode_bytes.as_slice(),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to set AES-ECB mode: {:?}", status);
            // SAFETY: Close the algorithm handle on error
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
            }
            return Err(CryptoError::RsaWrapAesEncryptFailed);
        }

        // Step 4: Import the AES KEK
        let mut aes_key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: BCryptGenerateSymmetricKey is safe with valid parameters
        let status = unsafe {
            BCryptGenerateSymmetricKey(aes_alg_handle, &mut aes_key_handle, None, &aes_kek, 0)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to import AES KEK: {:?}", status);
            // SAFETY: Close the algorithm handle on error
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
            }
            return Err(CryptoError::RsaWrapAesEncryptFailed);
        }

        // Step 5: Perform AES-KW2 encryption using our implementation
        let rsa_encrypted_len =
            self.rsa_encrypt_len(aes_kek_len, RsaCryptPadding::Oaep, hash_algo)?;
        let aes_wrapped_offset = rsa_encrypted_len;

        // Perform AES-KW2 encryption
        let actual_wrapped_len = aes_kw2_wrap(
            aes_key_handle,
            user_data,
            &mut wrapped_blob[aes_wrapped_offset..],
        )
        .inspect_err(|_e| {
            // Cleanup on error
            // SAFETY: Cleanup CNG handles on error, safe to ignore return values
            unsafe {
                let _ = BCryptDestroyKey(aes_key_handle);
                let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
            }
        })?;

        // Cleanup AES resources
        // SAFETY: Cleanup CNG handles after successful operation, safe to ignore return values
        unsafe {
            let _ = BCryptDestroyKey(aes_key_handle);
            let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
        }

        // Step 6: Encrypt AES KEK with RSA-OAEP
        let mut rsa_encrypted_key = vec![0u8; rsa_encrypted_len];
        let rsa_encrypted = self.rsa_encrypt(
            &aes_kek,
            RsaCryptPadding::Oaep,
            hash_algo,
            label,
            &mut rsa_encrypted_key,
        )?;

        // Step 7: Build the final blob: [RSA-OAEP Encrypted AES KEK | AES Key Wrap Encrypted User Data]
        let mut offset = 0;

        // Copy RSA-encrypted AES KEK
        wrapped_blob[offset..offset + rsa_encrypted.len()].copy_from_slice(rsa_encrypted);
        offset += rsa_encrypted.len();

        // AES-KW2 wrapped data is already in place at the correct offset
        offset += actual_wrapped_len;

        tracing::debug!(
            "RSA wrap successful: RSA KEK={}, AES wrapped data={}, total={}",
            rsa_encrypted.len(),
            actual_wrapped_len,
            offset
        );

        Ok(&wrapped_blob[..offset])
    }

    /// Returns the required output buffer size for RSA wrapping.
    fn rsa_wrap_len(
        &self,
        user_data_len: usize,
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
    ) -> Result<usize, CryptoError> {
        let aes_kek_len = aes_key_size.key_len();

        // RSA-encrypted AES KEK size
        let rsa_encrypted_size =
            self.rsa_encrypt_len(aes_kek_len, RsaCryptPadding::Oaep, hash_algo)?;

        // AES Key Wrap 2 output size (RFC 5649): padded to 8-byte boundary + 8 bytes ICV
        // The Key Wrap 2 algorithm pads input to 8-byte boundary and adds 8 bytes ICV
        let padded_len = user_data_len.div_ceil(8) * 8; // Round up to 8-byte boundary
        let aes_wrapped_size = padded_len + 8;

        let total_size = rsa_encrypted_size + aes_wrapped_size;
        Ok(total_size)
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
    #[allow(unsafe_code)]
    fn rsa_decrypt<'a>(
        &self,
        cipher_data: &[u8],
        padding: RsaCryptPadding,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Check input data
        if cipher_data.is_empty() {
            tracing::error!("Input cipher data to decrypt is empty");
            return Err(CryptoError::RsaDecryptInputEmpty);
        }
        if data.is_empty() {
            tracing::error!("Output buffer for decrypted data is empty");
            return Err(CryptoError::RsaDecryptOutputBufferEmpty);
        }
        // Create padding structure outside match to ensure lifetime spans entire function
        let oaep_padding_info: Option<BCRYPT_OAEP_PADDING_INFO>;

        // Prepare padding info
        #[allow(unused_assignments)]
        let (padding_info_ptr, padding_flags) = match padding {
            RsaCryptPadding::Oaep => {
                let algo_id = get_hash_algo_id(hash_algo);
                oaep_padding_info = Some(BCRYPT_OAEP_PADDING_INFO {
                    pszAlgId: algo_id,
                    pbLabel: label.map_or(std::ptr::null_mut(), |l| l.as_ptr() as *mut u8),
                    cbLabel: label.map_or(0, |l| l.len() as u32),
                });
                let padding_info_ptr =
                    oaep_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_OAEP)
            }
            // For None, flags must be BCRYPT_FLAGS(0) (not BCRYPT_PAD_NONE or 0)
            RsaCryptPadding::None => {
                oaep_padding_info = None;
                (None, BCRYPT_FLAGS(0))
            }
        };
        // Read required size
        let mut plain_len = 0;
        // SAFETY: call BCRYPT function to read expected plain text length
        let status = unsafe {
            BCryptDecrypt(
                self.private_key_handle.private_key_handle,
                Some(cipher_data),
                padding_info_ptr,
                None,
                None,
                &mut plain_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get expected plain text length: {:?}", status);
            return Err(CryptoError::RsaDecryptGetPlainLenFailed);
        }
        if plain_len as usize > data.len() {
            tracing::error!(
                "Decrypted buffer size is too small. expected: {:?}, actual: {:?}",
                plain_len,
                data.len()
            );
            return Err(CryptoError::RsaDecryptOutputBufferTooSmall);
        }
        let mut actual_len = 0;
        // Do actual decryption
        // SAFETY: call BCRYPT function to decrypt data
        let status = unsafe {
            BCryptDecrypt(
                self.private_key_handle.private_key_handle,
                Some(cipher_data),
                padding_info_ptr,
                None,
                Some(data),
                &mut actual_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to decrypt data: {:?}", status);
            return Err(CryptoError::RsaDecryptFailed);
        }
        if actual_len != plain_len {
            tracing::error!(
                "Expected plain text length not matching with actual length : Expected {:?}, actual :{:?}",
                plain_len, actual_len
            );
            return Err(CryptoError::RsaDecryptLengthMismatch);
        }
        Ok(&data[..actual_len as usize])
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
    #[allow(unsafe_code)]
    fn rsa_sign<'a>(
        &self,
        data: &[u8],
        padding: RsaSignaturePadding,
        hash_algo: HashAlgo,
        salt_size: Option<usize>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        if data.is_empty() {
            tracing::error!("Input data to sign is empty");
            return Err(CryptoError::RsaSignInputEmpty);
        }
        if signature.is_empty() {
            tracing::error!("Output buffer for signature is empty");
            return Err(CryptoError::RsaSignOutputBufferEmpty);
        }
        tracing::debug!("Signing data: data.len={}, signature.len={}, padding={:?}, hash_algo={:?}, salt_size={:?}", data.len(), signature.len(), padding, hash_algo, salt_size);

        // Hash the input data using the selected hash algorithm
        let digest_len = get_digest_size(hash_algo);

        let mut digest_bytes = vec![0u8; digest_len];
        // get the digest
        hash_algo.hash(data, &mut digest_bytes)?;

        // Create padding structures outside match to ensure lifetime spans entire function
        let pss_padding_info: Option<BCRYPT_PSS_PADDING_INFO>;
        let pkcs1_padding_info: Option<BCRYPT_PKCS1_PADDING_INFO>;

        #[allow(unused_assignments)]
        let (padding_info_ptr, padding_flags) = match padding {
            RsaSignaturePadding::Pss => {
                let salt_len = match salt_size {
                    Some(sz) => sz,
                    None => {
                        tracing::error!("PSS padding selected but no salt_size provided");
                        return Err(CryptoError::RsaPssSaltlenInvalid);
                    }
                };
                validate_pss_salt_len_with_modulus(self.size()?, hash_algo, salt_len)?;
                let algo_id = get_hash_algo_id(hash_algo);
                pss_padding_info = Some(BCRYPT_PSS_PADDING_INFO {
                    pszAlgId: algo_id,
                    cbSalt: salt_len as u32,
                });
                pkcs1_padding_info = None;
                let padding_info_ptr =
                    pss_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_PSS)
            }
            RsaSignaturePadding::Pkcs1_5 => {
                let algo_id = get_hash_algo_id(hash_algo);

                pss_padding_info = None; // Unused variable

                pkcs1_padding_info = Some(BCRYPT_PKCS1_PADDING_INFO { pszAlgId: algo_id });
                let padding_info_ptr =
                    pkcs1_padding_info.as_ref().unwrap() as *const _ as *const std::ffi::c_void;
                (Some(padding_info_ptr), BCRYPT_PAD_PKCS1)
            }
        };

        let mut sig_len = 0u32;
        // SAFETY: All pointers and handles are valid, CNG API is used as intended
        let status = unsafe {
            BCryptSignHash(
                self.private_key_handle.private_key_handle,
                padding_info_ptr,
                &digest_bytes,
                None,
                &mut sig_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (size) failed: status={:?}", status);
            return Err(CryptoError::RsaSignFailed);
        }
        if sig_len as usize > signature.len() {
            tracing::error!(
                "Signature buffer too small: required {}, provided {}",
                sig_len,
                signature.len()
            );
            return Err(CryptoError::RsaSignOutputBufferTooSmall);
        }
        let mut actual_len = 0u32;
        // SAFETY: All pointers and handles are valid, CNG API is used as intended, signature buffer is large enough
        let status = unsafe {
            BCryptSignHash(
                self.private_key_handle.private_key_handle,
                padding_info_ptr,
                &digest_bytes,
                Some(signature),
                &mut actual_len,
                padding_flags,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash failed: status={:?}", status);
            return Err(CryptoError::RsaSignFailed);
        }
        if actual_len != sig_len {
            tracing::error!(
                "Signature length mismatch: expected {}, got {}",
                sig_len,
                actual_len
            );
            return Err(CryptoError::RsaSignLengthMismatch);
        }
        tracing::debug!("Signature generated successfully, length={}", actual_len);
        Ok(&signature[..actual_len as usize])
    }
    /// Returns the maximum size of the signature buffer required for signing with this key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum signature size in bytes.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_max_signature_len(&self) -> Result<usize, CryptoError> {
        // The maximum signature length for RSA is the modulus size in bytes.
        // This is true for both PKCS#1 v1.5 and PSS paddings.
        let key_bits = self.size()?;
        Ok(key_bits.div_ceil(8))
    }

    /// Returns the maximum size of the decrypted data buffer required for this key.
    ///
    /// # Returns
    /// * `Ok(usize)` - The maximum decrypted data size in bytes.
    /// * `Err(CryptoError)` - If the key size could not be determined.
    fn rsa_max_decrypt_len(&self) -> Result<usize, CryptoError> {
        // The maximum size of decrypted data for RSA is the modulus size in bytes.
        // For OAEP, the actual plaintext is less, but this is the upper bound.
        let key_bits = self.size()?;
        Ok(key_bits.div_ceil(8))
    }

    /// Unwraps user data using RSA unwrap decryption (RSA-OAEP + AES-KW2).
    ///
    /// This function implements RSA unwrap decryption for data wrapped by `rsa_wrap`:
    /// 1. Parses the wrapped blob: [RSA-OAEP Encrypted AES KEK | AES-KW2 Encrypted User Data]
    /// 2. Decrypts the AES KEK using RSA-OAEP
    /// 3. Decrypts the user data using AES Key Wrap 2 (RFC 5649)
    ///
    /// # Arguments
    /// * `wrapped_blob` - The complete wrapped blob from `rsa_wrap`.
    /// * `aes_key_size` - The size of the AES KEK used.
    /// * `hash_algo` - The OAEP hash algorithm used for RSA decryption.
    /// * `label` - Optional OAEP label (must match the one used in wrapping).
    /// * `unwrapped_data` - Output buffer for the unwrapped user data.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - The unwrapped user data bytes.
    /// * `Err(CryptoError)` - If unwrapping fails.
    #[allow(unsafe_code)]
    fn rsa_unwrap<'a>(
        &self,
        wrapped_blob: &[u8],
        aes_key_size: AesKeySize,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        unwrapped_data: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Input validation
        if wrapped_blob.is_empty() {
            tracing::error!("Wrapped blob to unwrap is empty");
            return Err(CryptoError::RsaUnwrapInputEmpty);
        }
        if unwrapped_data.is_empty() {
            tracing::error!("Output buffer for unwrapped data is empty");
            return Err(CryptoError::RsaUnwrapOutputBufferEmpty);
        }

        // Calculate expected component sizes
        let aes_kek_len = aes_key_size.key_len();
        let modulus_size = self.size()? / 8; // Convert bits to bytes
        let min_blob_size = modulus_size + 16; // At least 8 bytes for Key Wrap overhead + some data

        if wrapped_blob.len() < min_blob_size {
            tracing::error!(
                "Wrapped blob too small: {} bytes, minimum expected: {}",
                wrapped_blob.len(),
                min_blob_size
            );
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        // Parse the blob: [RSA-OAEP Encrypted AES KEK | AES Key Wrap Encrypted User Data]
        let mut offset = 0;

        // Step 1: Extract and decrypt the RSA-encrypted AES KEK
        let rsa_encrypted_kek = &wrapped_blob[offset..offset + modulus_size];
        offset += modulus_size;

        let mut aes_kek = vec![0u8; aes_kek_len];
        let decrypted_kek = self.rsa_decrypt(
            rsa_encrypted_kek,
            RsaCryptPadding::Oaep,
            hash_algo,
            label,
            &mut aes_kek,
        )?;

        // Validate the decrypted KEK size
        if decrypted_kek.len() != aes_kek_len {
            tracing::error!(
                "Decrypted AES KEK size mismatch: expected {}, got {}",
                aes_kek_len,
                decrypted_kek.len()
            );
            return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
        }

        // Step 2: Extract the AES Key Wrap encrypted user data
        let wrapped_data = &wrapped_blob[offset..];
        if wrapped_data.is_empty() {
            tracing::error!("No AES Key Wrap encrypted data found in wrapped blob");
            return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
        }

        // Step 3: Open AES algorithm provider for Key Wrap
        let mut aes_alg_handle = BCRYPT_ALG_HANDLE::default();
        // SAFETY: BCryptOpenAlgorithmProvider is safe with valid parameters
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut aes_alg_handle,
                BCRYPT_AES_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open AES algorithm provider: {:?}", status);
            return Err(CryptoError::RsaUnwrapAesDecryptFailed);
        }

        // Step 4: Set AES chaining mode to ECB for manual Key Wrap implementation
        let ecb_mode_bytes = {
            // SAFETY: BCRYPT_CHAIN_MODE_ECB is a valid PCWSTR constant
            let mode_wide = unsafe { BCRYPT_CHAIN_MODE_ECB.as_wide() };
            // SAFETY: mode_wide is a valid pointer from Windows API, creating byte slice for BCryptSetProperty
            unsafe {
                std::slice::from_raw_parts(
                    mode_wide.as_ptr() as *const u8,
                    std::mem::size_of_val(mode_wide),
                )
            }
        };

        // SAFETY: BCryptSetProperty is safe with valid handle and data
        let status = unsafe {
            BCryptSetProperty(
                aes_alg_handle.into(),
                BCRYPT_CHAINING_MODE,
                ecb_mode_bytes,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to set AES-ECB mode: {:?}", status);
            // SAFETY: Close the algorithm handle on error
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
            }
            return Err(CryptoError::RsaUnwrapAesDecryptFailed);
        }

        // Step 5: Import the AES KEK
        let mut aes_key_handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: BCryptGenerateSymmetricKey is safe with valid parameters
        let status = unsafe {
            BCryptGenerateSymmetricKey(aes_alg_handle, &mut aes_key_handle, None, decrypted_kek, 0)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to import AES KEK: {:?}", status);
            // SAFETY: Close the algorithm handle on error
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
            }
            return Err(CryptoError::RsaUnwrapAesDecryptFailed);
        }

        // Step 6: Perform AES-KW2 decryption using our implementation
        let actual_unwrapped_len = aes_kw2_unwrap(aes_key_handle, wrapped_data, unwrapped_data)
            .inspect_err(|_e| {
                // Cleanup on error
                // SAFETY: Cleanup CNG handles on error, safe to ignore return values
                unsafe {
                    let _ = BCryptDestroyKey(aes_key_handle);
                    let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
                }
            })?;

        // Cleanup AES resources
        // SAFETY: Cleanup CNG handles after successful operation, safe to ignore return values
        unsafe {
            let _ = BCryptDestroyKey(aes_key_handle);
            let _ = BCryptCloseAlgorithmProvider(aes_alg_handle, 0);
        }

        tracing::debug!(
            "RSA unwrap successful: AES KEK={}, unwrapped data={}",
            aes_kek_len,
            actual_unwrapped_len
        );

        Ok(&unwrapped_data[..actual_unwrapped_len])
    }

    /// Returns the maximum size of the unwrapped user data buffer required.
    fn rsa_unwrap_len(
        &self,
        wrapped_blob_len: usize,
        _aes_key_size: AesKeySize,
    ) -> Result<usize, CryptoError> {
        let modulus_size = self.size()? / 8;

        if wrapped_blob_len < modulus_size {
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        // AES Key Wrap 2 data size (subtract RSA encrypted KEK size)
        let aes_wrapped_data_size = wrapped_blob_len - modulus_size;

        // AES Key Wrap 2 removes 8 bytes ICV and any padding
        // Maximum user data size is wrapped_data_size - 8 (ICV)
        if aes_wrapped_data_size < 16 {
            // Minimum: 8 bytes data + 8 bytes ICV
            return Err(CryptoError::RsaUnwrapInputTooSmall);
        }

        let max_user_data_size = aes_wrapped_data_size - 8;
        Ok(max_user_data_size)
    }
}

/// Pads a big-endian byte slice to the left with zeros to reach the desired size.
fn pad_left_be(input: &[u8], size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    if input.len() > size {
        out.copy_from_slice(&input[input.len() - size..]);
    } else {
        out[size - input.len()..].copy_from_slice(input);
    }
    out
}

/// Trims leading zeros from a big-endian byte slice.
fn trim_leading_zeros(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && input[i] == 0 {
        i += 1;
    }
    &input[i..]
}

/// Determines CNG blob field sizes for modulus, primes, and exponent.
fn get_cng_blob_sizes(n: &[u8], p: &[u8], q: &[u8], e: &[u8]) -> (usize, usize, usize, usize) {
    let cb_modulus = n.len().max(p.len() * 2).max(q.len() * 2);
    let cb_public_exp = trim_leading_zeros(e).len().max(1);
    let cb_prime1 = cb_modulus / 2;
    let cb_prime2 = cb_modulus / 2;
    (cb_modulus, cb_public_exp, cb_prime1, cb_prime2)
}

/// Validates the PSS salt length according to RFC 8017: saltLen ≤ k - hLen - 2
///
/// # Arguments
/// * `key_bits` - The RSA modulus size in bits (k = key_bits / 8)
/// * `hash_algo` - The hash algorithm used for PSS (determines hLen)
/// * `salt_len` - The requested salt length in bytes
///
/// # Returns
/// * `Ok(())` if the salt length is valid for the given key and hash
/// * `Err(CryptoError::RsaPssSaltlenInvalid)` if the salt length is invalid
fn validate_pss_salt_len_with_modulus(
    key_bits: usize,
    hash_algo: HashAlgo,
    salt_len: usize,
) -> Result<(), CryptoError> {
    // hLen: hash output length in bytes
    let hlen = match hash_algo {
        HashAlgo::Sha1 => 20,
        HashAlgo::Sha256 => 32,
        HashAlgo::Sha384 => 48,
        HashAlgo::Sha512 => 64,
    };
    // k: modulus length in bytes
    let k = key_bits / 8;
    // Per RFC 8017: saltLen ≤ k - hLen - 2
    if k < hlen + 2 {
        // Impossible to have any valid salt length
        return Err(CryptoError::RsaPssSaltlenInvalid);
    }
    let max_salt = k - hlen - 2;
    // salt_len must be nonzero and ≤ max_salt
    if salt_len == 0 || salt_len > max_salt {
        return Err(CryptoError::RsaPssSaltlenInvalid);
    }
    Ok(())
}

///Private helper function to get expected digest size for a given hash algo
///
fn get_digest_size(hash_algo: HashAlgo) -> usize {
    // Hash the input data using the selected hash algorithm
    match hash_algo {
        HashAlgo::Sha1 => 20,
        HashAlgo::Sha256 => 32,
        HashAlgo::Sha384 => 48,
        HashAlgo::Sha512 => 64,
    }
}

// ASN.1 struct definitions for parsing and encoding RSA keys using the `asn1` crate.
// These map directly to the ASN.1 structures defined in PKCS#8 (RFC 5208) for PrivateKeyInfo,
// PKCS#1 (RFC 8017) for RSA private keys, and X.509 SubjectPublicKeyInfo for RSA public keys.
// The `Asn1Read`/`Asn1Write` derives allow Rust code to serialize/deserialize DER-encoded keys
// for robust cross-platform interoperability.

// PKCS#8 PrivateKeyInfo ASN.1 structure:
// PrivateKeyInfo ::= SEQUENCE {
//   version                   Version,
//   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//   privateKey                OCTET STRING,
//   attributes           [0]  IMPLICIT Attributes OPTIONAL
// }
#[derive(Asn1Read, Asn1Write)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifier<'a>,
    private_key: &'a [u8],
    #[implicit(0)]
    attributes: Option<asn1::SetOf<'a, asn1::Tlv<'a>>>,
}

// AlgorithmIdentifier ASN.1 structure:
// AlgorithmIdentifier ::= SEQUENCE {
//   algorithm               OBJECT IDENTIFIER,
//   parameters              ANY DEFINED BY algorithm OPTIONAL
// }
#[derive(Asn1Read, Asn1Write)]
struct AlgorithmIdentifier<'a> {
    algorithm: asn1::ObjectIdentifier,
    parameters: Option<asn1::Tlv<'a>>,
}

// SubjectPublicKeyInfo ASN.1 structure for public keys:
// SubjectPublicKeyInfo ::= SEQUENCE {
//   algorithm            AlgorithmIdentifier,
//   subjectPublicKey     BIT STRING
// }
#[derive(Asn1Read, Asn1Write)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    subject_public_key: asn1::BitString<'a>,
}

// ASN.1 struct definitions for parsing and encoding RSA keys using the `asn1` crate.
// These map directly to the ASN.1 structures defined in PKCS#1 (RFC 8017) for RSA private keys
// and X.509 SubjectPublicKeyInfo for RSA public keys. The `Asn1Read` derives
// allow Rust code to deserialize DER-encoded keys for robust cross-platform interoperability.

// PKCS#1 RSAPrivateKey ASN.1 structure:
// RSAPrivateKey ::= SEQUENCE {
//   version           Version,
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER,  -- e
//   privateExponent   INTEGER,  -- d
//   prime1            INTEGER,  -- p
//   prime2            INTEGER,  -- q
//   exponent1         INTEGER,  -- d mod (p-1)
//   exponent2         INTEGER,  -- d mod (q-1)
//   coefficient       INTEGER,  -- (inverse of q) mod p
//   otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }
#[derive(Asn1Read, Asn1Write)]
struct RsaPrivateKey<'a> {
    version: u8,
    modulus: asn1::BigUint<'a>,
    public_exponent: asn1::BigUint<'a>,
    private_exponent: asn1::BigUint<'a>,
    prime1: asn1::BigUint<'a>,
    prime2: asn1::BigUint<'a>,
    exponent1: asn1::BigUint<'a>,
    exponent2: asn1::BigUint<'a>,
    coefficient: asn1::BigUint<'a>,
    // otherPrimeInfos is rarely used and typically None for 2-prime RSA
    other_prime_infos: Option<asn1::SequenceOf<'a, asn1::Tlv<'a>>>,
}

// PKCS#1 RSAPublicKey ASN.1 structure:
// RSAPublicKey ::= SEQUENCE {
//   modulus           INTEGER,  -- n
//   publicExponent    INTEGER   -- e
// }
#[derive(Asn1Read, Asn1Write)]
struct RsaPublicKey<'a> {
    modulus: asn1::BigUint<'a>,
    public_exponent: asn1::BigUint<'a>,
}

/// Trims leading zeros and prepends a zero byte if the high bit is set (for ASN.1 DER encoding)
fn prepend_zero_if_needed(input: &[u8]) -> Vec<u8> {
    let trimmed = trim_leading_zeros(input);
    if !trimmed.is_empty() && trimmed[0] >= 0x80 {
        let mut v = Vec::with_capacity(trimmed.len() + 1);
        v.push(0);
        v.extend_from_slice(trimmed);
        v
    } else {
        trimmed.to_vec()
    }
}

/// AES Key Wrap 2 (RFC 5649) encryption using CNG AES-ECB
/// This implements the AESKW2 algorithm for wrapping arbitrary length plaintext
#[allow(unsafe_code)]
fn aes_kw2_wrap(
    aes_key_handle: BCRYPT_KEY_HANDLE,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    // RFC 5649: AES Key Wrap 2 with Padding
    // Match DDI implementation: compute AIV according to RFC 5649 section 3
    const PADDED_UPPER_AIV: u64 = 0xA65959A600000000;
    let mli = plaintext.len() as u64;
    let aiv = (PADDED_UPPER_AIV | mli).swap_bytes();

    // Pad plaintext to 8-byte boundary
    let padded_len = plaintext.len().div_ceil(8) * 8;
    let mut padded_plaintext = vec![0u8; padded_len];
    padded_plaintext[..plaintext.len()].copy_from_slice(plaintext);

    // If plaintext is exactly 8 bytes, use simpler algorithm (matches DDI special case)
    if padded_len == 8 {
        // DDI special case: aes_ecb(aiv, plaintext_as_u64) -> (c0, c1)
        let p64 = u64::from_le_bytes([
            padded_plaintext[0],
            padded_plaintext[1],
            padded_plaintext[2],
            padded_plaintext[3],
            padded_plaintext[4],
            padded_plaintext[5],
            padded_plaintext[6],
            padded_plaintext[7],
        ]);

        // Create 16-byte input: [aiv.to_le_bytes(), p64.to_le_bytes()]
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&aiv.to_le_bytes());
        input.extend_from_slice(&p64.to_le_bytes());

        let mut encrypted = [0u8; 16];
        let mut encrypted_len = 0u32;
        // SAFETY: BCryptEncrypt called with valid key handle, input buffer, and output buffer
        let status = unsafe {
            BCryptEncrypt(
                aes_key_handle,
                Some(&input),
                None,
                None,
                Some(&mut encrypted),
                &mut encrypted_len,
                BCRYPT_FLAGS(0),
            )
        };

        if status != STATUS_SUCCESS {
            tracing::error!("AES-KW2 encryption failed: {:?}", status);
            return Err(CryptoError::RsaWrapAesEncryptFailed);
        }

        // Split result back into c0 and c1, then output as [c0.to_le_bytes(), c1.to_le_bytes()]
        let c0 = u64::from_le_bytes([
            encrypted[0],
            encrypted[1],
            encrypted[2],
            encrypted[3],
            encrypted[4],
            encrypted[5],
            encrypted[6],
            encrypted[7],
        ]);
        let c1 = u64::from_le_bytes([
            encrypted[8],
            encrypted[9],
            encrypted[10],
            encrypted[11],
            encrypted[12],
            encrypted[13],
            encrypted[14],
            encrypted[15],
        ]);

        // Output format: [c0.to_le_bytes(), c1.to_le_bytes()]
        if output.len() < 16 {
            return Err(CryptoError::RsaWrapOutputBufferTooSmall);
        }

        output[0..8].copy_from_slice(&c0.to_le_bytes());
        output[8..16].copy_from_slice(&c1.to_le_bytes());

        Ok(16)
    } else {
        // >8-byte case: use base_key_wrap algorithm (matches DDI)
        aes_kw2_base_key_wrap(aes_key_handle, aiv, &padded_plaintext, output)
    }
}

/// AES Key Wrap base algorithm - exactly matches DDI base_key_wrap
#[allow(unsafe_code)]
fn aes_kw2_base_key_wrap(
    aes_key_handle: BCRYPT_KEY_HANDLE,
    aiv: u64,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if !input.len().is_multiple_of(8) {
        return Err(CryptoError::RsaWrapAesEncryptFailed); // Unaligned input buffer length
    }

    let mut output_buf = vec![0u8; input.len() + 8];

    // Initialize (matches DDI exactly)
    let n = input.len() / 8;
    let mut a = aiv;
    output_buf[8..(n + 1) * 8].copy_from_slice(&input[..n * 8]);

    // Intermediate calculation (matches DDI exactly)
    for j in 0..6 {
        for i in 0..n {
            let b = u64::from_le_bytes(
                output_buf[(i + 1) * 8..(i + 2) * 8]
                    .try_into()
                    .map_err(|_| CryptoError::RsaWrapAesEncryptFailed)?,
            );

            // AES ECB encryption using Windows CNG (replaces DDI's self.aes_ecb)
            let (msb, lsb) = aes_ecb_cng(aes_key_handle, true, a, b)?;

            output_buf[(i + 1) * 8..(i + 2) * 8].copy_from_slice(&lsb.to_le_bytes());
            a = msb ^ (((n * j) + (i + 1)) as u64).swap_bytes();
        }
    }

    // Output (matches DDI exactly)
    output_buf[0..8].copy_from_slice(&a.to_le_bytes());

    let output_len = input.len() + 8;
    if output.len() < output_len {
        return Err(CryptoError::RsaWrapOutputBufferTooSmall);
    }

    output[0..output_len].copy_from_slice(&output_buf[0..output_len]);
    Ok(output_len)
}

/// AES ECB operation using Windows CNG - replaces DDI's aes_ecb function
#[allow(unsafe_code)]
fn aes_ecb_cng(
    aes_key_handle: BCRYPT_KEY_HANDLE,
    encrypt: bool,
    a: u64,
    b: u64,
) -> Result<(u64, u64), CryptoError> {
    // Input block will be 16 bytes (matches DDI exactly)
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&a.to_le_bytes());
    block[8..16].copy_from_slice(&b.to_le_bytes());

    let mut output_block = [0u8; 16];
    let mut output_len = 0u32;

    // SAFETY: BCryptEncrypt/BCryptDecrypt called with valid key handle, input and output buffers
    let status = unsafe {
        if encrypt {
            BCryptEncrypt(
                aes_key_handle,
                Some(&block),
                None,
                None,
                Some(&mut output_block),
                &mut output_len,
                BCRYPT_FLAGS(0),
            )
        } else {
            BCryptDecrypt(
                aes_key_handle,
                Some(&block),
                None,
                None,
                Some(&mut output_block),
                &mut output_len,
                BCRYPT_FLAGS(0),
            )
        }
    };

    if status != STATUS_SUCCESS {
        tracing::error!("AES ECB operation failed: {:?}", status);
        return Err(CryptoError::RsaWrapAesEncryptFailed);
    }

    let x = u64::from_le_bytes([
        output_block[0],
        output_block[1],
        output_block[2],
        output_block[3],
        output_block[4],
        output_block[5],
        output_block[6],
        output_block[7],
    ]);
    let y = u64::from_le_bytes([
        output_block[8],
        output_block[9],
        output_block[10],
        output_block[11],
        output_block[12],
        output_block[13],
        output_block[14],
        output_block[15],
    ]);

    Ok((x, y))
}

/// AES Key Wrap 2 (RFC 5649) decryption using CNG AES-ECB
#[allow(unsafe_code)]
fn aes_kw2_unwrap(
    aes_key_handle: BCRYPT_KEY_HANDLE,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(8) {
        return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
    }
    const AIV: u32 = 0xA65959A6;
    let n = (ciphertext.len() / 8) - 1; // Number of 64-bit plaintext blocks

    if n == 1 {
        // Simple case: decrypt two AES blocks
        let mut decrypted = [0u8; 16];
        let mut decrypted_len = 0u32;
        // SAFETY: BCryptDecrypt called with valid key handle, input and output buffers
        let status = unsafe {
            BCryptDecrypt(
                aes_key_handle,
                Some(ciphertext),
                None,
                None,
                Some(&mut decrypted),
                &mut decrypted_len,
                BCRYPT_FLAGS(0),
            )
        };

        if status != STATUS_SUCCESS {
            tracing::error!("AES-KW2 decryption failed: {:?}", status);
            return Err(CryptoError::RsaUnwrapAesDecryptFailed);
        }

        // Verify AIV and extract length
        if decrypted[0..4] != AIV.to_be_bytes() {
            return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
        }

        let plaintext_len =
            u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]) as usize;

        if plaintext_len > 8 || plaintext_len == 0 {
            return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
        }

        if output.len() < plaintext_len {
            return Err(CryptoError::RsaUnwrapOutputBufferTooSmall);
        }

        output[..plaintext_len].copy_from_slice(&decrypted[8..8 + plaintext_len]);
        Ok(plaintext_len)
    } else {
        // Complex case: use RFC 5649 unwrapping algorithm
        aes_kw2_unwrap_complex(aes_key_handle, ciphertext, output)
    }
}

/// AES Key Wrap 2 complex case for unwrapping data > 8 bytes
#[allow(unsafe_code)]
fn aes_kw2_unwrap_complex(
    aes_key_handle: BCRYPT_KEY_HANDLE,
    ciphertext: &[u8],
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    let n = (ciphertext.len() / 8) - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&ciphertext[0..8]);

    let mut r = vec![0u64; n];
    for (i, chunk) in ciphertext[8..].chunks_exact(8).enumerate() {
        r[i] = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }

    // Perform unwrapping algorithm (RFC 5649, Section 4)
    for j in (0..6).rev() {
        for (i, r_i) in r.iter_mut().enumerate().rev() {
            // B = AES^-1(K, (A ^ t) | R[i])
            let t = (n * j + i + 1) as u64;
            let a_val = u64::from_be_bytes(a);
            let a_xor_t = a_val ^ t;

            let mut input = [0u8; 16];
            input[0..8].copy_from_slice(&a_xor_t.to_be_bytes());
            input[8..16].copy_from_slice(&r_i.to_be_bytes());

            let mut decrypted = [0u8; 16];
            let mut decrypted_len = 0u32;
            // SAFETY: BCryptDecrypt called with valid key handle, input and output buffers
            let status = unsafe {
                BCryptDecrypt(
                    aes_key_handle,
                    Some(&input),
                    None,
                    None,
                    Some(&mut decrypted),
                    &mut decrypted_len,
                    BCRYPT_FLAGS(0),
                )
            };

            if status != STATUS_SUCCESS {
                tracing::error!("AES decryption failed in KW2 unwrap: {:?}", status);
                return Err(CryptoError::RsaUnwrapAesDecryptFailed);
            }

            // A = MSB(64, B)
            a.copy_from_slice(&decrypted[0..8]);

            // R[i] = LSB(64, B)
            *r_i = u64::from_be_bytes([
                decrypted[8],
                decrypted[9],
                decrypted[10],
                decrypted[11],
                decrypted[12],
                decrypted[13],
                decrypted[14],
                decrypted[15],
            ]);
        }
    }

    // Verify AIV format and extract plaintext length
    if a[0..4] != 0xA65959A6u32.to_be_bytes() {
        return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
    }

    let plaintext_len = u32::from_be_bytes([a[4], a[5], a[6], a[7]]) as usize;
    let padded_len = n * 8;

    if plaintext_len > padded_len || plaintext_len == 0 {
        return Err(CryptoError::RsaUnwrapInvalidBlobFormat);
    }

    if output.len() < plaintext_len {
        return Err(CryptoError::RsaUnwrapOutputBufferTooSmall);
    }

    // Extract plaintext from R blocks
    let mut plaintext_pos = 0;
    for &r_i in &r {
        let r_bytes = r_i.to_be_bytes();
        let copy_len = std::cmp::min(8, plaintext_len - plaintext_pos);
        if copy_len == 0 {
            break;
        }
        output[plaintext_pos..plaintext_pos + copy_len].copy_from_slice(&r_bytes[..copy_len]);
        plaintext_pos += copy_len;
    }

    Ok(plaintext_len)
}
