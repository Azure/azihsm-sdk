// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
//! A wrapper around a OpenSSL algorithm provider handle.

use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;

use super::*;
use crate::eckey::*;

impl EccCryptSignOp for EcPrivateKey {
    /// Signs the provided digest using the ECC private key.
    ///
    /// # Parameters
    /// - `digest`: The message digest to sign, as a byte slice (`&[u8]`).
    /// - `signature`: Mutable byte slice (`&mut [u8]`) to write the DER-encoded signature into.
    ///
    /// # Returns
    /// - `Ok(&[u8])`: The DER-encoded signature as a slice of the provided buffer.
    /// - `Err(CryptoError)`: An error if signing fails.
    fn ecc_crypt_sign<'a>(
        &self,
        digest: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Lock the private key handle for thread safety
        let key_guard = match self.private_key_handle.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("ecc_crypt_sign: mutex lock poisoned : {}", poisoned);
                return Err(CryptoError::EccSignError);
            }
        };

        // Get the EC group and its degree (curve size in bits)
        let group = key_guard.ossl_private_key_handle.group();
        let degree = group.degree();
        // Map the degree to a known curve ID
        let curve_id = match EcCurveId::from_bits(degree) {
            Some(val) => val,
            None => {
                tracing::error!(
                    "ecc_crypt_sign: unsupported bits for curve (degree: {})",
                    degree,
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        // Check if the digest size is valid for the curve
        if !curve_id.is_digest_valid_for_curve(digest) {
            tracing::error!(
                "ecc_crypt_sign: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                digest.len()
            );
            return Err(CryptoError::EccUnsupportedDigestSize);
        }

        // Create a PKey from the EC private key (OpenSSL abstraction)
        let pkey = PKey::from_ec_key(key_guard.ossl_private_key_handle.clone()).map_err(|e| {
            tracing::error!("ecc_crypt_sign: failed to create PKey from EcKey: {:?}", e);
            CryptoError::EccError
        })?;
        // Create a signing context
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!("ecc_crypt_sign: failed to create PkeyCtx: {:?}", e);
            CryptoError::EccError
        })?;
        // Initialize the signing operation
        ctx.sign_init().map_err(|e| {
            tracing::error!("ecc_crypt_sign: failed to init sign: {:?}", e);
            CryptoError::EccError
        })?;
        // Perform the signature operation, writing into the provided buffer
        let sig_len = ctx.sign(digest, Some(signature)).map_err(|e| {
            tracing::error!("ecc_crypt_sign: failed to sign digest: {:?}", e);
            CryptoError::EccError
        })?;
        // Return the signature slice
        Ok(&signature[..sig_len])
    }

    /// Returns the maximum size in bytes of a DER-encoded ECC signature for this key's curve and hash algorithm.
    ///
    /// # Parameters
    /// - `hash_algo`: The hash algorithm to check for support with the curve (`HashAlgo`).
    ///
    /// # Returns
    /// - `Ok(usize)`: The maximum DER signature size if supported.
    /// - `Err(CryptoError::EccUnsupportedHashAlgorithm)`: If the hash is not supported for the curve.
    /// - `Err(CryptoError::EcCurveMismatch)`: For unknown/unsupported curve.
    fn ecc_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError> {
        // Lock the private key handle for thread safety
        let key_guard = self.private_key_handle.lock().unwrap();
        // Get the EC group and its degree (curve size in bits)
        let group = key_guard.ossl_private_key_handle.group();
        let degree = group.degree();
        // Map the degree to a known curve ID
        let curve_id = match EcCurveId::from_bits(degree) {
            Some(val) => val,
            None => {
                tracing::error!(
                    "ecc_crypt_get_signature_size: unsupported bits for curve (degree: {})",
                    degree,
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        // Check if the hash algorithm is supported for the curve
        if !curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!(
                "ecc_crypt_get_signature_size: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        // # How the maximum DER size is determined:
        //
        // The DER-encoded ECDSA signature is a SEQUENCE of two INTEGERs (r, s), each representing a curve value.
        // For a curve of N bits, the value size is ceil(N/8) bytes. Each INTEGER may require a leading zero byte if the high bit is set.
        // The maximum size for each INTEGER is:
        //   1 (tag) + 1 (length) + (value size + 1 for possible leading zero)
        // The SEQUENCE wrapper adds 1 (tag) + 1 or 2 (length) bytes.
        //
        // Formula for maximum DER signature size:
        //   max_der = 1 + seq_len_field + 2 * (1 + 1 + value_size + 1)
        // Where:
        //   - value_size = ceil(curve_bits / 8)
        //   - seq_len_field = 2 if content_len >= 128, else 1
        //
        // For P-256 (256 bits): value_size = 32, max_der = 72
        // For P-384 (384 bits): value_size = 48, max_der = 107
        // For P-521 (521 bits): value_size = 66, max_der = 141
        //
        // These values are empirically verified to be the maximum possible DER-encoded signature sizes for each curve.
        // Return the empirically determined max DER signature size for the curve
        // P-256: 72, P-384: 107, P-521: 141 (max observed for each)
        let max_der_sig_size = match degree {
            256 => 72,                                     // P-256
            384 => 107,                                    // P-384
            521 => 141,                                    // P-521
            _ => return Err(CryptoError::EcCurveMismatch), // Only error for unknown/unsupported curve
        };
        Ok(max_der_sig_size)
    }
}

impl EccCryptVerifyOp for EcPublicKey {
    /// Verifies the provided signature against the digest using the ECC public key.
    ///
    /// # Parameters
    /// - `digest`: The message digest that was signed, as a byte slice (`&[u8]`).
    /// - `signature`: The DER-encoded signature to verify, as a byte slice (`&[u8]`).
    ///
    /// # Returns
    /// - `Ok(())`: If the signature is valid.
    /// - `Err(CryptoError)`: If the signature is invalid or verification fails.
    fn ecc_crypt_verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        // Lock the public key handle for thread safety
        let key_guard = self.public_key_handle.lock().unwrap();
        // Get the EC group and its degree (curve size in bits)
        let group = key_guard.ossl_public_key_handle.group();
        let degree = group.degree();
        // Map the degree to a known curve ID
        let curve_id = match EcCurveId::from_bits(degree) {
            Some(val) => val,
            None => {
                tracing::error!(
                    "ecc_crypt_sign: unsupported bits for curve (degree: {})",
                    degree,
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        // Check if provided digest is valid size for the curve
        if !curve_id.is_digest_valid_for_curve(digest) {
            tracing::error!(
                "ecc_crypt_verify: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                digest.len()
            );
            return Err(CryptoError::EccUnsupportedDigestSize);
        }
        // Create a PKey from the EC public key (OpenSSL abstraction)
        let pkey = PKey::from_ec_key(key_guard.ossl_public_key_handle.clone()).map_err(|e| {
            tracing::error!(
                "ecc_crypt_verify: failed to create PKey from EcKey: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        // Get the group again for signature length validation
        let group = key_guard.ossl_public_key_handle.group();
        // Check if the signature length is valid for the curve
        if !EcCurveId::is_valid_ec_signature_length(group, signature.len()) {
            tracing::error!(
                "ecc_crypt_verify: signature length {} out of expected range for curve",
                signature.len()
            );
            return Err(CryptoError::EccError);
        }
        // Create a verification context
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!("ecc_crypt_verify: failed to create PkeyCtx: {:?}", e);
            CryptoError::EccError
        })?;
        // Initialize the verification operation
        ctx.verify_init().map_err(|e| {
            tracing::error!("ecc_crypt_verify: failed to init verify: {:?}", e);
            CryptoError::EccError
        })?;
        // Perform the verification operation
        match ctx.verify(digest, signature) {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::error!("ecc_crypt_verify: signature verification failed");
                Err(CryptoError::EccVerifyError)
            }
            Err(e) => {
                tracing::error!("ecc_crypt_verify: failed to finalize verification: {:?}", e);
                Err(CryptoError::EccError)
            }
        }
    }
}
