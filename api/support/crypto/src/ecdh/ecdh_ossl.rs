// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use openssl::pkey::PKey;

use super::*;
use crate::eckey::*;

impl EcdhKeyDeriveOp for EcPrivateKey {
    /// Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH).
    ///
    /// # Arguments
    ///
    /// * `public_key` - Reference to the peer's public elliptic curve key (`EcPublicKey`).
    /// * `derived_key` - Mutable byte slice to store the derived shared secret.
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice referencing the derived shared secret on success.
    /// * `Err(CryptoError)` - If key derivation fails.
    fn ecdh_key_derive<'a>(
        &self,
        public_key: &EcPublicKey,
        derived_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Lock and clone the OpenSSL key objects, then drop the locks before FFI.
        //
        // Rationale: Holding Rust mutex locks across FFI boundaries (such as into OpenSSL)
        // can cause deadlocks or hangs if the FFI code internally acquires locks, calls back
        // into Rust, or otherwise blocks. By cloning the key objects while holding the lock,
        // we ensure we have a safe, independent reference to the OpenSSL key. We then drop
        // the Rust locks before calling any OpenSSL functions, which avoids potential deadlocks
        // and allows the key handles to be reused safely elsewhere in the program.
        // This is a best practice for safe FFI interaction with Rust and C libraries.
        let priv_handle = self.private_key_handle.lock().map_err(|e| {
            tracing::error!("Failed to lock private key handle: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        let pub_handle = public_key.public_key_handle.lock().map_err(|e| {
            tracing::error!("Failed to lock public key handle: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        let priv_key = priv_handle.ossl_private_key_handle.clone(); // Clone private key
        let pub_key = pub_handle.ossl_public_key_handle.clone(); // Clone public key
        drop(priv_handle); // Release private key lock
        drop(pub_handle); // Release public key lock

        // Create a PKey from the private EC key
        let pkey_priv = PKey::from_ec_key(priv_key).map_err(|e| {
            tracing::error!("Failed to create PKey from private key: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        // Create a PKey from the public EC key
        let pkey_pub = PKey::from_ec_key(pub_key).map_err(|e| {
            tracing::error!("Failed to create PKey from public key: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        // Create a Deriver for ECDH using the private key
        let mut deriver = openssl::derive::Deriver::new(&pkey_priv).map_err(|e| {
            tracing::error!("Failed to create Deriver: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        // Set the peer's public key for the ECDH operation
        deriver.set_peer(&pkey_pub).map_err(|e| {
            tracing::error!("Failed to set peer public key: {:?}", e);
            CryptoError::EcdhKeyAgreementFailed
        })?;
        // Get the required length for the derived key
        let required_len = self.ecdh_get_derived_key_size()?;
        // Check if the provided buffer is large enough
        if derived_key.len() < required_len {
            tracing::error!(
                "Output buffer too small: required {}, got {}",
                required_len,
                derived_key.len()
            );
            return Err(CryptoError::EcdhBufferTooSmall);
        }
        // Perform the ECDH key derivation
        let len = deriver.derive(derived_key).map_err(|e| {
            tracing::error!("ECDH key derivation failed: {:?}", e);
            CryptoError::EcdhKeyDerivationFailed
        })?;
        // Return the derived key slice
        Ok(&derived_key[..len])
    }

    /// Returns the size in bytes of the derived key for the current ECDH context.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the derived key in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn ecdh_get_derived_key_size(&self) -> Result<usize, CryptoError> {
        let priv_handle = self.private_key_handle.lock().map_err(|e| {
            tracing::error!("Failed to lock private key handle: {:?}", e);
            CryptoError::EcdhInternalError
        })?;
        let priv_key = &priv_handle.ossl_private_key_handle;
        let group = priv_key.group();
        let degree = group.degree();
        if degree == 0 {
            tracing::error!("ecdh_get_derived_key_size: group degree is zero");
            return Err(CryptoError::EcdhGetKeySizeFailed);
        }
        // For P-521, OpenSSL returns 66 bytes for the shared secret
        Ok((degree as usize).div_ceil(8))
    }
}
