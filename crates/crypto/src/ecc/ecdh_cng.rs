// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDH (Elliptic Curve Diffie-Hellman) key agreement using Windows CNG.
//!
//! This module provides ECDH key agreement operations using the Windows Cryptography
//! Next Generation (CNG) API. ECDH is a key agreement protocol that allows two parties,
//! each having an elliptic curve public-private key pair, to establish a shared secret
//! over an insecure channel.
//!
//! The implementation supports the NIST P-256, P-384, and P-521 curves and derives
//! raw shared secrets that can be used for subsequent key derivation functions.

use windows::Win32::Security::Cryptography::*;

use super::*;

/// ECDH key agreement operation using Windows CNG.
///
/// This structure holds a reference to a peer's public key and performs
/// the ECDH key agreement operation when combined with a private key.
/// The lifetime parameter ensures the peer key remains valid for the
/// duration of the ECDH operation.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the peer's public key reference
pub struct CngEcdhAlgo<'a> {
    /// Reference to the peer's public key used for key agreement
    peer_key: &'a EccPublicKey,
}

impl<'a> CngEcdhAlgo<'a> {
    /// Creates a new ECDH operation with the specified peer public key.
    ///
    /// # Parameters
    ///
    /// * `peer_key` - Reference to the peer's ECC public key
    ///
    /// # Returns
    ///
    /// A new `CngEcdh` instance ready to perform key agreement.
    pub fn new(peer_key: &'a EccPublicKey) -> Self {
        Self { peer_key }
    }

    /// Derives the raw shared secret from a CNG secret agreement handle.
    ///
    /// This method queries the required buffer size, then extracts the raw shared
    /// secret using the `BCRYPT_KDF_RAW_SECRET` key derivation function.
    ///
    /// # Parameters
    ///
    /// * `key` - The CNG secret agreement handle
    ///
    /// # Returns
    ///
    /// A vector containing the raw shared secret bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EcdhError` if the key derivation fails.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn derive_vec(&self, key: &CngSecretKey) -> Result<Vec<u8>, CryptoError> {
        let mut key_len: u32 = 0;
        //SAFETY: Calling  Unsafe Windows CNG API
        let status = unsafe {
            BCryptDeriveKey(
                key.handle(),
                BCRYPT_KDF_RAW_SECRET,
                None,
                None,
                &mut key_len,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::EcdhDeriveError)?;

        let mut derived_key = vec![0u8; key_len as usize];
        //SAFETY: Calling  Unsafe Windows CNG API
        let status = unsafe {
            BCryptDeriveKey(
                key.handle(),
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut derived_key),
                &mut key_len,
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::EcdhDeriveError)?;

        Ok(derived_key)
    }
}

impl<'a> DeriveOp for CngEcdhAlgo<'a> {
    /// The private key type used for key agreement (ECC private key).
    type Key = EccPrivateKey;

    /// The derived key type produced by the agreement (generic secret key).
    type DerivedKey = GenericSecretKey;

    /// Performs ECDH key agreement to derive a shared secret.
    ///
    /// This method combines the provided private key with the peer's public key
    /// (stored in this instance) to compute a shared secret. The operation is
    /// performed using Windows CNG's `BCryptSecretAgreement` function.
    ///
    /// # Parameters
    ///
    /// * `key` - The local private key to use for the agreement
    /// * `derived_len` - The desired length of the derived key (unused for ECDH as length is curve-dependent)
    ///
    /// # Returns
    ///
    /// A `GenericSecretKey` containing the derived shared secret.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EcdhError` if:
    /// - The secret agreement computation fails
    /// - The key derivation fails
    /// - The keys use incompatible curves
    ///
    /// # Security Considerations
    ///
    /// - The shared secret should not be used directly as a key
    /// - Apply a proper key derivation function (KDF) to the shared secret
    /// - Ensure both parties are authenticated to prevent man-in-the-middle attacks
    /// - The shared secret should be handled securely and zeroized after use
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn derive(
        &self,
        key: &Self::Key,
        _derived_len: usize,
    ) -> Result<Self::DerivedKey, CryptoError> {
        if _derived_len != key.size() {
            return Err(CryptoError::EcdhInvalidDerivedKeyLength);
        }

        let mut secret_key = CngSecretKey::new();
        //SAFETY: Calling  Unsafe Windows CNG API
        let status = unsafe {
            BCryptSecretAgreement(
                key.ecdh_handle(),
                self.peer_key.ecdh_handle(),
                secret_key.handle_mut(),
                0,
            )
        };
        status.ok().map_err(|_| CryptoError::EcdhSetPropertyError)?;

        let mut secret = self.derive_vec(&secret_key)?;

        // CNG returns raw secret bytes in little endian format; convert to big endian
        secret.reverse();

        GenericSecretKey::from_bytes(&secret)
    }
}

/// RAII wrapper for Windows CNG secret agreement handles.
///
/// This structure manages a `BCRYPT_SECRET_HANDLE` representing an ECDH
/// secret agreement. The handle is automatically cleaned up when the
/// structure is dropped, ensuring proper resource management.
struct CngSecretKey {
    /// The underlying Windows CNG secret agreement handle
    handle: BCRYPT_SECRET_HANDLE,
}

impl Drop for CngSecretKey {
    /// Automatically cleans up the CNG secret handle when dropped.
    ///
    /// This ensures that Windows CNG resources are properly released.
    /// If the handle is invalid (default), no cleanup is performed.
    ///
    /// # Safety
    ///
    /// This function contains unsafe code as it calls Windows CNG APIs directly.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        //SAFETY: Calling  Unsafe Windows CNG API to destroy key
        unsafe {
            if self.handle != BCRYPT_SECRET_HANDLE::default() {
                let _ = BCryptDestroySecret(self.handle);
            }
        }
    }
}

impl CngSecretKey {
    /// Creates a new uninitialized secret key handle.
    ///
    /// The handle is set to the default (invalid) state and will be
    /// initialized by Windows CNG during the secret agreement operation.
    ///
    /// # Returns
    ///
    /// A new `CngSecretKey` with an uninitialized handle.
    fn new() -> Self {
        Self {
            handle: BCRYPT_SECRET_HANDLE::default(),
        }
    }

    /// Returns the underlying CNG secret handle.
    ///
    /// # Returns
    ///
    /// The `BCRYPT_SECRET_HANDLE` for this secret agreement.
    fn handle(&self) -> BCRYPT_SECRET_HANDLE {
        self.handle
    }

    /// Returns a mutable reference to the underlying CNG secret handle.
    ///
    /// This is used to allow Windows CNG APIs to initialize the handle.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `BCRYPT_SECRET_HANDLE`.
    fn handle_mut(&mut self) -> &mut BCRYPT_SECRET_HANDLE {
        &mut self.handle
    }
}
