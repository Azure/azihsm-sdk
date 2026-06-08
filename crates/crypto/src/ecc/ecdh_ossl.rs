// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based ECDH (Elliptic Curve Diffie-Hellman) key derivation implementation.
//!
//! This module provides ECDH key agreement operations using OpenSSL's cryptographic
//! primitives. ECDH is a key agreement protocol that allows two parties to establish
//! a shared secret over an insecure channel using elliptic curve cryptography.
//!
//! # Protocol
//!
//! ECDH works by:
//! 1. Each party has an ECC private/public key pair
//! 2. Each party shares their public key with the other
//! 3. Each party combines their own private key with the peer's public key
//! 4. Both parties arrive at the same shared secret
//!
//! # Security
//!
//! - The shared secret should be used for key derivation (e.g., HKDF) rather than directly
//! - Ephemeral keys (ECDHE) provide forward secrecy
//! - Public keys should be authenticated to prevent man-in-the-middle attacks

use super::*;

/// OpenSSL-backed ECDH key derivation operation.
///
/// This structure performs Elliptic Curve Diffie-Hellman key agreement, producing
/// a shared secret from a local private key and a peer's public key. The shared
/// secret can then be used as key material for symmetric encryption or further
/// key derivation.
///
/// # Lifetime
///
/// The lifetime parameter `'a` ensures that the peer's public key remains valid
/// for the duration of the ECDH operation.
///
/// # Security Considerations
///
/// - The derived shared secret should not be used directly as an encryption key
/// - Apply a key derivation function (KDF) like HKDF to the shared secret
/// - Validate peer public keys to prevent invalid curve attacks
/// - Use ephemeral keys when forward secrecy is required
/// - The same shared secret is derived by both parties
pub struct OsslEcdhAlgo<'a> {
    /// The peer's public key used for key agreement
    peer_key: &'a EccPublicKey,
}

impl<'a> OsslEcdhAlgo<'a> {
    /// Creates a new ECDH operation with a peer's public key.
    ///
    /// This constructor initializes an ECDH key agreement operation that will
    /// use the provided peer public key to derive a shared secret when combined
    /// with a local private key.
    ///
    /// # Arguments
    ///
    /// * `peer_key` - Reference to the peer's ECC public key
    ///
    /// # Returns
    ///
    /// A new `OsslEcdh` instance ready to perform key derivation.
    ///
    /// # Security
    ///
    /// - Ensure the peer public key is authentic (e.g., via certificate validation)
    /// - The peer key should be on the same curve as the local private key
    /// - Validate that the peer key is a valid curve point
    pub fn new(peer_key: &'a EccPublicKey) -> Self {
        Self { peer_key }
    }
}

impl<'a> DeriveOp for OsslEcdhAlgo<'a> {
    type Key = EccPrivateKey;
    type DerivedKey = GenericSecretKey;

    /// Performs ECDH key agreement to derive a shared secret.
    ///
    /// This method combines the local private key with the peer's public key
    /// to compute a shared secret using the ECDH algorithm. Both parties using
    /// matching key pairs will derive the same shared secret.
    ///
    /// # Arguments
    ///
    /// * `key` - The local ECC private key
    /// * `derived_len` - The desired length of the derived key in bytes (currently unused;
    ///   ECDH produces a fixed-length shared secret based on the curve)
    ///
    /// # Returns
    ///
    /// A `GenericSecretKey` containing the derived shared secret.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key derivation operation fails
    /// - The peer key is invalid or on a different curve
    /// - The private key is invalid
    /// - OpenSSL encounters an internal error
    ///
    /// # Security
    ///
    /// The derived shared secret should be processed through a key derivation
    /// function (KDF) before use:
    /// - Use HKDF or similar to derive actual encryption keys
    /// - Include context information to prevent key reuse
    /// - Consider adding a salt for additional security
    /// - Never use the raw shared secret directly for encryption
    #[allow(unsafe_code)]
    fn derive(&self, key: &Self::Key, derived_len: usize) -> Result<Self::DerivedKey, CryptoError> {
        use std::os::raw::c_char;
        use std::ptr;

        use foreign_types::ForeignTypeRef;
        use openssl_sys as ffi;

        // The openssl crate's `Deriver` uses the legacy `EVP_PKEY_CTX_new`, which
        // fetches the ECDH keyexch from the *process default* libctx regardless
        // of the key's libctx — on OpenSSL 3.5 that resolves to the azihsm
        // provider and re-enters it during the HSM session open. Build the derive
        // ctx explicitly in the crate-private libctx (default-provider only) so
        // the keyexch fetch never lands on azihsm. `EVP_PKEY_CTX_new_from_pkey`
        // exists in OpenSSL 3.0+ libcrypto but is not bound by openssl-sys 0.9.x,
        // so it is declared here. See [`crate::libctx`].
        unsafe extern "C" {
            fn EVP_PKEY_CTX_new_from_pkey(
                libctx: *mut ffi::OSSL_LIB_CTX,
                pkey: *mut ffi::EVP_PKEY,
                propquery: *const c_char,
            ) -> *mut ffi::EVP_PKEY_CTX;
        }

        // SAFETY: pointers are NULL-checked before use; `ctx` is freed on every
        // path; the output buffer is sized from the first `EVP_PKEY_derive`.
        let secret = unsafe {
            let ctx = EVP_PKEY_CTX_new_from_pkey(
                crate::libctx::crypto_libctx_ptr(),
                key.pkey().as_ptr(),
                ptr::null(),
            );
            if ctx.is_null() {
                return Err(CryptoError::EcdhError);
            }
            let result = (|| {
                if ffi::EVP_PKEY_derive_init(ctx) != 1 {
                    return Err(CryptoError::EcdhError);
                }
                if ffi::EVP_PKEY_derive_set_peer(ctx, self.peer_key.pkey().as_ptr()) != 1 {
                    return Err(CryptoError::EcdhSetPropertyError);
                }
                let mut len: usize = 0;
                if ffi::EVP_PKEY_derive(ctx, ptr::null_mut(), &mut len) != 1 {
                    return Err(CryptoError::EcdhError);
                }
                if derived_len != len {
                    return Err(CryptoError::EcdhInvalidDerivedKeyLength);
                }
                let mut secret = vec![0u8; len];
                if ffi::EVP_PKEY_derive(ctx, secret.as_mut_ptr(), &mut len) != 1 {
                    return Err(CryptoError::EcdhDeriveError);
                }
                secret.truncate(len);
                Ok(secret)
            })();
            ffi::EVP_PKEY_CTX_free(ctx);
            result?
        };

        GenericSecretKey::from_bytes(&secret)
    }
}
