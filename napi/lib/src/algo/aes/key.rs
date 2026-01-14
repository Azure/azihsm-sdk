// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES key structures and generation.
//!
//! This module provides AES key types and generation algorithms for use with
//! HSM sessions. It implements key generation operations that create and manage
//! AES keys within the hardware security module.

use super::*;

define_hsm_key!(pub HsmAesKey);

impl HsmSecretKey for HsmAesKey {}

impl HsmEncryptionKey for HsmAesKey {}

impl HsmDecryptionKey for HsmAesKey {}

/// HSM-based AES key generation algorithm.
///
/// Implements the key generation operation trait for creating AES keys within
/// an HSM session. This implementation delegates key generation to the underlying
/// hardware security module.
#[derive(Default)]
pub struct HsmAesKeyGenAlgo {}

impl HsmKeyGenOp for HsmAesKeyGenAlgo {
    type Key = HsmAesKey;
    type Session = HsmSession;
    type Error = HsmError;

    /// Generates a new AES key.
    ///
    /// Creates a new AES key within the HSM session using the specified key
    /// properties. The key is generated within the hardware security module
    /// and returned with both a handle for operations and masked key material.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session in which to generate the key
    /// * `props` - Key properties defining attributes like size and usage permissions
    ///
    /// # Returns
    ///
    /// Returns an `AesKey` instance on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session is invalid or closed
    /// - Key properties are invalid or unsupported
    /// - Key generation fails in the HSM
    /// - Resource limits are exceeded
    fn generate_key(
        &mut self,
        session: &Self::Session,
        props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::aes_generate_key(session, props)?;
        Ok(HsmAesKey::new(session.clone(), props, handle))
    }
}

/// AES Key Unwrapping Algorithm using RSA keys.
///
/// This struct implements the key unwrapping operation for AES keys that have been wrapped with
/// RSA AES Key Wrap algorithm.
pub struct HsmAesKeyRsaAesKeyUnwrapAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmAesKeyRsaAesKeyUnwrapAlgo {
    /// Creates a new AES key unwrapping algorithm with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use during the unwrapping process.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmAesKeyRsaAesKeyUnwrapAlgo`.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmKeyUnwrapOp for HsmAesKeyRsaAesKeyUnwrapAlgo {
    type UnwrappingKey = HsmRsaPrivateKey;
    type Key = HsmAesKey;
    type Error = HsmError;

    /// Unwraps an AES key using the provided RSA unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unwrapping operation.
    /// * `unwrapping_key` - The RSA private key used to unwrap the AES
    /// * `wrapped_key` - The wrapped AES key data.
    /// * `key_props` - Properties for the unwrapped AES key.
    ///
    /// # Returns
    ///
    /// Returns the unwrapped AES key on success.
    fn unwrap_key(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        key_props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) =
            ddi::rsa_aes_unwrap_key(unwrapping_key, wrapped_key, self.hash_algo, key_props)?;
        let key = HsmAesKey::new(unwrapping_key.session().clone(), props, handle);
        Ok(key)
    }
}
