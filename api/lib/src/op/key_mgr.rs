// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key generation operations.
//!
//! This module provides a unified interface for generating cryptographic keys
//! using various algorithm implementations. The [`KeyGenerator`] wrapper
//! consolidates key generation operations behind a consistent API.

use super::*;

/// Key management operation wrapper.
///
/// This structure provides a unified interface for key management operations,
/// wrapping the underlying algorithm-specific implementations to provide a consistent API.
pub struct HsmKeyManager;

impl HsmKeyManager {
    /// Generates a new cryptographic key.
    ///
    /// Creates a new key with the specified properties using the provided algorithm
    /// implementation. The key is generated within the context of the given session if applicable.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to generate the key
    /// * `algo` - The key generation algorithm implementation
    /// * `props` - Key properties specifying the desired key attributes
    ///
    /// # Returns
    ///
    /// Returns the newly generated key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key properties are invalid or unsupported
    /// - The session is invalid
    /// - The underlying cryptographic operation fails
    /// - Insufficient resources are available
    pub fn generate_key<Algo: HsmKeyGenOp>(
        session: &Algo::Session,
        algo: &mut Algo,
        props: HsmKeyProps,
    ) -> Result<Algo::Key, Algo::Error> {
        algo.generate_key(session, props)
    }

    /// Generates a new asymmetric key pair.
    ///
    /// Creates a new public/private key pair with the specified properties using
    /// the provided algorithm implementation. The key pair is generated within the
    /// context of the given session if applicable.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to generate the key pair
    /// * `algo` - The key pair generation algorithm implementation
    /// * `priv_key_props` - Key properties for the private key
    /// * `pub_key_props` - Key properties for the public key
    ///
    /// # Returns
    ///
    /// Returns the newly generated private key on success.
    /// Public key can be obtained from the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key properties are invalid or unsupported
    /// - The session is invalid
    /// - The underlying cryptographic operation fails
    /// - The public and private key properties are incompatible
    /// - Insufficient resources are available
    pub fn generate_key_pair<Algo: HsmKeyPairGenOp>(
        session: &Algo::Session,
        algo: &mut Algo,
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Algo::PrivateKey,
            <Algo::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Algo::Error,
    > {
        algo.generate_key_pair(session, priv_key_props, pub_key_props)
    }

    /// Unwraps (decrypts) a wrapped key using the specified unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key unwrapping algorithm implementation
    /// * `unwrapping_key` - The key used to unwrap (decrypt) the wrapped key
    /// * `wrapped_key` - The wrapped (encrypted) key data
    /// * `key_props` - Properties for the unwrapped key
    ///
    /// # Returns
    ///
    /// Returns the unwrapped key on success.
    pub fn unwrap_key<Algo: HsmKeyUnwrapOp>(
        algo: &mut Algo,
        unwrapping_key: &Algo::UnwrappingKey,
        wrapped_key: &[u8],
        key_props: HsmKeyProps,
    ) -> Result<Algo::Key, Algo::Error> {
        algo.unwrap_key(unwrapping_key, wrapped_key, key_props)
    }

    /// Unwraps (decrypts) a wrapped asymmetric key pair using the specified unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key pair unwrapping algorithm implementation
    /// * `unwrapping_key` - The key used to unwrap (decrypt) the
    /// * `wrapped_key_pair` - The wrapped (encrypted) key pair data
    /// * `priv_key_props` - Properties for the unwrapped private key
    /// * `pub_key_props` - Properties for the unwrapped public key
    ///
    /// # Returns
    ///
    /// Returns the unwrapped private and public keys on success.
    pub fn unwrap_key_pair<Algo: HsmKeyPairUnwrapOp>(
        algo: &mut Algo,
        unwrapping_key: &Algo::UnwrappingKey,
        wrapped_key_pair: &[u8],
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Algo::PrivateKey,
            <Algo::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Algo::Error,
    > {
        algo.unwrap_key_pair(
            unwrapping_key,
            wrapped_key_pair,
            priv_key_props,
            pub_key_props,
        )
    }

    /// Unmasks a masked key.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unmasking operation
    /// * `algo` - The key unmasking algorithm implementation
    /// * `masked_key` - The masked key data

    ///
    /// # Returns
    ///
    /// Returns the unmasked key on success.
    pub fn unmask_key<Algo: HsmKeyUnmaskOp>(
        session: &Algo::Session,
        algo: &mut Algo,
        masked_key: &[u8],
    ) -> Result<Algo::Key, Algo::Error> {
        algo.unmask_key(session, masked_key)
    }

    /// Unmasks a masked asymmetric key pair.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to perform the unmasking operation
    /// * `algo` - The key pair unmasking algorithm implementation
    /// * `masked_key_pair` - The masked key pair data
    /// * `priv_key_props` - Properties for the unmasked private key
    /// * `pub_key_props` - Properties for the unmasked public key
    ///
    /// # Returns
    ///
    /// Returns the unmasked private and public keys on success.
    pub fn unmask_key_pair<Algo: HsmKeyPairUnmaskOp>(
        session: &Algo::Session,
        algo: &mut Algo,
        masked_key_pair: &[u8],
    ) -> Result<
        (
            Algo::PrivateKey,
            <Algo::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Algo::Error,
    > {
        algo.unmask_key_pair(session, masked_key_pair)
    }

    /// Derives a new cryptographic key from an existing base key.
    ///
    /// Derives a key with the specified properties using the provided algorithm
    /// implementation. The operation is performed within the context of the given
    /// session if applicable.
    ///
    /// # Arguments
    ///
    /// * `session` - The session context in which to derive the key
    /// * `algo` - The key derivation algorithm implementation
    /// * `base_key` - The base key material (or handle) from which to derive a new key
    /// * `props` - Key properties specifying the desired derived key attributes
    ///
    /// # Returns
    ///
    /// Returns the newly derived key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key properties are invalid or unsupported
    /// - The base key is invalid or incompatible with the derivation algorithm
    /// - The session is invalid
    /// - The underlying cryptographic operation fails
    /// - Insufficient resources are available
    pub fn derive_key<Algo: HsmKeyDeriveOp>(
        session: &Algo::Session,
        algo: &mut Algo,
        base_key: &Algo::BaseKey,
        props: HsmKeyProps,
    ) -> Result<Algo::DerivedKey, Algo::Error> {
        algo.derive_key(session, base_key, props)
    }

    /// Deletes a key from the HSM.
    ///
    /// Removes the specified key from the HSM partition, making it no longer usable.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete (consumes the key)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if the deletion operation fails
    pub fn delete_key<Key: HsmKeyDeleteOp>(key: Key) -> Result<(), Key::Error> {
        key.delete_key()
    }
}
