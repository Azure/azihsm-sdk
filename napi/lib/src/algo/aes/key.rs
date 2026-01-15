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

impl HsmKeyPropsValidator for HsmAesKey {
    /// Validates that `props` describe a supported HSM-backed AES secret key.
    ///
    /// This is used as a defensive check at API boundaries (key generation,
    /// unwrapping, and algorithm operations) so we fail fast with
    /// [`HsmError::InvalidKeyProps`] instead of sending an invalid request to the device.
    ///
    /// # Enforced invariants
    ///
    /// - Key kind must be AES and class must be Secret.
    /// - AES keys in this layer are restricted to encryption/decryption usage; we
    ///   reject signing/verifying/derivation and key wrap/unwrap usage flags.
    /// - Key material must not be extractable.
    /// - Key size must be one of 128/192/256 bits.
    fn validate(props: &HsmKeyProps) -> HsmResult<()> {
        // Kind/class: ensure we're validating an AES *secret* key.
        if props.kind() != HsmKeyKind::Aes {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES keys must be secret keys.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES keys should be both encrypt/decrypt.
        if !props.can_encrypt() && !props.can_decrypt() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Usage restrictions: this wrapper is for AES encryption/decryption only.
        if props.can_sign()
            || props.can_verify()
            || props.can_derive()
            || props.can_wrap()
            || props.can_unwrap()
        {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Key material must not be extractable via this API.
        if props.is_extractable() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Only standard AES key sizes are supported.
        if props.bits() != 128 && props.bits() != 192 && props.bits() != 256 {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Make sure ECC Curve is None for AES keys
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES keys should not pub key material
        if props.pub_key_der().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES secret keys are not marked as private.
        if props.is_private() {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

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
        //check key properties before generating key
        HsmAesKey::validate(&props)?;

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
        // Validate key properties before unwrapping, else handle will not be released properly
        HsmAesKey::validate(&key_props)?;

        let (handle, props) =
            ddi::rsa_aes_unwrap_key(unwrapping_key, wrapped_key, self.hash_algo, key_props)?;
        let key = HsmAesKey::new(unwrapping_key.session().clone(), props, handle);
        Ok(key)
    }
}

impl TryFrom<HsmGenericSecretKey> for HsmAesKey {
    type Error = HsmError;

    /// Converts a generic secret-key handle into a typed AES key wrapper.
    ///
    /// This is a cheap conversion: it re-wraps the same underlying key handle
    /// (stored in shared state) after validating key kind and class.
    fn try_from(key: HsmGenericSecretKey) -> Result<Self, Self::Error> {
        // Ensure the generic key is actually an AES *secret* key.
        if key.kind() != HsmKeyKind::Aes || key.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKey)?;
        }

        // Validate key properties before converting
        HsmAesKey::validate(&key.props())?;

        // Re-wrap the existing inner key state so typed wrappers share the same
        // underlying handle + drop semantics.
        Ok(HsmAesKey::from_inner(key.inner()))
    }
}
