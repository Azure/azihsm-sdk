// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES key structures and generation.
//!
//! This module provides AES key types and generation algorithms for use with
//! HSM sessions. It implements key generation operations that create and manage
//! AES keys within the hardware security module.

use super::*;

define_hsm_key!(pub HsmAesKey);

impl HsmAesKey {
    /// Returns whether `bits` is a supported AES key size.
    ///
    /// The value is expressed in **bits** (not bytes). This layer only accepts
    /// standard AES key sizes: 128, 192, and 256.
    ///
    /// This is used by [`HsmAesKey::validate_props`] to reject unsupported key
    /// sizes early.
    fn validate_key_size(bits: usize) -> Result<(), HsmError> {
        match bits {
            128 | 192 | 256 => Ok(()),
            _ => Err(HsmError::InvalidKeyProps),
        }
    }

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
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        let supported_flags = HsmKeyFlags::ENCRYPT | HsmKeyFlags::DECRYPT; //AES Keys can be used for both encrypt and decrypt

        // Kind/class: ensure we're validating an AES *secret* key.
        if props.kind() != HsmKeyKind::Aes {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES keys must be secret keys.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Only standard AES key sizes are supported.
        HsmAesKey::validate_key_size(props.bits() as usize)?;

        // check if Ecc curve is set
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Ensure no invalid usage flags are set.
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }
        Ok(())
    }
}

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
        //check key properties before generating key
        HsmAesKey::validate_props(&props)?;

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
        HsmAesKey::validate_props(&key_props)?;

        let (handle, props) =
            ddi::rsa_aes_unwrap_key(unwrapping_key, wrapped_key, self.hash_algo, key_props)?;
        let key = HsmAesKey::new(unwrapping_key.session().clone(), props, handle);
        Ok(key)
    }
}

#[derive(Default)]
pub struct HsmAesKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmAesKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmAesKey;
    type Error = HsmError;

    /// Unmasks an AES key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked AES key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked AES key on success.
    fn unmask_key(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;
        HsmAesKey::validate_props(&props)?;
        let key = HsmAesKey::new(session.clone(), props, handle);
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
        // Validate key properties before converting
        HsmAesKey::validate_props(&key.props())?;

        // Re-wrap the existing inner key state so typed wrappers share the same
        // underlying handle + drop semantics.
        Ok(HsmAesKey::from_inner(key.inner()))
    }
}

// HSM AES XTS key
define_hsm_key!(pub HsmAesXtsKey, (ddi::HsmKeyHandle, ddi::HsmKeyHandle));

impl HsmAesXtsKey {
    /// Returns whether `bits` is a supported AES XTS key size.
    ///
    /// The value is expressed in **bits** (not bytes). This layer only accepts
    /// 64-byte AES XTS keys (512 bits).
    ///
    /// This is used by [`HsmAesXtsKey::validate_props`] to reject unsupported key
    /// sizes early.
    fn validate_key_size(bits: usize) -> Result<(), HsmError> {
        match bits {
            512 => Ok(()),
            _ => Err(HsmError::InvalidKeyProps),
        }
    }

    /// Validates that `props` describe a supported HSM-backed AES XTS secret key.
    ///
    /// This is used as a defensive check at API boundaries (key generation,
    /// unwrapping, and algorithm operations) so we fail fast with
    /// [`HsmError::InvalidKeyProps`] instead of sending an invalid request to the device.
    /// # Enforced invariants
    /// - Key kind must be AES and class must be Secret.
    /// - AES XTS keys in this layer are restricted to encryption/decryption usage; we
    ///   reject signing/verifying/derivation and key wrap/unwrap usage flags.
    /// - Key material must not be extractable.
    /// - Key size must be 512 bits.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        let supported_flags = HsmKeyFlags::ENCRYPT | HsmKeyFlags::DECRYPT; //AES XTS Keys can be used for both encrypt and decrypt

        // check if key supports at least one of encrypt/decrypt
        if !props.can_encrypt() && !props.can_decrypt() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Kind/class: ensure we're validating an AES *secret* key.
        if props.kind() != HsmKeyKind::AesXts {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES keys must be secret keys.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Only standard AES XTS key sizes are supported.
        HsmAesXtsKey::validate_key_size(props.bits() as usize)?;

        // check if Ecc curve is set
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Ensure no invalid usage flags are set.
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}
impl HsmSecretKey for HsmAesXtsKey {}

impl HsmEncryptionKey for HsmAesXtsKey {}

impl HsmDecryptionKey for HsmAesXtsKey {}

#[derive(Default)]
pub struct HsmAesXtsKeyGenAlgo {}

impl HsmKeyGenOp for HsmAesXtsKeyGenAlgo {
    type Key = HsmAesXtsKey;
    type Session = HsmSession;
    type Error = HsmError;

    /// Generates a new AES XTS key.
    ///
    /// Creates a new AES XTS key within the HSM session using the specified key
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
    /// Returns an `AesXtsKey` instance on success.
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
        HsmAesXtsKey::validate_props(&props)?;

        let (handle1, handle2, dev_key_props) = ddi::aes_xts_generate_key(session, props)?;

        Ok(HsmAesXtsKey::new(
            session.clone(),
            dev_key_props,
            (handle1, handle2),
        ))
    }
}

// AES-GCM Key Type
define_hsm_key!(pub HsmAesGcmKey);

impl HsmAesGcmKey {
    /// Validates that `bits` is a supported AES-GCM key size.
    ///
    /// The device only supports 256-bit keys for AES-GCM.
    fn validate_key_size(bits: usize) -> Result<(), HsmError> {
        match bits {
            256 => Ok(()),
            _ => Err(HsmError::InvalidKeyProps),
        }
    }

    /// Validates that `props` describe a supported HSM-backed AES-GCM secret key.
    ///
    /// This is used as a defensive check at API boundaries (key generation,
    /// unwrapping, and algorithm operations) so we fail fast with
    /// [`HsmError::InvalidKeyProps`] instead of sending an invalid request to the device.
    ///
    /// # Enforced invariants
    ///
    /// - Key kind must be AesGcm and class must be Secret.
    /// - AES-GCM keys are restricted to encryption/decryption usage.
    /// - Key size must be 256 bits.
    pub(crate) fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        let supported_flags = HsmKeyFlags::ENCRYPT | HsmKeyFlags::DECRYPT;

        // Kind/class: ensure we're validating an AES-GCM *secret* key.
        if props.kind() != HsmKeyKind::AesGcm {
            Err(HsmError::InvalidKeyProps)?;
        }

        // AES-GCM keys must be secret keys.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Only 256-bit keys are supported for AES-GCM.
        HsmAesGcmKey::validate_key_size(props.bits() as usize)?;

        // check if Ecc curve is set
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Ensure no invalid usage flags are set.
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

impl HsmSecretKey for HsmAesGcmKey {}

impl HsmEncryptionKey for HsmAesGcmKey {}

impl HsmDecryptionKey for HsmAesGcmKey {}

/// HSM-based AES-GCM key generation algorithm.
///
/// Implements the key generation operation trait for creating AES-GCM keys within
/// an HSM session. AES-GCM keys are 256-bit only.
#[derive(Default)]
pub struct HsmAesGcmKeyGenAlgo {}

impl HsmKeyGenOp for HsmAesGcmKeyGenAlgo {
    type Key = HsmAesGcmKey;
    type Session = HsmSession;
    type Error = HsmError;

    /// Generates a new AES-GCM key.
    ///
    /// Creates a new AES-GCM key within the HSM session using the specified key
    /// properties. The key is generated within the hardware security module
    /// and returned with both a handle for operations and masked key material.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session in which to generate the key
    /// * `props` - Key properties defining attributes like usage permissions
    ///
    /// # Returns
    ///
    /// Returns an `HsmAesGcmKey` instance on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session is invalid or closed
    /// - Key properties are invalid or unsupported
    /// - Key generation fails in the HSM
    fn generate_key(
        &mut self,
        session: &Self::Session,
        props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error> {
        // Check key properties before generating key
        HsmAesGcmKey::validate_props(&props)?;

        let (handle, props) = ddi::aes_gcm_generate_key(session, props)?;
        Ok(HsmAesGcmKey::new(session.clone(), props, handle))
    }
}

/// AES-GCM Key Unwrapping Algorithm using RSA keys.
///
/// This struct implements the key unwrapping operation for AES-GCM keys that have been wrapped with
/// RSA AES Key Wrap algorithm.
pub struct HsmAesGcmKeyRsaAesKeyUnwrapAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmAesGcmKeyRsaAesKeyUnwrapAlgo {
    /// Creates a new AES-GCM key unwrapping algorithm with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use during the unwrapping process.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmAesGcmKeyRsaAesKeyUnwrapAlgo`.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmKeyUnwrapOp for HsmAesGcmKeyRsaAesKeyUnwrapAlgo {
    type UnwrappingKey = HsmRsaPrivateKey;
    type Key = HsmAesGcmKey;
    type Error = HsmError;

    /// Unwraps an AES-GCM key using the provided RSA unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `unwrapping_key` - The RSA private key used to unwrap the AES-GCM key
    /// * `wrapped_key` - The wrapped AES-GCM key data.
    /// * `key_props` - Properties for the unwrapped AES-GCM key.
    ///
    /// # Returns
    ///
    /// Returns the unwrapped AES-GCM key on success.
    fn unwrap_key(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        key_props: HsmKeyProps,
    ) -> Result<Self::Key, Self::Error> {
        // Validate key properties before unwrapping
        HsmAesGcmKey::validate_props(&key_props)?;

        let (handle, props) =
            ddi::rsa_aes_unwrap_key(unwrapping_key, wrapped_key, self.hash_algo, key_props)?;
        let key = HsmAesGcmKey::new(unwrapping_key.session().clone(), props, handle);
        Ok(key)
    }
}

/// AES-GCM Key Unmasking Algorithm.
#[derive(Default)]
pub struct HsmAesGcmKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmAesGcmKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmAesGcmKey;
    type Error = HsmError;

    /// Unmasks an AES-GCM key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked AES-GCM key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked AES-GCM key on success.
    fn unmask_key(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;
        HsmAesGcmKey::validate_props(&props)?;
        let key = HsmAesGcmKey::new(session.clone(), props, handle);
        Ok(key)
    }
}

impl TryFrom<HsmGenericSecretKey> for HsmAesGcmKey {
    type Error = HsmError;

    /// Converts a generic secret-key handle into a typed AES-GCM key wrapper.
    ///
    /// This is a cheap conversion: it re-wraps the same underlying key handle
    /// (stored in shared state) after validating key kind and class.
    fn try_from(key: HsmGenericSecretKey) -> Result<Self, Self::Error> {
        // Validate key properties before converting
        HsmAesGcmKey::validate_props(&key.props())?;

        // Re-wrap the existing inner key state so typed wrappers share the same
        // underlying handle + drop semantics.
        Ok(HsmAesGcmKey::from_inner(key.inner()))
    }
}
