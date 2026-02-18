// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC key structures and generation.
//!
//! This module provides Elliptic Curve Cryptography (ECC) key types and generation
//! algorithms for use with HSM sessions. It implements key pair generation operations
//! that create and manage ECC private/public key pairs within the hardware security module.

use azihsm_crypto as crypto;

use super::*;

// Define HsmEccPrivateKey and HsmEccPublicKey types.
define_hsm_key_pair!(pub HsmEccPrivateKey, pub HsmEccPublicKey,  crypto::EccPublicKey);

impl HsmEccPrivateKey {
    /// Validates key properties for an ECC **private** key.
    ///
    /// This is a fail-fast validation used by operations like key generation and unwrapping.
    /// It enforces:
    /// - `kind` must be [`HsmKeyKind::Ecc`]
    /// - `class` must be [`HsmKeyClass::Private`]
    /// - an ECC curve must be present (`ecc_curve`)
    /// - usage flags must be **exactly one** of `SIGN` or `DERIVE`
    /// - no unsupported flags may be set (beyond what this layer allows)
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if any required property is missing/invalid,
    /// or if unsupported/contradictory usage flags are present.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        // Supported usage flags for ECC private keys in this layer.
        let supported_flag = HsmKeyFlags::SIGN | HsmKeyFlags::DERIVE;

        // ECC private key must be either a signing key or a derivation key (but not both).
        if props.can_sign() == props.can_derive() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Kind/class: ensure we're validating an ECC *private* key.
        if props.kind() != HsmKeyKind::Ecc {
            Err(HsmError::InvalidKeyProps)?;
        }

        // ECC private keys must have a curve specified.
        if props.ecc_curve().is_none() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // ECC private keys must be private keys.
        if props.class() != HsmKeyClass::Private {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Ensure only supported usage flags are set.
        if !props.check_supported_flags(supported_flag) {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }

    /// Validates a requested ECC private/public key pair property set.
    ///
    /// This is a fail-fast validation used by ECC key-pair operations (generation, unwrap, unmask)
    /// to ensure the private and public [`HsmKeyProps`] are individually valid and mutually
    /// compatible.
    ///
    /// It enforces:
    /// - `priv_props` is a valid ECC private-key property set (see [`Self::validate_props`])
    /// - `pub_props` is a valid ECC public-key property set (see [`HsmEccPublicKey::validate_props`])
    /// - both keys specify the same ECC curve (`ecc_curve`)
    /// - public-key usage does not exceed private-key capability:
    ///   - if `pub_props` allows `VERIFY`, then `priv_props` must allow `SIGN`
    ///   - if `pub_props` allows `DERIVE`, then `priv_props` must allow `DERIVE`
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if either side is invalid, if curves mismatch,
    /// or if the usage capabilities are not compatible.
    fn validate_key_pair_props(priv_props: &HsmKeyProps, pub_props: &HsmKeyProps) -> HsmResult<()> {
        // Validate both private key properties.
        Self::validate_props(priv_props)?;

        //validate public key properties
        HsmEccPublicKey::validate_props(pub_props)?;

        // check compatibility between private and public key properties
        if priv_props.ecc_curve() != pub_props.ecc_curve() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // private key must be able to sign if public key can verify
        if pub_props.can_verify() && !priv_props.can_sign() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // private key must be able to derive if public key can derive
        if pub_props.can_derive() && !priv_props.can_derive() {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

impl HsmEccPublicKey {
    /// Validates key properties for an ECC **public** key.
    ///
    /// This is a fail-fast validation used by operations like key generation and unwrapping.
    /// It enforces:
    /// - `kind` must be [`HsmKeyKind::Ecc`]
    /// - `class` must be [`HsmKeyClass::Public`]
    /// - an ECC curve must be present (`ecc_curve`)
    /// - only supported usage flags may be set (`VERIFY` or `DERIVE`)
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if any required property is missing/invalid,
    /// or if unsupported usage flags are present.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        // Supported usage flags for ECC public keys in this layer.
        let supported_flag = HsmKeyFlags::VERIFY | HsmKeyFlags::DERIVE;

        //check if public key is verifiable or derivable
        if props.can_verify() == props.can_derive() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Kind/class: ensure we're validating an ECC *public* key.
        if props.kind() != HsmKeyKind::Ecc {
            Err(HsmError::InvalidKeyProps)?;
        }

        // ECC public keys must have a curve specified.
        if props.ecc_curve().is_none() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // ECC public keys must be public keys.
        if props.class() != HsmKeyClass::Public {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Ensure only supported usage flags are set.
        if !props.check_supported_flags(supported_flag) {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

impl HsmSigningKey for HsmEccPrivateKey {}

impl HsmDerivationKey for HsmEccPrivateKey {}

impl HsmVerificationKey for HsmEccPublicKey {}

/// ECC key pair generation algorithm using caller-provided public-key properties.
#[derive(Default)]
pub struct HsmEccKeyGenAlgo {}

impl HsmKeyPairGenOp for HsmEccKeyGenAlgo {
    type PrivateKey = HsmEccPrivateKey;
    type Session = HsmSession;
    type Error = HsmError;

    /// Generates a new ECC key pair in the HSM.
    ///
    /// # Parameters
    /// - `session`: Active HSM session for the operation.
    /// - `priv_key_props`: Properties applied to the private key and generation request.
    /// - `pub_key_props`: Properties applied to the public key.
    ///
    /// # Returns
    ///
    /// A tuple containing `HsmEccPrivateKey` (with handle, masked key, and associated public key)
    /// and `HsmEccPublicKey` on success, or `HsmError` on failure.
    fn generate_key_pair(
        &mut self,
        session: &Self::Session,
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Self::PrivateKey,
            <Self::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Self::Error,
    > {
        //validate private and public key properties
        HsmEccPrivateKey::validate_key_pair_props(&priv_key_props, &pub_key_props)?;

        // Create the ECC Key in the HSM via DDI.
        let (handle, priv_key_props, pub_key_props) =
            ddi::ecc_generate_key(session, priv_key_props)?;

        // Extract the public key DER from the private key properties.
        let Some(pub_key_der) = pub_key_props.pub_key_der() else {
            return Err(HsmError::InternalError);
        };

        // Import the public key using azihsm-crypto.
        use crypto::ImportableKey;
        let crypto_key =
            crypto::EccPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

        // Construct the HSM ECC key objects.
        let pub_key = HsmEccPublicKey::new(pub_key_props, crypto_key);
        let priv_key =
            HsmEccPrivateKey::new(session.clone(), priv_key_props, handle, pub_key.clone());

        Ok((priv_key, pub_key))
    }
}

pub struct HsmEccKeyRsaAesKeyUnwrapAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmEccKeyRsaAesKeyUnwrapAlgo {
    /// Creates a new ECC key pair unwrapping algorithm with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use during the unwrapping process.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmEccKeyRsaAesKeyUnwrapAlgo`.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmKeyPairUnwrapOp for HsmEccKeyRsaAesKeyUnwrapAlgo {
    type UnwrappingKey = HsmRsaPrivateKey;
    type PrivateKey = HsmEccPrivateKey;
    type Error = HsmError;

    /// Unwraps (decrypts) a wrapped ECC key pair using the specified RSA unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `unwrapping_key` - The RSA private key used to unwrap the ECC key pair.
    /// * `wrapped_key` - The wrapped ECC key pair data.
    /// * `priv_key_props` - Properties for the unwrapped private key.
    /// * `pub_key_props` - Properties for the unwrapped public key.
    ///
    /// # Returns
    ///
    /// Returns the unwrapped private and public keys on success.
    fn unwrap_key_pair(
        &mut self,
        unwrapping_key: &Self::UnwrappingKey,
        wrapped_key: &[u8],
        priv_key_props: HsmKeyProps,
        pub_key_props: HsmKeyProps,
    ) -> Result<
        (
            Self::PrivateKey,
            <Self::PrivateKey as HsmPrivateKey>::PublicKey,
        ),
        Self::Error,
    > {
        //Make sure unwrapping key can unwrap
        if !unwrapping_key.can_unwrap() {
            return Err(HsmError::InvalidKey);
        }

        HsmEccPrivateKey::validate_key_pair_props(&priv_key_props, &pub_key_props)?;

        //Make sure public key is verifiable key
        let (handle, priv_key_props, pub_key_props) = ddi::rsa_aes_unwrap_key_pair(
            unwrapping_key,
            wrapped_key,
            self.hash_algo,
            priv_key_props,
            pub_key_props,
        )?;

        // Extract the public key DER from the private key properties.
        let Some(pub_key_der) = pub_key_props.pub_key_der() else {
            return Err(HsmError::InternalError);
        };

        // Import the public key using azihsm-crypto.
        use crypto::ImportableKey;
        let crypto_key =
            crypto::EccPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

        // Construct the HSM ECC key objects.
        let pub_key = HsmEccPublicKey::new(pub_key_props, crypto_key);
        let priv_key = HsmEccPrivateKey::new(
            unwrapping_key.session().clone(),
            priv_key_props,
            handle,
            pub_key.clone(),
        );

        Ok((priv_key, pub_key))
    }
}

#[derive(Default)]
pub struct HsmEccKeyUnmaskAlgo {}

impl HsmKeyPairUnmaskOp for HsmEccKeyUnmaskAlgo {
    type Session = HsmSession;
    type PrivateKey = HsmEccPrivateKey;
    type Error = HsmError;

    /// Unmasks an ECC key pair using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked ECC key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked ECC key on success.
    fn unmask_key_pair(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> HsmResult<(
        algo::ecc::key::HsmEccPrivateKey,
        algo::ecc::key::HsmEccPublicKey,
    )> {
        let (handle, priv_props, pub_props) = ddi::unmask_key_pair(session, masked_key)?;

<<<<<<< HEAD
        HsmEccPrivateKey::validate_key_pair_props(&priv_props, &pub_props)?;

        let Some(pub_key_der) = pub_props.pub_key_der() else {
=======
        //construct key guard first to ensure handles are released if validation fails
        let key_id = ddi::HsmKeyIdGuard::new(session, handle);

        //create a guard for handl
        let Some(pub_key_der) = pub_props.pub_key_der() else {
            // NOTE: This should never happen because the DDI unmask_key_pair should guarantee the presence of pub_key_der,
            // no need to drop the handle here
>>>>>>> main
            return Err(HsmError::InternalError);
        };

        use crypto::ImportableKey;
        let crypto_key =
            crypto::EccPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

<<<<<<< HEAD
        let pub_key = HsmEccPublicKey::new(pub_props, crypto_key);
        let priv_key = HsmEccPrivateKey::new(session.clone(), priv_props, handle, pub_key.clone());
=======
        let pub_key = HsmEccPublicKey::new(pub_props.clone(), crypto_key);
        let priv_key = HsmEccPrivateKey::new(
            session.clone(),
            priv_props.clone(),
            key_id.release(),
            pub_key.clone(),
        );

        // Validate after constructing the wrapper so a failure drops and deletes the handle.
        HsmEccPrivateKey::validate_key_pair_props(&priv_props, &pub_props)?;
>>>>>>> main

        Ok((priv_key, pub_key))
    }
}

impl From<HsmEccCurve> for crypto::EccCurve {
    /// Maps a [`HsmEccCurve`] variant to the corresponding [`crypto::EccCurve`] variant.
    fn from(curve: HsmEccCurve) -> Self {
        match curve {
            HsmEccCurve::P256 => crypto::EccCurve::P256,
            HsmEccCurve::P384 => crypto::EccCurve::P384,
            HsmEccCurve::P521 => crypto::EccCurve::P521,
        }
    }
}
