// Copyright (C) Microsoft Corporation. All rights reserved.

//! ECC key structures and generation.
//!
//! This module provides Elliptic Curve Cryptography (ECC) key types and generation
//! algorithms for use with HSM sessions. It implements key pair generation operations
//! that create and manage ECC private/public key pairs within the hardware security module.

use azihsm_crypto as crypto;

use super::*;

// Define HsmEccPrivateKey and HsmEccPublicKey types.
define_hsm_key_pair!(pub HsmEccPrivateKey, pub HsmEccPublicKey,  crypto::EccPublicKey);

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
        // Create the ECC Key in the HSM via DDI.
        let (handle, priv_key_props, pub_key_props) =
            ddi::ecc_generate_key(session, priv_key_props, pub_key_props)?;

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
