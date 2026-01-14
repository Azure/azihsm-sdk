// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;

use super::*;

define_hsm_key_pair!(pub HsmRsaPrivateKey, pub HsmRsaPublicKey, crypto::RsaPublicKey);

impl HsmDecryptionKey for HsmRsaPrivateKey {}

impl HsmSigningKey for HsmRsaPrivateKey {}

impl HsmUnwrappingKey for HsmRsaPrivateKey {}

impl HsmEncryptionKey for HsmRsaPublicKey {}

impl HsmVerificationKey for HsmRsaPublicKey {}

/// RSA Key Unwrapping Key Generation Algorithm
#[derive(Default)]
pub struct HsmRsaKeyUnwrappingKeyGenAlgo {}

impl HsmKeyPairGenOp for HsmRsaKeyUnwrappingKeyGenAlgo {
    type PrivateKey = HsmRsaPrivateKey;
    type Session = HsmSession;
    type Error = HsmError;

    /// Generates an RSA key pair for key unwrapping.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for key generation.
    /// * `priv_key_props` - Properties for the private key to be generated.
    /// * `pub_key_props` - Properties for the public key to be generated.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing the generated private and public keys.
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
        let (handle, priv_key_props, pub_key_props) =
            ddi::get_rsa_unwrapping_key(session, priv_key_props, pub_key_props)?;

        // Extract the public key DER from the private key properties.
        let Some(pub_key_der) = pub_key_props.pub_key_der() else {
            return Err(HsmError::InternalError);
        };

        // Import the public key using azihsm-crypto.
        use crypto::ImportableKey;
        let crypto_key =
            crypto::RsaPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

        // Construct the HSM RSA key objects.
        let pub_key = HsmRsaPublicKey::new(pub_key_props, crypto_key);
        let priv_key =
            HsmRsaPrivateKey::new(session.clone(), priv_key_props, handle, pub_key.clone());

        Ok((priv_key, pub_key))
    }
}

pub struct HsmRsaKeyRsaAesKeyUnwrapAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmRsaKeyRsaAesKeyUnwrapAlgo {
    /// Creates a new RSA key pair unwrapping algorithm with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use during the unwrapping process.
    ///
    /// # Returns
    ///
    /// A new instance of `HsmRsaKeyRsaAesKeyUnwrapAlgo`.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmKeyPairUnwrapOp for HsmRsaKeyRsaAesKeyUnwrapAlgo {
    type UnwrappingKey = HsmRsaPrivateKey;
    type PrivateKey = HsmRsaPrivateKey;
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
            crypto::RsaPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

        // Construct the HSM RSA key objects.
        let pub_key = HsmRsaPublicKey::new(pub_key_props, crypto_key);
        let priv_key = HsmRsaPrivateKey::new(
            unwrapping_key.session().clone(),
            priv_key_props,
            handle,
            pub_key.clone(),
        );

        Ok((priv_key, pub_key))
    }
}
