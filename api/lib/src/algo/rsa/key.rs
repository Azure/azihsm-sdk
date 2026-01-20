// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;

use super::*;

define_hsm_key_pair!(pub HsmRsaPrivateKey, pub HsmRsaPublicKey, crypto::RsaPublicKey);

/// Validates supported RSA key sizes for this layer.
///
/// The RSA backend/implementation only supports a fixed set of modulus sizes.
/// Callers should ensure the `bits` field of [`HsmKeyProps`] is one of these values
/// before attempting key generation/import/unwrapping.
///
/// # Errors
/// Returns [`HsmError::InvalidKeyProps`] if `bits` is not supported.
fn validate_key_size(bits: usize) -> HsmResult<()> {
    match bits {
        2048 | 3072 | 4096 => Ok(()),
        _ => Err(HsmError::InvalidKeyProps),
    }
}

impl HsmRsaPrivateKey {
    /// Validates key properties for an RSA **private** key.
    ///
    /// This is a fail-fast validation used by operations like unwrapping/import.
    /// It enforces:
    /// - `kind` must be [`HsmKeyKind::Rsa`]
    /// - `class` must be [`HsmKeyClass::Private`]
    /// - key size must be supported (see [`validate_key_size`])
    /// - `ecc_curve` must be unset (RSA keys must not specify an ECC curve)
    /// - usage flags must include **exactly one** of: `DECRYPT`, `UNWRAP`, `SIGN`
    /// - no unsupported flags may be set (beyond what this layer allows; `SESSION` is allowed)
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if any required property is missing/invalid,
    /// if more than one usage flag is set, or if unsupported flags are present.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        //RSA private key supported flags are DECRYPT, UNWRAP, SIGN
        let supported_flags = HsmKeyFlags::DECRYPT | HsmKeyFlags::SIGN | HsmKeyFlags::UNWRAP;

        // Kind/class: ensure we're validating an AES *secret* key.
        if props.kind() != HsmKeyKind::Rsa {
            Err(HsmError::InvalidKeyProps)?;
        }

        // RSA private keys must be Private class.
        if props.class() != HsmKeyClass::Private {
            Err(HsmError::InvalidKeyProps)?;
        }

        //RSA should have one of the supported crypto functions (typecast to u8 and sum to simplify the logic)
        let usage_count =
            props.can_decrypt() as u8 + props.can_unwrap() as u8 + props.can_sign() as u8;
        if usage_count != 1 {
            Err(HsmError::InvalidKeyProps)?;
        }

        // check if Ecc curve is set
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Validate key size
        validate_key_size(props.bits() as usize)?;

        // Ensure no invalid usage flags are set other than expected ones.
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }
        Ok(())
    }

    /// Validates a requested RSA private/public key pair property set.
    ///
    /// This is a fail-fast validation used by RSA key-pair operations (generation, unwrap, unmask)
    /// to ensure the provided private and public [`HsmKeyProps`] are individually valid and also
    /// mutually compatible.
    ///
    /// It enforces:
    /// - `priv_props` is a valid RSA private-key property set (see [`Self::validate_props`])
    /// - `pub_props` is a valid RSA public-key property set (see [`HsmRsaPublicKey::validate_props`])
    /// - both keys use the same modulus size (`bits`)
    /// - usage flags are complementary (`DECRYPT`↔`ENCRYPT`, `SIGN`↔`VERIFY`, `UNWRAP`↔`WRAP`)
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if either side is invalid, if the key sizes differ,
    /// or if usage flags are not complementary.
    fn validate_key_pair_props(priv_props: &HsmKeyProps, pub_props: &HsmKeyProps) -> HsmResult<()> {
        //validate private key props
        Self::validate_props(priv_props)?;

        //validate public key props
        HsmRsaPublicKey::validate_props(pub_props)?;

        // Both keys must have the same modulus size.
        if priv_props.bits() != pub_props.bits() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Private/Public key usage flags must be complementary.
        if priv_props.can_decrypt() != pub_props.can_encrypt()
            || priv_props.can_sign() != pub_props.can_verify()
            || priv_props.can_unwrap() != pub_props.can_wrap()
        {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}
impl HsmRsaPublicKey {
    /// Validates key properties for an RSA **public** key.
    ///
    /// This is a fail-fast validation used by operations like unwrapping/import.
    /// It enforces:
    /// - `kind` must be [`HsmKeyKind::Rsa`]
    /// - `class` must be [`HsmKeyClass::Public`]
    /// - key size must be supported (see [`validate_key_size`])
    /// - `ecc_curve` must be unset (RSA keys must not specify an ECC curve)
    /// - usage flags must include **zero or one** of: `ENCRYPT`, `WRAP`, `VERIFY`
    ///   (zero allows "export-only" public keys)
    /// - no unsupported flags may be set (beyond what this layer allows; `SESSION` is allowed)
    ///
    /// # Errors
    /// Returns [`HsmError::InvalidKeyProps`] if any required property is missing/invalid,
    /// if more than one usage flag is set, or if unsupported flags are present.
    fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        //RSA public key supported flags are ENCRYPT, WRAP, VERIFY
        let supported_flags = HsmKeyFlags::ENCRYPT | HsmKeyFlags::VERIFY | HsmKeyFlags::WRAP;

        // Kind/class: ensure we're validating an AES *secret* key.
        if props.kind() != HsmKeyKind::Rsa {
            Err(HsmError::InvalidKeyProps)?;
        }

        // RSA public keys must be Public class.
        if props.class() != HsmKeyClass::Public {
            Err(HsmError::InvalidKeyProps)?;
        }

        //RSA public keys must have none or one of the supported crypto functions (typecast to u8 and sum to simplify the logic)
        if props.can_encrypt() as u8 + props.can_wrap() as u8 + props.can_verify() as u8 > 1 {
            Err(HsmError::InvalidKeyProps)?;
        }
        // check if Ecc curve is set
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Validate key size
        validate_key_size(props.bits() as usize)?;

        // Ensure no invalid usage flags are set.
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }
        Ok(())
    }
}

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
        // Validate the provided key properties.
        HsmRsaPrivateKey::validate_key_pair_props(&priv_key_props, &pub_key_props)?;

        // DDI supports only unwrapping keys for RSA key pair generation.
        if !priv_key_props.can_unwrap() || !pub_key_props.can_wrap() {
            return Err(HsmError::InvalidKeyProps);
        }

        // DDI Supports only 2048 key size for unwrapping keys
        if priv_key_props.bits() != 2048 || pub_key_props.bits() != 2048 {
            return Err(HsmError::InvalidKeyProps);
        }

        let (handle, priv_key_props, pub_key_props) = ddi::get_rsa_unwrapping_key(session)?;

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

    /// Unwraps (decrypts) a wrapped RSA key pair using the specified RSA unwrapping key.
    ///
    /// # Arguments
    ///
    /// * `unwrapping_key` - The RSA private key used to unwrap the RSA key pair.
    /// * `wrapped_key` - The wrapped RSA key pair data.
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
        // check if unwrapping key can unwrap
        if !unwrapping_key.can_unwrap() {
            return Err(HsmError::InvalidKey);
        }

        //check private and public key properties
        HsmRsaPrivateKey::validate_key_pair_props(&priv_key_props, &pub_key_props)?;

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

#[derive(Default)]
pub struct HsmRsaKeyUnmaskAlgo {}

impl HsmKeyPairUnmaskOp for HsmRsaKeyUnmaskAlgo {
    type Session = HsmSession;
    type PrivateKey = HsmRsaPrivateKey;
    type Error = HsmError;

    /// Unmasks an RSA key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked RSA key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked RSA key pair on success.
    fn unmask_key_pair(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> HsmResult<(
        algo::rsa::key::HsmRsaPrivateKey,
        algo::rsa::key::HsmRsaPublicKey,
    )> {
        let (handle, priv_props, pub_props) = ddi::unmask_key_pair(session, masked_key)?;

        HsmRsaPrivateKey::validate_key_pair_props(&priv_props, &pub_props)?;

        let Some(pub_key_der) = pub_props.pub_key_der() else {
            return Err(HsmError::InternalError);
        };

        use crypto::ImportableKey;
        let crypto_key =
            crypto::RsaPublicKey::from_bytes(pub_key_der).map_hsm_err(HsmError::InternalError)?;

        let pub_key = HsmRsaPublicKey::new(pub_props, crypto_key);
        let priv_key = HsmRsaPrivateKey::new(session.clone(), priv_props, handle, pub_key.clone());

        Ok((priv_key, pub_key))
    }
}
