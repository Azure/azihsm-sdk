#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! RSA cryptographic operations
use std::sync::Arc;

use azihsm_crypto::*;
use azihsm_ddi_types::DdiHashAlgorithm;
use azihsm_ddi_types::DdiKeyAvailability;
use azihsm_ddi_types::DdiKeyClass;
use azihsm_ddi_types::DdiKeyType;
use azihsm_ddi_types::DdiKeyUsage;
use azihsm_ddi_types::DdiRsaCryptoPadding;
use parking_lot::RwLock;

use crate::crypto::utils::rsa_pkcs_pss_utils;
use crate::crypto::Algo;
use crate::crypto::DecryptOp;
use crate::crypto::EncryptOp;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::KeyUnwrapOp;
use crate::crypto::KeyWrapOp;
use crate::crypto::SafeInnerAccess;
use crate::crypto::SignOp;
use crate::crypto::VerifyOp;
use crate::ddi;
use crate::ddi::DdiRsaUnwrapParams;
use crate::types::key_props::AzihsmKeyClass;
use crate::types::key_props::InnerKeyPropsOps;
use crate::types::key_props::KeyPairPropsOps;
use crate::types::key_props::KeyPropValue;
use crate::types::key_props::KeyProps;
use crate::types::AlgoId;
use crate::types::AzihsmKeyPropId;
use crate::types::KeyKind;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_INTERNAL_ERROR;
use crate::AZIHSM_KEY_ALREADY_EXISTS;
use crate::AZIHSM_KEY_NOT_INITIALIZED;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;
use crate::AZIHSM_RSA_CRYPTO_ERROR;
use crate::AZIHSM_RSA_INVALID_PUB_KEY;
use crate::AZIHSM_RSA_KEYGEN_FAILED;
use crate::AZIHSM_RSA_SIGN_FAILED;
use crate::AZIHSM_RSA_UNSUPPORTED_HASH_ALGORITHM;
use crate::AZIHSM_RSA_UNWRAP_FAILED;
use crate::AZIHSM_RSA_VERIFY_FAILED;

/// RSA Key Pair generation implementation
#[derive(Clone, Debug)]
pub struct RsaPkcsKeyPair(Arc<RwLock<RsaPkcsKeyPairInner>>);

#[derive(Clone, Debug)]
pub(crate) struct RsaPkcsPrivateKey(Arc<RwLock<RsaPkcsPrivateKeyInner>>);

impl RsaPkcsPrivateKey {
    /// Get the private key ID
    pub fn key_id(&self) -> Option<KeyId> {
        self.0.read().priv_key_id
    }

    /// Set the private key ID
    pub fn set_key_id(&mut self, id: KeyId) {
        self.0.write().priv_key_id = Some(id);
    }

    /// Access key properties immutably
    pub(crate) fn properties(&self) -> parking_lot::RwLockReadGuard<'_, RsaPkcsPrivateKeyInner> {
        self.0.read()
    }

    /// Access key properties mutably
    pub(crate) fn properties_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, RsaPkcsPrivateKeyInner> {
        self.0.write()
    }
}

pub(crate) struct RsaPkcsPrivateKeyInner {
    priv_key_id: Option<KeyId>,
    priv_key_props: KeyProps,
}

pub(crate) struct RsaPkcsPublicKeyInner {
    pub_key: Option<Vec<u8>>,
    pub_key_props: KeyProps,
}

#[derive(Clone, Debug)]
pub(crate) struct RsaPkcsPublicKey(Arc<RwLock<RsaPkcsPublicKeyInner>>);

impl RsaPkcsPublicKey {
    /// Get a copy of the public key bytes
    pub fn key_bytes(&self) -> Option<Vec<u8>> {
        self.0.read().pub_key.clone()
    }

    /// Set the public key bytes
    pub fn set_key_bytes(&mut self, key: Vec<u8>) {
        self.0.write().pub_key = Some(key);
    }

    /// Access key properties immutably
    pub(crate) fn properties(&self) -> parking_lot::RwLockReadGuard<'_, RsaPkcsPublicKeyInner> {
        self.0.read()
    }

    /// Access key properties mutably
    pub(crate) fn properties_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, RsaPkcsPublicKeyInner> {
        self.0.write()
    }
}

struct RsaPkcsKeyPairInner {
    private_key: RsaPkcsPrivateKey,
    public_key: RsaPkcsPublicKey,
}

impl InnerKeyPropsOps for RsaPkcsPrivateKeyInner {
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.priv_key_props.get_property(id)
    }

    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.priv_key_props.set_property(id, value)
    }

    fn apply_defaults(&mut self) -> Result<(), AzihsmError> {
        // Set operation defaults for private keys only if user hasn't specified any operations
        // Check if user has specified any operation flags
        let has_any_operation = self.priv_key_props.decrypt().is_some()
            || self.priv_key_props.sign().is_some()
            || self.priv_key_props.wrap().is_some()
            || self.priv_key_props.unwrap().is_some()
            || self.priv_key_props.derive().is_some();

        if !has_any_operation {
            // Default to decrypt (EncryptDecrypt category) if no operations specified
            self.priv_key_props.set_decrypt(true);
        }

        // Apply HSM-managed defaults for private keys
        // Private keys are always locally generated (for now)
        self.priv_key_props.apply_hsm_defaults(
            AzihsmKeyClass::Private,
            true, // is_local: true for generated keys
        );
        Ok(())
    }
}

impl InnerKeyPropsOps for RsaPkcsPublicKeyInner {
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.pub_key_props.get_property(id)
    }

    fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.pub_key_props.set_property(id, value)
    }

    fn apply_defaults(&mut self) -> Result<(), AzihsmError> {
        // Set operation defaults for public keys only if user hasn't specified any operations
        // Check if user has specified any operation flags
        let has_any_operation = self.pub_key_props.encrypt().is_some()
            || self.pub_key_props.verify().is_some()
            || self.pub_key_props.wrap().is_some()
            || self.pub_key_props.unwrap().is_some();

        if !has_any_operation {
            // Default to encrypt (EncryptDecrypt category) if no operations specified
            self.pub_key_props.set_encrypt(true);
        }

        // Apply HSM-managed defaults for public keys
        // Public keys are always locally generated (for now)
        self.pub_key_props.apply_hsm_defaults(
            AzihsmKeyClass::Public,
            true, // is_local: true for generated keys
        );
        Ok(())
    }
}

impl std::fmt::Debug for RsaPkcsKeyPairInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPkcsKeyPairInner")
            .field("private_key", &self.private_key)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl std::fmt::Debug for RsaPkcsPrivateKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPkcsPrivateKeyInner")
            .field("priv_key_id", &self.priv_key_id)
            .field("priv_key_props", &self.priv_key_props)
            .finish()
    }
}

impl std::fmt::Debug for RsaPkcsPublicKeyInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaPkcsPublicKeyInner")
            .field("pub_key", &self.pub_key.as_ref().map(|v| v.len()))
            .field("pub_key_props", &self.pub_key_props)
            .finish()
    }
}

impl Key for RsaPkcsKeyPair {}

impl RsaPkcsKeyPair {
    /// Create a new RSA PKCS#1 v1.5 key pair generation object
    ///
    /// # Errors
    ///
    /// Returns an error if user-provided properties are invalid (e.g., non-settable properties,
    /// conflicting operation flags, or properties that violate operation exclusivity).
    pub fn new(pub_key_props: KeyProps, priv_key_props: KeyProps) -> Result<Self, AzihsmError> {
        // Create initial key properties
        let mut validated_priv_props = KeyProps::new();
        let mut validated_pub_props = KeyProps::new();

        // Validate and apply user properties
        validated_priv_props.apply_user_properties(&priv_key_props)?;
        validated_pub_props.apply_user_properties(&pub_key_props)?;

        // Create key structures
        let mut priv_key = RsaPkcsPrivateKeyInner {
            priv_key_id: None,
            priv_key_props: validated_priv_props,
        };
        let mut pub_key = RsaPkcsPublicKeyInner {
            pub_key: None,
            pub_key_props: validated_pub_props,
        };

        // Apply key-specific defaults
        priv_key.apply_defaults()?;
        pub_key.apply_defaults()?;

        // Validate operation exclusivity after defaults are applied
        priv_key.priv_key_props.validate_operation_exclusivity()?;
        pub_key.pub_key_props.validate_operation_exclusivity()?;

        let inner = RsaPkcsKeyPairInner {
            private_key: RsaPkcsPrivateKey(Arc::new(RwLock::new(priv_key))),
            public_key: RsaPkcsPublicKey(Arc::new(RwLock::new(pub_key))),
        };
        Ok(RsaPkcsKeyPair(Arc::new(RwLock::new(inner))))
    }
    /// Create a new RSA PKCS key pair with an existing key ID and public key
    ///
    /// This is typically used when importing or wrapping existing keys.
    ///
    /// # Arguments
    /// * `priv_key_id` - The existing private key ID
    /// * `pub_key` - Optional DER-encoded public key bytes
    /// * `pub_key_props` - Public key properties
    /// * `priv_key_props` - Private key properties
    ///
    /// # Errors
    ///
    /// Returns an error if user-provided properties are invalid.
    pub fn new_with_id(
        priv_key_id: KeyId,
        pub_key: Option<Vec<u8>>,
        pub_key_props: KeyProps,
        priv_key_props: KeyProps,
    ) -> Result<Self, AzihsmError> {
        // Create key pair with validated properties and defaults applied
        let new_key_pair = Self::new(pub_key_props, priv_key_props)?;

        // Set the existing key ID and public key bytes
        new_key_pair.with_inner_mut(|inner| {
            inner.private_key.set_key_id(priv_key_id);
            if let Some(key_bytes) = pub_key {
                inner.public_key.set_key_bytes(key_bytes);
            }
        });

        Ok(new_key_pair)
    }
    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&RsaPkcsKeyPairInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut RsaPkcsKeyPairInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn priv_key_id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.private_key.key_id())
    }

    #[allow(unused)]
    pub fn pub_key(&self) -> Option<Vec<u8>> {
        self.with_inner(|inner| inner.public_key.key_bytes())
    }

    #[allow(unused)]
    pub fn with_pub_key<R>(&self, f: impl FnOnce(Option<&[u8]>) -> R) -> R {
        self.with_inner(|inner| {
            let pub_key_guard = inner.public_key.properties();
            f(pub_key_guard.pub_key.as_deref())
        })
    }

    /// Get the key size for this key pair
    #[allow(unused)]
    pub(crate) fn key_size(&self) -> Option<u32> {
        self.with_inner(|inner| inner.private_key.properties().priv_key_props.bit_len())
    }
}

impl KeyPairPropsOps for RsaPkcsKeyPair {
    fn get_pub_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.public_key.0.read().get_property(id))
    }

    fn set_pub_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.public_key.0.write().set_property(id, value))
    }

    fn get_priv_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.private_key.0.read().get_property(id))
    }

    fn set_priv_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.private_key.0.write().set_property(id, value))
    }
}

impl KeyGenOp for RsaPkcsKeyPair {
    fn generate_key_pair(&mut self, session: &Session) -> Result<(), AzihsmError> {
        // Check if already generated using the accessor functions
        if self.priv_key_id().is_some() || self.pub_key().is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        // Get key size from public key properties
        let key_size_bits = {
            let inner = self.0.read();
            let key_size_value = inner
                .public_key
                .0
                .read()
                .get_property(AzihsmKeyPropId::BitLen)?;

            // Extract u32 from KeyPropValue
            match key_size_value {
                KeyPropValue::BitLen(bits) => bits,
                _ => return Err(AZIHSM_KEY_PROPERTY_NOT_PRESENT),
            }
        };

        // Get RSA key pair from DDI
        let rsa_get_unwrapping_key = ddi::rsa_get_unwrapping_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
        )
        .map_err(|_| AZIHSM_RSA_KEYGEN_FAILED)?;

        // check if returned key_kind is same size as bit_len by matching
        let rec_key_size = match rsa_get_unwrapping_key.data.pub_key.key_kind {
            DdiKeyType::Rsa2kPublic => 2048,
            DdiKeyType::Rsa3kPublic => 3072,
            DdiKeyType::Rsa4kPublic => 4096,
            _ => return Err(AZIHSM_RSA_KEYGEN_FAILED),
        };

        if key_size_bits != rec_key_size {
            return Err(AZIHSM_RSA_KEYGEN_FAILED);
        }

        // Store the key ID and public key bytes
        self.with_inner_mut(|inner| {
            // Store the key ID and public key bytes
            inner
                .private_key
                .set_key_id(KeyId(rsa_get_unwrapping_key.data.key_id));
            inner.public_key.set_key_bytes(
                rsa_get_unwrapping_key.data.pub_key.der.data()
                    [..rsa_get_unwrapping_key.data.pub_key.der.len()]
                    .to_vec(),
            );

            // Set immutable properties (Kind and BitLen) that weren't in user properties
            {
                let mut props = inner.private_key.properties_mut();
                if props.priv_key_props.kind().is_none() {
                    props.priv_key_props.set_kind(KeyKind::Rsa);
                }
                if props.priv_key_props.bit_len().is_none() {
                    props.priv_key_props.set_bit_len(key_size_bits);
                }
            }

            {
                let mut props = inner.public_key.properties_mut();
                if props.pub_key_props.kind().is_none() {
                    props.pub_key_props.set_kind(KeyKind::Rsa);
                }
                if props.pub_key_props.bit_len().is_none() {
                    props.pub_key_props.set_bit_len(key_size_bits);
                }
            }
        });

        Ok(())
    }
}

/// Key deletion operations for RSA PKCS key pairs
impl KeyDeleteOp for RsaPkcsKeyPair {
    /// Delete the entire key pair (both public and private keys)
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut errors = Vec::new();

        // Try to delete private key first
        if let Err(e) = self.delete_priv_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Always try to delete public key
        if let Err(e) = self.delete_pub_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Return the first error if any occurred during actual deletion
        if let Some(error) = errors.first() {
            Err(*error)
        } else {
            Ok(())
        }
    }

    /// Delete only the public key (local storage only)
    fn delete_pub_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| {
            if inner.public_key.key_bytes().is_none() {
                Err(AZIHSM_KEY_NOT_INITIALIZED)?;
            }

            inner.public_key.properties_mut().pub_key = None;
            Ok(())
        })
    }

    /// Delete only the private key from the HSM
    fn delete_priv_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| {
            if inner.private_key.key_id().is_none() {
                Err(AZIHSM_KEY_NOT_INITIALIZED)?;
            }

            inner.private_key.properties_mut().priv_key_id = None;
            Ok(())
        })
    }
}

/// MGF1 mask generation function identifier enumeration for RSA operations.
///
/// This enum defines the supported mask generation functions used in RSA operations,
/// particularly for OAEP padding schemes. MGF1 is based on hash functions and provides
/// deterministic mask generation for cryptographic operations.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::FromRepr)]
pub enum AzihsmMgf1Id {
    /// MGF1 with SHA-256 hash function
    Sha256 = 1,

    /// MGF1 with SHA-384 hash function
    Sha384 = 2,

    /// MGF1 with SHA-512 hash function
    Sha512 = 3,
}

impl AzihsmMgf1Id {
    /// Convert AzihsmMgf1Id to AlgoId for hash algorithm operations
    pub fn to_algo_id(self) -> AlgoId {
        match self {
            AzihsmMgf1Id::Sha256 => AlgoId::Sha256,
            AzihsmMgf1Id::Sha384 => AlgoId::Sha384,
            AzihsmMgf1Id::Sha512 => AlgoId::Sha512,
        }
    }
}

//define Rsa Pkcs algo params struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPkcsOaepParams {
    pub hash_algo_id: AlgoId,
    pub mgf1_hash_algo_id: AzihsmMgf1Id,
    pub label: Option<Vec<u8>>,
}

// define RSA AES keywrap algo params struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaAesKeyWrapParams {
    pub aes_key_bits: u32,
    pub key_type: KeyKind,
    pub oaep_params: RsaPkcsOaepParams,
}
pub struct AlgoRsaAesKeyWrap {
    pub params: RsaAesKeyWrapParams,
}
impl Algo for AlgoRsaAesKeyWrap {}
impl KeyUnwrapOp<AlgoRsaAesKeyWrap> for RsaPkcsKeyPair {
    ///  Function to retrieve RSA wrapping key handle from session
    fn unwrap(
        &self,
        session: &Session,
        algo: &AlgoRsaAesKeyWrap,
        wrapped_key: &[u8],
        unwrapped_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError> {
        // check if key is empty
        if self.key_size().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?
        }

        let label = &algo.params.oaep_params.label;
        // Return Invalid param if AES key size is not 256
        if algo.params.aes_key_bits != 256 && algo.params.aes_key_bits != 128 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }
        // prepare ddi params and call ddi unwrap function
        // match MCR hash algo id
        let hash_algo = match algo.params.oaep_params.hash_algo_id {
            AlgoId::Sha256 => DdiHashAlgorithm::Sha256,
            AlgoId::Sha384 => DdiHashAlgorithm::Sha384,
            AlgoId::Sha512 => DdiHashAlgorithm::Sha512,
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };
        // get private key ID from the key pair
        let priv_key_id = self.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        // get key class
        let key_class = match algo.params.key_type {
            KeyKind::Aes => DdiKeyClass::Aes,
            KeyKind::Rsa => DdiKeyClass::Rsa,
            KeyKind::AesXts => DdiKeyClass::AesXtsBulk,
            KeyKind::Ec => DdiKeyClass::Ecc,

            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };
        // get key usage from unwrapped_key_props
        let has_encrypt = unwrapped_key_props.encrypt() == Some(true);
        let has_decrypt = unwrapped_key_props.decrypt() == Some(true);
        let has_sign = unwrapped_key_props.sign() == Some(true);
        let has_verify = unwrapped_key_props.verify() == Some(true);

        let has_encrypt_decrypt = has_encrypt || has_decrypt;
        let has_sign_verify = has_sign || has_verify;

        let key_usage = if has_encrypt_decrypt && has_sign_verify {
            // Keys with both encrypt/decrypt AND sign/verify capabilities are not supported
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?
        } else if has_encrypt_decrypt {
            DdiKeyUsage::EncryptDecrypt
        } else if has_sign_verify {
            DdiKeyUsage::SignVerify
        } else {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        };
        // get MCR DDI unwrapping key
        let ddi_params = DdiRsaUnwrapParams {
            key_id: priv_key_id.0,
            key_class,
            padding: DdiRsaCryptoPadding::Oaep,
            hash_algo,
            key_tag: None,
            label: label.as_ref().map(|l| l.to_vec()), // Convert &[u8] to Vec<u8>
            key_usage,
            key_availability: DdiKeyAvailability::App,
        };
        // call ddi layer
        let resp = ddi::rsa_unwrap_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_params,
            wrapped_key,
        )
        .map_err(|_| AZIHSM_RSA_UNWRAP_FAILED)?;
        //copy returned key id
        let key_id = KeyId(resp.data.key_id);
        Ok(key_id)
    }

    /// Function to get maximum unwrapped data length for RSA OAEP unwrapping
    ///
    /// This returns the maximum size of plaintext data that can be unwrapped
    /// from an RSA OAEP encrypted blob using this key. Note that the actual
    /// unwrap operation in the HSM creates a new key handle rather than
    /// returning the raw key material to the caller.
    fn unwrap_max_len(&self, hash_algo_id: AlgoId) -> Result<usize, AzihsmError> {
        // Get the RSA key size in bits from the key properties
        let key_size_bits = self.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // Convert to bytes
        let key_size_bytes = key_size_bits as usize / 8;

        // For RSA OAEP unwrapping, the maximum plaintext length depends on:
        // - RSA key size in bytes
        // - Hash function used (affects overhead)
        // - OAEP padding overhead
        //
        // Formula: max_plaintext_len = key_size_bytes - 2 * hash_len - 2
        let hash_len = match hash_algo_id {
            AlgoId::Sha256 => 32,
            AlgoId::Sha384 => 48,
            AlgoId::Sha512 => 64,
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };

        let oaep_overhead: usize = 2 * hash_len + 2;

        // Ensure we have enough space for the overhead
        if key_size_bytes <= oaep_overhead {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }

        let max_plaintext_len = key_size_bytes - oaep_overhead;

        Ok(max_plaintext_len)
    }
}

impl KeyWrapOp<AlgoRsaAesKeyWrap> for RsaPkcsKeyPair {
    /// Wrap user data using RSA AES Key Wrap
    fn wrap(
        &self,
        _session: &Session,
        algo: &AlgoRsaAesKeyWrap,
        user_data: &[u8],
        wrapped_data: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        // Check if key is initialized
        if self.key_size().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        // Get public key DER data
        let pub_key_der = self.pub_key().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let secret_key =
            GenericSecretKey::from_bytes(user_data).map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        // Import public key into azihsm_crypto
        let crypto_pub_key =
            RsaPublicKey::from_bytes(&pub_key_der).map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        // Convert hash algorithm to azihsm_crypto HashAlgo
        let hash = match algo.params.oaep_params.hash_algo_id {
            AlgoId::Sha256 => HashAlgo::sha256(),
            AlgoId::Sha384 => HashAlgo::sha384(),
            AlgoId::Sha512 => HashAlgo::sha512(),
            _ => Err(AZIHSM_RSA_UNSUPPORTED_HASH_ALGORITHM)?,
        };

        let wrap = RsaAesKeyWrap::new(hash, (algo.params.aes_key_bits / 8) as usize);

        // Perform the wrapping
        let len = wrap
            .wrap_key(&crypto_pub_key, &secret_key, Some(wrapped_data))
            .map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        Ok(len)
    }

    /// Get the required buffer length for wrapping user data
    fn wrap_len(
        &self,
        algo: &AlgoRsaAesKeyWrap,
        user_data_len: usize,
    ) -> Result<usize, AzihsmError> {
        // Check if key is initialized
        if self.key_size().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        let key = vec![0u8; user_data_len];
        // Get public key DER data
        let pub_key_der = self.pub_key().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let secret_key = GenericSecretKey::from_bytes(&key).map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        // Import public key into azihsm_crypto
        let crypto_pub_key =
            RsaPublicKey::from_bytes(&pub_key_der).map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        // Convert hash algorithm to azihsm_crypto HashAlgo
        let hash = match algo.params.oaep_params.hash_algo_id {
            AlgoId::Sha256 => HashAlgo::sha256(),
            AlgoId::Sha384 => HashAlgo::sha384(),
            AlgoId::Sha512 => HashAlgo::sha512(),
            _ => Err(AZIHSM_RSA_UNSUPPORTED_HASH_ALGORITHM)?,
        };

        let wrap = RsaAesKeyWrap::new(hash, (algo.params.aes_key_bits / 8) as usize);

        // Perform the wrapping
        let len = wrap
            .wrap_key(&crypto_pub_key, &secret_key, None)
            .map_err(|_| AZIHSM_RSA_CRYPTO_ERROR)?;

        Ok(len)
    }
}

pub struct RsaPkcs15Algo {
    pub algo_id: AlgoId,
}
impl Algo for RsaPkcs15Algo {}
impl RsaPkcs15Algo {
    const SHA1_ALGO_ID: [u8; 15] = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];

    const SHA256_ALGO_ID: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    const SHA384_ALGO_ID: [u8; 19] = [
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];

    const SHA512_ALGO_ID: [u8; 19] = [
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    pub fn new(algo_id: AlgoId) -> Self {
        RsaPkcs15Algo { algo_id }
    }
    pub fn get_hash_algo_id(&self) -> Result<AlgoId, AzihsmError> {
        match self.algo_id {
            AlgoId::RsaPkcsSha1 | AlgoId::RsaPkcsPssSha1 => Ok(AlgoId::Sha1),
            AlgoId::RsaPkcsSha256 | AlgoId::RsaPkcsPssSha256 => Ok(AlgoId::Sha256),
            AlgoId::RsaPkcsSha384 | AlgoId::RsaPkcsPssSha384 => Ok(AlgoId::Sha384),
            AlgoId::RsaPkcsSha512 | AlgoId::RsaPkcsPssSha512 => Ok(AlgoId::Sha512),
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED),
        }
    }

    fn get_pkcs1v15_digest_info_len(&self) -> Result<usize, AzihsmError> {
        let hash_algo_id = self.get_hash_algo_id()?;
        let digest_info_len = match hash_algo_id {
            AlgoId::Sha1 => Self::SHA1_ALGO_ID.len(), // SHA-1: 15 bytes DigestInfo
            AlgoId::Sha256 => Self::SHA256_ALGO_ID.len(), // SHA-256: 19 bytes DigestInfo
            AlgoId::Sha384 => Self::SHA384_ALGO_ID.len(), // SHA-384: 19 bytes DigestInfo
            AlgoId::Sha512 => Self::SHA512_ALGO_ID.len(), // SHA-512: 19 bytes DigestInfo
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };
        Ok(digest_info_len)
    }

    fn get_minimum_padded_digest_len(&self) -> Result<usize, AzihsmError> {
        let hash_algorithm = HashAlgo::try_from(self.algo_id)?;
        let hash_len = hash_algorithm.size();
        let digest_info_len = self.get_pkcs1v15_digest_info_len()?;

        // Minimum RSA key size for PKCS#1 v1.5: hash_len + digest_info_len + 11 bytes overhead
        // 11 bytes = 0x00(1) + 0x01(1) + PS(min 8 bytes of 0xFF) + 0x00(1)
        Ok(hash_len + digest_info_len + 11)
    }
    fn get_pkcs1v15_padded_digest(
        &self,
        data: &[u8],
        key_size_in_bytes: usize,
        padded_digest: &mut [u8],
    ) -> Result<u32, AzihsmError> {
        // Check if digest buffer is large enough for the RSA key size
        if padded_digest.len() < key_size_in_bytes {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Validate that the RSA key size is sufficient for this hash algorithm
        let min_required_size = self.get_minimum_padded_digest_len()?;
        if key_size_in_bytes < min_required_size {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }

        // Get hash algorithm instance
        let mut hash_algo = HashAlgo::try_from(self.algo_id)?;

        // Perform hashing on the input data
        let hash_len = hash_algo.size();
        let mut hash_output = vec![0u8; hash_len];
        Hasher::hash(&mut hash_algo, data, Some(&mut hash_output)).map_err(|crypto_error| {
            match crypto_error {
                azihsm_crypto::CryptoError::HashBufferTooSmall => AZIHSM_ERROR_INSUFFICIENT_BUFFER,
                _ => AZIHSM_INTERNAL_ERROR,
            }
        })?;

        // Get DigestInfo for the hash algorithm
        let hash_algo_id = self.get_hash_algo_id()?;
        let digest_info: &[u8] = match hash_algo_id {
            AlgoId::Sha1 => &Self::SHA1_ALGO_ID,
            AlgoId::Sha256 => &Self::SHA256_ALGO_ID,
            AlgoId::Sha384 => &Self::SHA384_ALGO_ID,
            AlgoId::Sha512 => &Self::SHA512_ALGO_ID,
            _ => Err(AZIHSM_OPERATION_NOT_SUPPORTED)?,
        };

        // Calculate the T length (DigestInfo + Hash)
        let t_len = digest_info.len() + hash_len;

        // PKCS#1 v1.5 padding structure: EM = 0x00 || 0x01 || PS || 0x00 || T
        // PS must be at least 8 bytes of 0xFF
        let ps_len = key_size_in_bytes - t_len - 3; // 3 = 0x00 + 0x01 + 0x00

        if ps_len < 8 {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }

        // Clear the buffer first
        padded_digest[..key_size_in_bytes].fill(0);

        // Build the padded digest: EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Hash
        let mut pos = 0;

        // 0x00
        padded_digest[pos] = 0x00;
        pos += 1;

        // 0x01
        padded_digest[pos] = 0x01;
        pos += 1;

        // PS (padding string of 0xFF bytes)
        for i in 0..ps_len {
            padded_digest[pos + i] = 0xFF;
        }
        pos += ps_len;

        // 0x00 separator
        padded_digest[pos] = 0x00;
        pos += 1;

        // DigestInfo
        padded_digest[pos..pos + digest_info.len()].copy_from_slice(digest_info);
        pos += digest_info.len();

        // Hash
        padded_digest[pos..pos + hash_len].copy_from_slice(&hash_output);

        Ok(key_size_in_bytes as u32)
    }
}
/// Implementation of RSA Key signing and verification operations
impl SignOp<RsaPkcsKeyPair> for RsaPkcs15Algo {
    ///returns maximum signature length for RSA key
    fn signature_len(&self, key: &RsaPkcsKeyPair) -> Result<u32, AzihsmError> {
        // The maximum signature length for RSA is the modulus size in bytes.
        // This is true for both PKCS#1 v1.5 and PSS paddings.
        let key_bits = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        Ok(key_bits.div_ceil(8))
    }

    fn sign(
        &self,
        session: &Session,
        key: &RsaPkcsKeyPair,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), AzihsmError> {
        // ensure private key ID exists
        if key.priv_key_id().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }
        if self.algo_id != AlgoId::RsaPkcsSha1
            && self.algo_id != AlgoId::RsaPkcsSha256
            && self.algo_id != AlgoId::RsaPkcsSha384
            && self.algo_id != AlgoId::RsaPkcsSha512
        {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }
        let key_size_bytes = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let key_size_bytes = key_size_bytes as usize / 8;

        //get private key id
        let priv_key_id = key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // Prepare padded digest
        let mut padded_digest = vec![0u8; key_size_bytes];
        self.get_pkcs1v15_padded_digest(data, key_size_bytes, &mut padded_digest)?;

        // Call DDI sign function
        let resp = ddi::rsa_sign(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            priv_key_id.0,
            &padded_digest,
        )
        .map_err(|_| AZIHSM_RSA_SIGN_FAILED)?;
        // Check if signature buffer is large enough
        if signature.len() < resp.data.x.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Copy the signature into the provided buffer
        signature[..resp.data.x.len()].copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

        Ok(())
    }
}

/// Implementation of RSA Key verify operation
impl VerifyOp<RsaPkcsKeyPair> for RsaPkcs15Algo {
    fn verify(
        &self,
        _session: &Session,
        key: &RsaPkcsKeyPair,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AzihsmError> {
        let key_size_bytes = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let key_size_bytes = key_size_bytes as usize / 8;

        // return error if signature length does not match key size
        if signature.len() != key_size_bytes {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Import Der pub key into crypto package
        let pub_key_der = key.pub_key().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let rsa_pub_key_handle =
            RsaPublicKey::from_bytes(&pub_key_der).map_err(|_| AZIHSM_RSA_INVALID_PUB_KEY)?;

        // get hash algo
        let hash_algo = HashAlgo::try_from(self.algo_id)?;
        // Perform RSA public key operation to verify signature

        let result = Verifier::verify(
            &mut RsaHashSignAlgo::with_pkcs1_padding(hash_algo),
            &rsa_pub_key_handle,
            data,
            signature,
        )
        .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        if !result {
            Err(AZIHSM_RSA_VERIFY_FAILED)?;
        }

        Ok(())
    }
}

// Implement RsaPkcsPssAlgo struct and its methods
pub struct RsaPkcsPssAlgo {
    pub algo_id: AlgoId,
    pub params: RsaPkcsPssParams,
}
pub struct RsaPkcsPssParams {
    pub hash_algo_id: AlgoId,
    pub mgf_id: AzihsmMgf1Id,
    pub salt_len: u32,
}

impl Algo for RsaPkcsPssAlgo {}

impl RsaPkcsPssAlgo {
    pub fn new(algo_id: AlgoId, params: RsaPkcsPssParams) -> Self {
        RsaPkcsPssAlgo { algo_id, params }
    }
}

/// Implement RsaPkcsPssAlgo helper methods
impl RsaPkcsPssAlgo {
    /// Encode message with Probabilistic Signature Scheme (PSS)
    ///
    /// Params:
    /// HashAlgo and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// em_bits: intended bit length of encoded message. Caller should set
    ///      this to key_size_in_bits - 1. Refer RFC 8017 Section 8.1.1
    ///      Step 1 for more.
    /// salt_len: intented length in octets of salt. If None, salt length
    ///      is chosen to be maximum allowable (equal to digest length).
    pub fn encode_pss(
        &self,
        data: &[u8],
        em_bits: usize,
        hash_algo: &mut HashAlgo,
        salt_len: u16,
        encoded_message: &mut [u8],
    ) -> Result<(), AzihsmError> {
        // em_len = ceil(em_bits/8)
        let em_len = em_bits.div_ceil(8);
        let h_len = hash_algo.size();

        // Handle salt_len = 0 as maximum allowable salt length (like DDI implementation)
        let s_len = if salt_len == 0 {
            // Maximum salt length for PSS is: k - h_len - 2
            // where k is the key size in bytes
            let max_salt = em_len - h_len - 2;
            std::cmp::min(max_salt, h_len) // Don't exceed hash length
        } else {
            salt_len as usize
        };

        // check if encoded_message buffer is large enough
        if encoded_message.len() < em_len {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }
        // Check salt length according to NIST.FIPS.186-5 Section 5.4 (g)
        // 0 <= s_len <= h_len
        if s_len > h_len {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        if em_len < h_len + s_len + 2 {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }

        let mut salt: Vec<u8> = vec![0; s_len];
        // get cryptographic random bytes for salt
        Rng::rand_bytes(salt.as_mut_slice()).map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        // Hash the message
        let m_hash = data.to_vec();

        let mut m_dash: Vec<u8> = vec![0; 8 + m_hash.len() + s_len];
        m_dash[8..8 + m_hash.len()].copy_from_slice(&m_hash);
        m_dash[8 + m_hash.len()..].copy_from_slice(&salt);
        //compute H = Hash(m_dash)
        let mut h: Vec<u8> = vec![0; h_len];
        Hasher::hash(hash_algo, &m_dash, Some(&mut h)).map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        let db_size = em_len - h_len - 1;
        let db = &mut encoded_message[0..db_size];
        db[db_size - s_len - 1] = 0x1;
        if s_len != 0 {
            db[db_size - s_len..].copy_from_slice(&salt);
        }
        let mut db_mask = vec![0u8; db_size];
        rsa_pkcs_pss_utils::mgf1(&h, db_size, hash_algo, &mut db_mask)?;
        rsa_pkcs_pss_utils::xor_slices(db, &db_mask);

        let n_zero_bits = 8 * em_len - em_bits;
        rsa_pkcs_pss_utils::zero_leftmost_x_bits(db, n_zero_bits);

        encoded_message[db_size..em_len - 1].copy_from_slice(&h);
        encoded_message[em_len - 1] = 0xbc;

        debug_assert!(encoded_message.len() == em_len);
        Ok(())
    }
}
/// Implementation of RSA Key verify operation
impl VerifyOp<RsaPkcsKeyPair> for RsaPkcsPssAlgo {
    fn verify(
        &self,
        _session: &Session,
        key: &RsaPkcsKeyPair,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AzihsmError> {
        let key_size_bytes = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let key_size_bytes = key_size_bytes as usize / 8;

        //return error if signature length does not match key size
        if signature.len() != key_size_bytes {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Import Der pub key into crypto package
        let pub_key_der = key.pub_key().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let rsa_pub_key_handle =
            RsaPublicKey::from_bytes(&pub_key_der).map_err(|_| AZIHSM_RSA_INVALID_PUB_KEY)?;
        // check if hash_algo_id matches with mgf1 hash algo id
        if self.params.hash_algo_id != self.params.mgf_id.to_algo_id() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        // get hash algo
        let hash_algo = HashAlgo::try_from(self.params.hash_algo_id)?;
        // Perform RSA public key operation to verify signature
        let result = Verifier::verify(
            &mut RsaHashSignAlgo::with_pss_padding(
                hash_algo.clone(),
                self.params.salt_len as usize,
            ),
            &rsa_pub_key_handle,
            data,
            signature,
        )
        .map_err(|_| AZIHSM_INTERNAL_ERROR)?;
        if !result {
            Err(AZIHSM_RSA_VERIFY_FAILED)?;
        }

        Ok(())
    }
}

impl SignOp<RsaPkcsKeyPair> for RsaPkcsPssAlgo {
    /// returns maximum signature length for RSA key
    fn signature_len(&self, key: &RsaPkcsKeyPair) -> Result<u32, AzihsmError> {
        // The maximum signature length for RSA is the modulus size in bytes.
        // This is true for both PKCS#1 v1.5 and PSS paddings.
        let key_bits = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        Ok(key_bits.div_ceil(8))
    }

    fn sign(
        &self,
        session: &Session,
        key: &RsaPkcsKeyPair,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), AzihsmError> {
        // ensure private key ID exists
        if key.priv_key_id().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }
        if self.algo_id != AlgoId::RsaPkcsPssSha1
            && self.algo_id != AlgoId::RsaPkcsPssSha256
            && self.algo_id != AlgoId::RsaPkcsPssSha384
            && self.algo_id != AlgoId::RsaPkcsPssSha512
        {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }

        let key_size_bytes = key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let key_size_bytes = key_size_bytes as usize / 8;

        //get private key id
        let priv_key_id = key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        // Hash the message and encode using PSS
        let mut hash_algo = HashAlgo::try_from(self.params.hash_algo_id)?;
        let mut hashed_data = vec![0u8; hash_algo.size()];
        Hasher::hash(&mut hash_algo, data, Some(&mut hashed_data))
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;
        // Prepare encoded message
        let em_bits = (key_size_bytes * 8) - 1;
        let mut encoded_message = vec![0u8; key_size_bytes];
        self.encode_pss(
            hashed_data.as_slice(),
            em_bits,
            &mut hash_algo,
            self.params.salt_len as u16,
            &mut encoded_message,
        )?;

        // Call DDI sign function
        let resp = ddi::rsa_sign(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            priv_key_id.0,
            &encoded_message,
        )
        .map_err(|_| AZIHSM_RSA_SIGN_FAILED)?;
        // Check if signature buffer is large enough
        if signature.len() < resp.data.x.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        // Copy the signature into the provided buffer
        signature.copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

        Ok(())
    }
}

/// Define RSA Encrypt/Decrypt structs
pub struct RsaPkcsOaepAlgo {
    pub id: AlgoId,
    pub params: RsaPkcsOaepParams,
}

/// Implement Algo trait for RsaPkcsOaepAlgo
impl Algo for RsaPkcsOaepAlgo {}

impl RsaPkcsOaepAlgo {
    /// Decode message with Optimal Asymmetric Encryption Padding (OAEP)
    ///
    /// Params:
    ///
    /// encoded_message: encoded_message
    /// key_size: size of RSA key in bytes
    /// digest_kind and hash_func: Hash function identifying enum and
    ///      hash function pointer respectively. Caller is responsible
    ///      for setting consistent values for the two parameters. Hash
    ///      function is used internally by encoding scheme.
    /// label: label to be associated with message. If label is None,
    ///      empty string is used as label.
    ///
    /// Errors: RsaError::InvalidParameter
    ///
    pub fn decode_oaep(
        encoded_message: &mut [u8],
        label: Option<&[u8]>,
        key_size: usize,
        hash_algo: &mut HashAlgo,
    ) -> Result<Vec<u8>, AzihsmError> {
        let h_len = hash_algo.size();

        // Compute L_hash = Hash(label) where label is the optional OAEP label
        let label_data = label.unwrap_or(b""); // Use empty string if no label provided
        let mut l_hash = vec![0u8; h_len];
        Hasher::hash(hash_algo, label_data, Some(&mut l_hash))
            .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

        {
            let masked_db = &encoded_message[h_len + 1..];
            // create seed mask
            let mut seed_mask = vec![0u8; h_len];
            rsa_pkcs_pss_utils::mgf1(masked_db, h_len, hash_algo, &mut seed_mask)?;
            let masked_seed = &mut encoded_message[1..h_len + 1];
            rsa_pkcs_pss_utils::xor_slices(masked_seed, seed_mask.as_slice());
        }

        {
            let seed = &encoded_message[1..h_len + 1];
            let mut db_mask = vec![0u8; key_size - h_len - 1];
            rsa_pkcs_pss_utils::mgf1(seed, key_size - h_len - 1, hash_algo, &mut db_mask)?;
            let masked_db = &mut encoded_message[h_len + 1..];
            rsa_pkcs_pss_utils::xor_slices(masked_db, db_mask.as_slice());
        }

        let db = &encoded_message[h_len + 1..];
        let _db_size = key_size - h_len - 1;
        let l_hash_em = &db[0..h_len];
        let label_mismatch = l_hash_em != l_hash;
        let em_msb_not_zero = encoded_message[0] != 0;
        let fixed_db_byte_idx = db.iter().skip(h_len).position(|&x| x == 0x01);
        let fixed_db_byte_not_found = fixed_db_byte_idx.is_none();

        // From RFC 8017 7.1.2: Care must be taken to ensure that an opponent cannot distinguish
        // the different error conditions in, whether by error message or timing..
        if label_mismatch || fixed_db_byte_not_found || em_msb_not_zero {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        }
        let fixed_db_byte_idx = fixed_db_byte_idx.ok_or(AZIHSM_ERROR_INVALID_ARGUMENT)?;
        let m = db[fixed_db_byte_idx + h_len + 1..].to_vec();
        Ok(m)
    }
}

impl EncryptOp<RsaPkcsKeyPair> for RsaPkcsOaepAlgo {
    fn encrypt(
        &mut self,
        _session: &Session,
        key: &RsaPkcsKeyPair,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        // return error if algoid is not OAEP
        if self.id != AlgoId::RsaPkcsOaep {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }
        // 1. Retrieve public key from the RsaPkcsKeyPair
        let public_key_der = key.pub_key().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // 2. Import public key into HSM Crypto support module as DDI doesn't support direct encrypt with public key
        let rsa_public_key_handle =
            RsaPublicKey::from_bytes(&public_key_der).map_err(|_| AZIHSM_RSA_INVALID_PUB_KEY)?;

        // 3. Perform RSA encryption using the imported key
        let hash_algo = HashAlgo::try_from(self.params.hash_algo_id)?;
        let label = self.params.label.as_deref();
        let len = Encrypter::encrypt(
            &mut RsaEncryptAlgo::with_oaep_padding(hash_algo, label),
            &rsa_public_key_handle,
            pt,
            Some(ct),
        )
        .map_err(|_| AZIHSM_OPERATION_NOT_SUPPORTED)?;

        Ok(len)
    }

    fn ciphertext_len(&self, _pt_len: usize) -> usize {
        // For RSA OAEP, the ciphertext length is equal to the RSA key size in bytes
        // Since we don't have the key size here, we cannot compute it directly.
        // The caller should ensure that the ciphertext buffer is large enough
        // to hold the RSA key size in bytes.
        // Indicate that the caller must determine the ciphertext length based on key size
        // return error if algoid is not RsaPkcsOaep
        0
    }
}
impl DecryptOp<RsaPkcsKeyPair> for RsaPkcsOaepAlgo {
    fn decrypt(
        &mut self,
        session: &Session,
        key: &RsaPkcsKeyPair,
        input_data: &[u8],
        output_buf: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        if self.id != AlgoId::RsaPkcsOaep {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }
        // For OAEP decryption, we need to call rsa_mod_exp with Decrypt operation
        let priv_key_id = key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        // get key size in bytes
        let key_size_bytes = (key.key_size().ok_or(AZIHSM_KEY_NOT_INITIALIZED)? / 8) as usize;
        // Validate input data length
        if input_data.len() < key_size_bytes {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?;
        }

        // Step 1: Perform raw RSA modular exponentiation via DDI layer
        let resp = ddi::rsa_decrypt(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            priv_key_id.0,
            input_data,
        )
        .map_err(|_| AZIHSM_OPERATION_NOT_SUPPORTED)?;

        // Step 2: Apply OAEP padding removal to get the plaintext message

        let mut hash_algo = HashAlgo::try_from(self.params.hash_algo_id)
            .map_err(|_| AZIHSM_OPERATION_NOT_SUPPORTED)?;

        let label = self.params.label.as_deref();

        // Step 2: Prepare raw decrypted data for OAEP processing
        // Create a buffer with the correct key size and copy only the actual data length
        let mut raw_decrypted = vec![0u8; key_size_bytes];
        let actual_data_len = resp.data.x.len();

        // Validate that DDI didn't return more data than expected
        if actual_data_len > key_size_bytes {
            Err(AZIHSM_INTERNAL_ERROR)?;
        }

        // Right-align the data (normal case when leading zeros stripped by DDI)
        let start_pos = key_size_bytes - actual_data_len;
        raw_decrypted[start_pos..].copy_from_slice(&resp.data.x.data()[..actual_data_len]); // The raw_decrypted buffer is now correctly sized for OAEP processing

        // Decode OAEP to extract the original message

        let plaintext_message =
            Self::decode_oaep(&mut raw_decrypted, label, key_size_bytes, &mut hash_algo)?;

        // Step 3: Copy the plaintext message to output buffer (check size after OAEP removal)
        if output_buf.len() < plaintext_message.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        output_buf[..plaintext_message.len()].copy_from_slice(&plaintext_message);

        // Securely clear the intermediate buffer
        raw_decrypted.fill(0);

        Ok(plaintext_message.len())
    }
    fn plaintext_len(&self, ct_len: usize) -> usize {
        // For RSA OAEP, the maximum plaintext length is:
        // key_size_bytes - 2 * hash_len - 2
        let key_size_bytes = ct_len; // ciphertext length = RSA key size in bytes

        let hash_len = match self.params.hash_algo_id {
            AlgoId::Sha256 => 32,
            AlgoId::Sha384 => 48,
            AlgoId::Sha512 => 64,
            _ => return 0, // Unsupported hash algorithm
        };

        let oaep_overhead = 2 * hash_len + 2;

        // Ensure we have enough space for the overhead
        if key_size_bytes <= oaep_overhead {
            return 0;
        }
        //return usize
        key_size_bytes - oaep_overhead
    }
}
