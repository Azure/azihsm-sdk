// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(unused_imports)]
#![allow(dead_code)]

use std::ffi::c_void;

use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::DdiKeyAvailability;
use mcr_ddi_types::DdiKeyProperties;
use mcr_ddi_types::DdiKeyUsage;
use strum::EnumCount;

use crate::AzihsmError;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;

/// Key property identifier enumeration.
///
/// This enum defines the various properties that can be associated with cryptographic keys
/// in the HSM. Each property has a unique identifier that is used to query or set specific
/// attributes of a key object.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::EnumCount, strum_macros::FromRepr)]
pub enum AzihsmKeyPropId {
    /// Key class property (e.g., Private, Public, Secret).
    /// Corresponds to AZIHSM_KEY_PROP_ID_CLASS
    Class = 1,

    /// Key kind property (e.g., RSA, ECC, AES).
    /// Corresponds to AZIHSM_KEY_PROP_ID_TYPE
    Kind = 2,

    /// Session handle associated with the key.
    /// Corresponds to AZIHSM_KEY_PROP_ID_SESSION
    Session = 3,

    /// Whether the key is private (boolean property).
    /// Corresponds to AZIHSM_KEY_PROP_ID_PRIVATE
    Private = 4,

    /// Whether the key can be modified after creation.
    /// Corresponds to AZIHSM_KEY_PROP_ID_MODIFIABLE
    Modifiable = 5,

    /// Whether the key can be copied.
    /// Corresponds to AZIHSM_KEY_PROP_ID_COPYABLE
    Copyable = 6,

    /// Whether the key can be destroyed.
    /// Corresponds to AZIHSM_KEY_PROP_ID_DESTROYABLE
    Destroyable = 7,

    /// Whether the key was generated locally in the HSM.
    /// Corresponds to AZIHSM_KEY_PROP_ID_LOCAL
    Local = 8,

    /// Whether the key is sensitive (cannot be revealed in plaintext).
    /// Corresponds to AZIHSM_KEY_PROP_ID_SENSITIVE
    Sensitive = 9,

    /// Whether the key has always been sensitive since creation.
    /// Corresponds to AZIHSM_KEY_PROP_ID_ALWAYS_SENSITIVE
    AlwaysSensitive = 10,

    /// Whether the key can be extracted from the HSM.
    /// Corresponds to AZIHSM_KEY_PROP_ID_EXTRACTABLE
    Extractable = 11,

    /// Whether the key has never been extractable since creation.
    /// Corresponds to AZIHSM_KEY_PROP_ID_NEVER_EXTRACTABLE
    NeverExtractable = 12,

    /// Whether the key is trusted for cryptographic operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_TRUSTED
    Trusted = 13,

    /// Whether the key can only be wrapped with trusted keys.
    /// Corresponds to AZIHSM_KEY_PROP_ID_WRAP_WITH_TRUSTED
    WrapWithTrusted = 14,

    /// Whether the key can be used for encryption operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_ENCRYPT
    Encrypt = 15,

    /// Whether the key can be used for decryption operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_DECRYPT
    Decrypt = 16,

    /// Whether the key can be used for signing operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_SIGN
    Sign = 17,

    /// Whether the key can be used for verification operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_VERIFY
    Verify = 18,

    /// Whether the key can be used for key wrapping operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_WRAP
    Wrap = 19,

    /// Whether the key can be used for key unwrapping operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_UNWRAP
    Unwrap = 20,

    /// Whether the key can be used for key derivation operations.
    /// Corresponds to AZIHSM_KEY_PROP_ID_DERIVE
    Derive = 21,

    /// Public key information associated with the key.
    /// Corresponds to AZIHSM_KEY_PROP_PUB_KEY_INFO
    PubKeyInfo = 22,

    /// Elliptic curve identifier for ECC keys.
    /// Corresponds to AZIHSM_KEY_PROP_ID_EC_CURVE
    EcCurve = 23,

    /// Whether the key is masked (protected by hardware).
    /// Corresponds to AZIHSM_KEY_PROP_ID_MASKED_KEY
    MaskedKey = 24,

    /// Bit length of the key.
    /// Corresponds to AZIHSM_KEY_PROP_ID_BIT_LEN
    BitLen = 25,

    /// Human-readable label for the key.
    /// Corresponds to AZIHSM_KEY_PROP_ID_LABEL
    Label = 26,
}

/// HSM key class enumeration.
///
/// This enum defines the different classes of cryptographic keys that can be managed
/// by the HSM. Each key class has specific characteristics and use cases:
///
/// - **Private keys**: Part of an asymmetric key pair, used for decryption and signing
/// - **Public keys**: Part of an asymmetric key pair, used for encryption and verification
/// - **Secret keys**: Symmetric keys used for encryption/decryption and MAC operations
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::FromRepr)]
pub enum AzihsmKeyClass {
    /// Private key class for asymmetric cryptography.
    ///
    /// Private keys are used for:
    /// - Decrypting data encrypted with the corresponding public key
    /// - Creating digital signatures
    /// - Key agreement protocols
    Private = 1,

    /// Public key class for asymmetric cryptography.
    ///
    /// Public keys are used for:
    /// - Encrypting data that can only be decrypted with the corresponding private key
    /// - Verifying digital signatures created with the corresponding private key
    /// - Key agreement protocols
    Public = 2,

    /// Secret key class for symmetric cryptography.
    ///
    /// Secret keys are used for:
    /// - Symmetric encryption and decryption
    /// - Message Authentication Codes (MACs)
    /// - Key derivation functions
    /// - HMAC operations
    Secret = 3,
}

/// Cryptographic key type enumeration.
///
/// This enum defines the specific cryptographic algorithms and key types supported
/// by the HSM. Each key type corresponds to a different cryptographic algorithm
/// or key usage pattern.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::FromRepr)]
pub enum KeyKind {
    /// RSA asymmetric key kind.
    ///
    /// RSA keys are used for:
    /// - Public key encryption and decryption
    /// - Digital signatures (PKCS#1, PSS)
    /// - Key transport and exchange
    Rsa = 1,

    /// Elliptic Curve (EC) asymmetric key kind.
    ///
    /// EC keys are used for:
    /// - Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// - Elliptic Curve Diffie-Hellman (ECDH) key agreement
    /// - More efficient public key operations compared to RSA
    Ec = 2,

    /// Advanced Encryption Standard (AES) symmetric key kind.
    ///
    /// AES keys are used for:
    /// - Symmetric block cipher encryption and decryption
    /// - Supports key sizes of 128, 192, and 256 bits
    /// - Various modes of operation (ECB, CBC, GCM, etc.)
    Aes = 3,

    /// AES-XTS (XEX-based tweaked-codebook mode) key kind.
    ///
    /// AES-XTS keys are used for:
    /// - Disk encryption and storage security
    /// - Sector-based encryption with tweaks
    /// - Prevents certain attacks on encrypted storage
    AesXts = 4,

    /// Generic key type for custom or non-standard algorithms.
    ///
    /// Generic keys are used for:
    /// - Custom cryptographic algorithms
    /// - Key material that doesn't fit standard categories
    /// - Raw key material for specialized operations
    Generic = 5,

    /// HMAC with SHA-1 hash function key kind.
    ///
    /// HMAC-SHA1 keys are used for:
    /// - Message authentication codes with SHA-1
    /// - Legacy systems requiring SHA-1 compatibility
    /// - Note: SHA-1 is considered cryptographically weak
    HmacSha1 = 6,

    /// HMAC with SHA-256 hash function key type.
    ///
    /// HMAC-SHA256 keys are used for:
    /// - Message authentication codes with SHA-256
    /// - Strong cryptographic hash-based authentication
    /// - Recommended for new implementations
    HmacSha256 = 7,

    /// HMAC with SHA-384 hash function key kind.
    ///
    /// HMAC-SHA384 keys are used for:
    /// - Message authentication codes with SHA-384
    /// - Higher security level than SHA-256
    /// - Part of the SHA-2 family
    HmacSha384 = 8,

    /// HMAC with SHA-512 hash function key kind.
    ///
    /// HMAC-SHA512 keys are used for:
    /// - Message authentication codes with SHA-512
    /// - Highest security level in SHA-2 family
    /// - Maximum hash output size of 512 bits
    HmacSha512 = 9,

    /// Masking key type for cryptographic protection.
    ///
    /// Masking keys are used for:
    /// - Protecting other keys through masking techniques
    Masking = 10,
}

/// Elliptic curve identifier enumeration for ECC keys.
///
/// This enum defines the supported elliptic curves for Elliptic Curve Cryptography (ECC)
/// operations in the HSM. Each curve represents a different security level and performance
/// characteristic.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum_macros::FromRepr)]
pub enum EcCurve {
    /// NIST P-256 curve (secp256r1)
    P256 = 1,

    /// NIST P-384 curve (secp384r1)
    P384 = 2,

    /// NIST P-521 curve (secp521r1)
    P521 = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyPropValue {
    None,
    Boolean(bool),
    KeyClass(AzihsmKeyClass),
    KeyType(KeyKind),
    String(String),
    EcCurve(EcCurve),
    BitLen(u32),
}

#[derive(Debug, Clone)]
pub struct KeyProps {
    props: [KeyPropValue; AzihsmKeyPropId::COUNT + 1],
}

impl KeyProps {
    pub(crate) fn new() -> Self {
        KeyProps {
            props: std::array::from_fn(|_| KeyPropValue::None.clone()),
        }
    }

    pub fn class(&self) -> Option<AzihsmKeyClass> {
        match &self.props[AzihsmKeyPropId::Class as usize] {
            KeyPropValue::KeyClass(class) => Some(*class),
            _ => None,
        }
    }

    pub(crate) fn set_class(&mut self, class: AzihsmKeyClass) {
        self.props[AzihsmKeyPropId::Class as usize] = KeyPropValue::KeyClass(class);
    }

    pub fn kind(&self) -> Option<KeyKind> {
        match &self.props[AzihsmKeyPropId::Kind as usize] {
            KeyPropValue::KeyType(kind) => Some(*kind),
            _ => None,
        }
    }

    pub(crate) fn set_kind(&mut self, kind: KeyKind) {
        self.props[AzihsmKeyPropId::Kind as usize] = KeyPropValue::KeyType(kind);
    }

    pub fn session(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Session as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_session(&mut self, session: bool) {
        self.props[AzihsmKeyPropId::Session as usize] = KeyPropValue::Boolean(session);
    }

    pub fn private(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Private as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_private(&mut self, private: bool) {
        self.props[AzihsmKeyPropId::Private as usize] = KeyPropValue::Boolean(private);
    }

    pub fn modifiable(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Modifiable as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_modifiable(&mut self, modifiable: bool) {
        self.props[AzihsmKeyPropId::Modifiable as usize] = KeyPropValue::Boolean(modifiable);
    }

    pub fn copyable(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Copyable as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_copyable(&mut self, copyable: bool) {
        self.props[AzihsmKeyPropId::Copyable as usize] = KeyPropValue::Boolean(copyable);
    }

    pub fn destroyable(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Destroyable as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_destroyable(&mut self, destroyable: bool) {
        self.props[AzihsmKeyPropId::Destroyable as usize] = KeyPropValue::Boolean(destroyable);
    }

    pub fn local(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Local as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_local(&mut self, local: bool) {
        self.props[AzihsmKeyPropId::Local as usize] = KeyPropValue::Boolean(local);
    }

    pub fn sensitive(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Sensitive as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_sensitive(&mut self, sensitive: bool) {
        self.props[AzihsmKeyPropId::Sensitive as usize] = KeyPropValue::Boolean(sensitive);
    }

    pub fn always_sensitive(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::AlwaysSensitive as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_always_sensitive(&mut self, always_sensitive: bool) {
        self.props[AzihsmKeyPropId::AlwaysSensitive as usize] =
            KeyPropValue::Boolean(always_sensitive);
    }

    pub fn extractable(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Extractable as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_extractable(&mut self, extractable: bool) {
        self.props[AzihsmKeyPropId::Extractable as usize] = KeyPropValue::Boolean(extractable);
    }

    pub fn never_extractable(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::NeverExtractable as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_never_extractable(&mut self, never_extractable: bool) {
        self.props[AzihsmKeyPropId::NeverExtractable as usize] =
            KeyPropValue::Boolean(never_extractable);
    }

    pub fn trusted(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Trusted as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_trusted(&mut self, trusted: bool) {
        self.props[AzihsmKeyPropId::Trusted as usize] = KeyPropValue::Boolean(trusted);
    }

    pub fn wrap_with_trusted(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::WrapWithTrusted as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_wrap_with_trusted(&mut self, wrap_with_trusted: bool) {
        self.props[AzihsmKeyPropId::WrapWithTrusted as usize] =
            KeyPropValue::Boolean(wrap_with_trusted);
    }

    pub fn encrypt(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Encrypt as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_encrypt(&mut self, encrypt: bool) {
        self.props[AzihsmKeyPropId::Encrypt as usize] = KeyPropValue::Boolean(encrypt);
    }

    pub fn decrypt(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Decrypt as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_decrypt(&mut self, decrypt: bool) {
        self.props[AzihsmKeyPropId::Decrypt as usize] = KeyPropValue::Boolean(decrypt);
    }

    pub fn sign(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Sign as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_sign(&mut self, sign: bool) {
        self.props[AzihsmKeyPropId::Sign as usize] = KeyPropValue::Boolean(sign);
    }

    pub fn verify(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Verify as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_verify(&mut self, verify: bool) {
        self.props[AzihsmKeyPropId::Verify as usize] = KeyPropValue::Boolean(verify);
    }

    pub fn wrap(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Wrap as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_wrap(&mut self, wrap: bool) {
        self.props[AzihsmKeyPropId::Wrap as usize] = KeyPropValue::Boolean(wrap);
    }

    pub fn unwrap(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Unwrap as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_unwrap(&mut self, unwrap: bool) {
        self.props[AzihsmKeyPropId::Unwrap as usize] = KeyPropValue::Boolean(unwrap);
    }

    pub fn derive(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Derive as usize] {
            KeyPropValue::Boolean(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_derive(&mut self, derive: bool) {
        self.props[AzihsmKeyPropId::Derive as usize] = KeyPropValue::Boolean(derive);
    }

    pub fn ecc_curve(&self) -> Option<EcCurve> {
        match &self.props[AzihsmKeyPropId::EcCurve as usize] {
            KeyPropValue::EcCurve(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_ecc_curve(&mut self, curve: EcCurve) {
        self.props[AzihsmKeyPropId::EcCurve as usize] = KeyPropValue::EcCurve(curve);
    }

    pub fn bit_len(&self) -> Option<u32> {
        match &self.props[AzihsmKeyPropId::BitLen as usize] {
            KeyPropValue::BitLen(val) => Some(*val),
            _ => None,
        }
    }
    pub(crate) fn set_bit_len(&mut self, bit_len: u32) {
        self.props[AzihsmKeyPropId::BitLen as usize] = KeyPropValue::BitLen(bit_len);
    }

    pub fn label(&self) -> Option<&String> {
        match &self.props[AzihsmKeyPropId::Label as usize] {
            KeyPropValue::String(val) => Some(val),
            _ => None,
        }
    }

    pub(crate) fn set_label(&mut self, label: String) {
        self.props[AzihsmKeyPropId::Label as usize] = KeyPropValue::String(label);
    }
}

/// Builder for constructing `KeyProps` with a fluent API.
///
/// This builder allows for easy construction of key properties by chaining method calls.
/// It provides a more ergonomic way to create key properties compared to manually setting
/// each property individually.
pub struct KeyPropsBuilder {
    props: KeyProps,
}

impl KeyProps {
    /// Creates a new builder for constructing `KeyProps`.
    ///
    /// # Returns
    ///
    /// A new `KeyPropsBuilder` instance with default values.
    pub fn builder() -> KeyPropsBuilder {
        KeyPropsBuilder {
            props: KeyProps::new(),
        }
    }
}

impl KeyPropsBuilder {
    /// Sets whether the key is a session key.
    ///
    /// # Arguments
    ///
    /// * `session` - True if the key is a session key
    pub fn session(mut self, session: bool) -> Self {
        self.props.set_session(session);
        self
    }

    /// Sets whether the key is modifiable.
    ///
    /// # Arguments
    ///
    /// * `modifiable` - True if the key can be modified
    pub fn modifiable(mut self, modifiable: bool) -> Self {
        self.props.set_modifiable(modifiable);
        self
    }

    /// Sets whether the key can be used for encryption.
    ///
    /// # Arguments
    ///
    /// * `encrypt` - True if the key can be used for encryption
    pub fn encrypt(mut self, encrypt: bool) -> Self {
        self.props.set_encrypt(encrypt);
        self
    }

    /// Sets whether the key can be used for decryption.
    ///
    /// # Arguments
    ///
    /// * `decrypt` - True if the key can be used for decryption
    pub fn decrypt(mut self, decrypt: bool) -> Self {
        self.props.set_decrypt(decrypt);
        self
    }

    /// Sets whether the key can be used for signing.
    ///
    /// # Arguments
    ///
    /// * `sign` - True if the key can be used for signing
    pub fn sign(mut self, sign: bool) -> Self {
        self.props.set_sign(sign);
        self
    }

    /// Sets whether the key can be used for verification.
    ///
    /// # Arguments
    ///
    /// * `verify` - True if the key can be used for verification
    pub fn verify(mut self, verify: bool) -> Self {
        self.props.set_verify(verify);
        self
    }

    /// Sets whether the key can be used for key wrapping.
    ///
    /// # Arguments
    ///
    /// * `wrap` - True if the key can be used for key wrapping
    pub fn wrap(mut self, wrap: bool) -> Self {
        self.props.set_wrap(wrap);
        self
    }

    /// Sets whether the key can be used for key unwrapping.
    ///
    /// # Arguments
    ///
    /// * `unwrap` - True if the key can be used for key unwrapping
    pub fn unwrap(mut self, unwrap: bool) -> Self {
        self.props.set_unwrap(unwrap);
        self
    }

    /// Sets whether the key can be used for key derivation.
    ///
    /// # Arguments
    ///
    /// * `derive` - True if the key can be used for key derivation
    pub fn derive(mut self, derive: bool) -> Self {
        self.props.set_derive(derive);
        self
    }

    /// Sets the elliptic curve for ECC keys.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve to use (e.g., P-256, P-384, P-521)
    pub fn ecc_curve(mut self, curve: EcCurve) -> Self {
        self.props.set_ecc_curve(curve);
        self
    }

    /// Sets the bit length of the key.
    ///
    /// # Arguments
    ///
    /// * `bit_len` - The bit length of the key (e.g., 2048 for RSA, 256 for AES)
    pub fn bit_len(mut self, bit_len: u32) -> Self {
        self.props.set_bit_len(bit_len);
        self
    }

    /// Sets the label for the key.
    ///
    /// # Arguments
    ///
    /// * `label` - A human-readable label for the key
    pub fn label(mut self, label: String) -> Self {
        self.props.set_label(label);
        self
    }

    /// Builds the final `KeyProps` instance.
    ///
    /// # Returns
    ///
    /// The constructed `KeyProps` instance with all the specified properties.
    pub fn build(self) -> KeyProps {
        self.props
    }
}

impl TryFrom<&KeyProps> for DdiKeyProperties {
    type Error = AzihsmError;

    fn try_from(props: &KeyProps) -> Result<Self, Self::Error> {
        // Determine key usage based on individual operation flags
        let key_usage = if props.encrypt().unwrap_or(false) || props.decrypt().unwrap_or(false) {
            DdiKeyUsage::EncryptDecrypt
        } else if props.sign().unwrap_or(false) || props.verify().unwrap_or(false) {
            DdiKeyUsage::SignVerify
        } else if props.wrap().unwrap_or(false) || props.unwrap().unwrap_or(false) {
            DdiKeyUsage::Unwrap
        } else {
            DdiKeyUsage::EncryptDecrypt // Default when no operations are specified
        };

        // Determine key availability - default to App if not specified
        let key_availability = if props.session().unwrap_or(false) {
            DdiKeyAvailability::Session
        } else {
            DdiKeyAvailability::App
        };

        // Convert label to MborByteArray
        let label = props.label().cloned().unwrap_or_else(|| "".to_string());
        let label_bytes = label.as_bytes();
        let key_label = match MborByteArray::from_slice(label_bytes) {
            Ok(arr) => arr,
            Err(_) => Err(AZIHSM_ILLEGAL_KEY_PROPERTY)?,
        };

        Ok(DdiKeyProperties {
            key_usage,
            key_availability,
            key_label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_props_new() {
        let props = KeyProps::new();

        // All properties should be None initially
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
        assert_eq!(props.session(), None);
        assert_eq!(props.private(), None);
        assert_eq!(props.modifiable(), None);
        assert_eq!(props.copyable(), None);
        assert_eq!(props.destroyable(), None);
        assert_eq!(props.local(), None);
        assert_eq!(props.sensitive(), None);
        assert_eq!(props.always_sensitive(), None);
        assert_eq!(props.extractable(), None);
        assert_eq!(props.never_extractable(), None);
        assert_eq!(props.trusted(), None);
        assert_eq!(props.wrap_with_trusted(), None);
        assert_eq!(props.encrypt(), None);
        assert_eq!(props.decrypt(), None);
        assert_eq!(props.sign(), None);
        assert_eq!(props.verify(), None);
        assert_eq!(props.wrap(), None);
        assert_eq!(props.unwrap(), None);
        assert_eq!(props.derive(), None);
        assert_eq!(props.bit_len(), None);
        assert_eq!(props.label(), None);
    }

    #[test]
    fn test_key_props_setters_and_getters() {
        let mut props = KeyProps::new();

        // Test class
        props.set_class(AzihsmKeyClass::Private);
        assert_eq!(props.class(), Some(AzihsmKeyClass::Private));

        // Test kind
        props.set_kind(KeyKind::Rsa);
        assert_eq!(props.kind(), Some(KeyKind::Rsa));

        // Test boolean properties
        props.set_session(true);
        assert_eq!(props.session(), Some(true));

        props.set_private(false);
        assert_eq!(props.private(), Some(false));

        props.set_modifiable(true);
        assert_eq!(props.modifiable(), Some(true));

        props.set_copyable(false);
        assert_eq!(props.copyable(), Some(false));

        props.set_destroyable(true);
        assert_eq!(props.destroyable(), Some(true));

        props.set_local(false);
        assert_eq!(props.local(), Some(false));

        props.set_sensitive(true);
        assert_eq!(props.sensitive(), Some(true));

        props.set_always_sensitive(false);
        assert_eq!(props.always_sensitive(), Some(false));

        props.set_extractable(true);
        assert_eq!(props.extractable(), Some(true));

        props.set_never_extractable(false);
        assert_eq!(props.never_extractable(), Some(false));

        props.set_trusted(true);
        assert_eq!(props.trusted(), Some(true));

        props.set_wrap_with_trusted(false);
        assert_eq!(props.wrap_with_trusted(), Some(false));

        props.set_encrypt(true);
        assert_eq!(props.encrypt(), Some(true));

        props.set_decrypt(false);
        assert_eq!(props.decrypt(), Some(false));

        props.set_sign(true);
        assert_eq!(props.sign(), Some(true));

        props.set_verify(false);
        assert_eq!(props.verify(), Some(false));

        props.set_wrap(true);
        assert_eq!(props.wrap(), Some(true));

        props.set_unwrap(false);
        assert_eq!(props.unwrap(), Some(false));

        props.set_derive(true);
        assert_eq!(props.derive(), Some(true));

        // Test numeric property
        props.set_bit_len(2048);
        assert_eq!(props.bit_len(), Some(2048));

        // Test string property
        props.set_label("Test Key".to_string());
        assert_eq!(props.label(), Some(&"Test Key".to_string()));
    }

    #[test]
    fn test_key_class_enum() {
        assert_eq!(AzihsmKeyClass::Private as u32, 1);
        assert_eq!(AzihsmKeyClass::Public as u32, 2);
        assert_eq!(AzihsmKeyClass::Secret as u32, 3);
    }

    #[test]
    fn test_key_kind_enum() {
        assert_eq!(KeyKind::Rsa as u32, 1);
        assert_eq!(KeyKind::Ec as u32, 2);
        assert_eq!(KeyKind::Aes as u32, 3);
        assert_eq!(KeyKind::AesXts as u32, 4);
        assert_eq!(KeyKind::Generic as u32, 5);
        assert_eq!(KeyKind::HmacSha1 as u32, 6);
        assert_eq!(KeyKind::HmacSha256 as u32, 7);
        assert_eq!(KeyKind::HmacSha384 as u32, 8);
        assert_eq!(KeyKind::HmacSha512 as u32, 9);
        assert_eq!(KeyKind::Masking as u32, 10);
    }

    #[test]
    fn test_key_prop_id_enum() {
        assert_eq!(AzihsmKeyPropId::Class as u32, 1);
        assert_eq!(AzihsmKeyPropId::Kind as u32, 2);
        assert_eq!(AzihsmKeyPropId::Session as u32, 3);
        assert_eq!(AzihsmKeyPropId::Private as u32, 4);
        assert_eq!(AzihsmKeyPropId::Label as u32, 26);

        // Test enum count
        assert_eq!(AzihsmKeyPropId::COUNT, 26);
    }

    #[test]
    fn test_from_repr_key_class() {
        assert_eq!(AzihsmKeyClass::from_repr(1), Some(AzihsmKeyClass::Private));
        assert_eq!(AzihsmKeyClass::from_repr(2), Some(AzihsmKeyClass::Public));
        assert_eq!(AzihsmKeyClass::from_repr(3), Some(AzihsmKeyClass::Secret));
        assert_eq!(AzihsmKeyClass::from_repr(999), None);
    }

    #[test]
    fn test_from_repr_key_kind() {
        assert_eq!(KeyKind::from_repr(1), Some(KeyKind::Rsa));
        assert_eq!(KeyKind::from_repr(2), Some(KeyKind::Ec));
        assert_eq!(KeyKind::from_repr(3), Some(KeyKind::Aes));
        assert_eq!(KeyKind::from_repr(999), None);
    }

    #[test]
    fn test_from_repr_key_prop_id() {
        assert_eq!(AzihsmKeyPropId::from_repr(1), Some(AzihsmKeyPropId::Class));
        assert_eq!(AzihsmKeyPropId::from_repr(2), Some(AzihsmKeyPropId::Kind));
        assert_eq!(AzihsmKeyPropId::from_repr(26), Some(AzihsmKeyPropId::Label));
        assert_eq!(AzihsmKeyPropId::from_repr(999), None);
    }

    #[test]
    fn test_builder_pattern() {
        let props = KeyProps::builder()
            .bit_len(2048)
            .encrypt(true)
            .decrypt(true)
            .sign(true)
            .verify(false)
            .label("RSA Private Key".to_string())
            .build();

        // Only test settable properties via builder
        assert_eq!(props.bit_len(), Some(2048));
        assert_eq!(props.encrypt(), Some(true));
        assert_eq!(props.decrypt(), Some(true));
        assert_eq!(props.sign(), Some(true));
        assert_eq!(props.verify(), Some(false));
        assert_eq!(props.label(), Some(&"RSA Private Key".to_string()));

        // Non-settable properties should be None
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
        assert_eq!(props.sensitive(), None);
        assert_eq!(props.extractable(), None);
    }

    #[test]
    fn test_builder_chaining() {
        let builder = KeyProps::builder();
        let builder = builder.session(true);
        let builder = builder.bit_len(256);
        let props = builder.build();

        assert_eq!(props.session(), Some(true));
        assert_eq!(props.bit_len(), Some(256));

        // Non-settable properties should be None
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
    }

    #[test]
    fn test_settable_properties_only() {
        let props = KeyProps::builder()
            .session(false)
            .modifiable(true)
            .encrypt(true)
            .decrypt(true)
            .sign(false)
            .verify(true)
            .wrap(false)
            .unwrap(true)
            .derive(false)
            .bit_len(256)
            .label("AES-256 Key".to_string())
            .build();

        // Test only settable properties
        assert_eq!(props.session(), Some(false));
        assert_eq!(props.modifiable(), Some(true));
        assert_eq!(props.encrypt(), Some(true));
        assert_eq!(props.decrypt(), Some(true));
        assert_eq!(props.sign(), Some(false));
        assert_eq!(props.verify(), Some(true));
        assert_eq!(props.wrap(), Some(false));
        assert_eq!(props.unwrap(), Some(true));
        assert_eq!(props.derive(), Some(false));
        assert_eq!(props.bit_len(), Some(256));
        assert_eq!(props.label(), Some(&"AES-256 Key".to_string()));

        // Non-settable properties should be None
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
        assert_eq!(props.private(), None);
        assert_eq!(props.copyable(), None);
        assert_eq!(props.destroyable(), None);
        assert_eq!(props.local(), None);
        assert_eq!(props.sensitive(), None);
        assert_eq!(props.always_sensitive(), None);
        assert_eq!(props.extractable(), None);
        assert_eq!(props.never_extractable(), None);
        assert_eq!(props.trusted(), None);
        assert_eq!(props.wrap_with_trusted(), None);
    }

    #[test]
    fn test_direct_property_setting() {
        // Test direct property setting (used internally, not via builder)
        let mut props = KeyProps::new();

        // Set non-settable properties directly
        props.set_class(AzihsmKeyClass::Secret);
        props.set_kind(KeyKind::Aes);
        props.set_private(false);
        props.set_copyable(false);
        props.set_destroyable(true);
        props.set_local(true);
        props.set_sensitive(true);
        props.set_always_sensitive(true);
        props.set_extractable(false);
        props.set_never_extractable(true);
        props.set_trusted(false);
        props.set_wrap_with_trusted(false);

        // Set settable properties
        props.set_session(false);
        props.set_modifiable(false);
        props.set_encrypt(true);
        props.set_decrypt(true);
        props.set_bit_len(256);
        props.set_label("Test AES Key".to_string());

        // Verify all properties
        assert_eq!(props.class(), Some(AzihsmKeyClass::Secret));
        assert_eq!(props.kind(), Some(KeyKind::Aes));
        assert_eq!(props.private(), Some(false));
        assert_eq!(props.copyable(), Some(false));
        assert_eq!(props.destroyable(), Some(true));
        assert_eq!(props.local(), Some(true));
        assert_eq!(props.sensitive(), Some(true));
        assert_eq!(props.always_sensitive(), Some(true));
        assert_eq!(props.extractable(), Some(false));
        assert_eq!(props.never_extractable(), Some(true));
        assert_eq!(props.trusted(), Some(false));
        assert_eq!(props.wrap_with_trusted(), Some(false));
        assert_eq!(props.session(), Some(false));
        assert_eq!(props.modifiable(), Some(false));
        assert_eq!(props.encrypt(), Some(true));
        assert_eq!(props.decrypt(), Some(true));
        assert_eq!(props.bit_len(), Some(256));
        assert_eq!(props.label(), Some(&"Test AES Key".to_string()));
    }

    #[test]
    fn test_bit_len_string_conversion() {
        let mut props = KeyProps::new();

        // Test various bit lengths
        props.set_bit_len(128);
        assert_eq!(props.bit_len(), Some(128));

        props.set_bit_len(256);
        assert_eq!(props.bit_len(), Some(256));

        props.set_bit_len(2048);
        assert_eq!(props.bit_len(), Some(2048));

        props.set_bit_len(4096);
        assert_eq!(props.bit_len(), Some(4096));
    }

    #[test]
    fn test_empty_builder() {
        let props = KeyProps::builder().build();

        // Should be equivalent to KeyProps::new()
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
        assert_eq!(props.bit_len(), None);
        assert_eq!(props.label(), None);
    }

    #[test]
    fn test_partial_builder() {
        let props = KeyProps::builder().encrypt(true).bit_len(2048).build();

        assert_eq!(props.encrypt(), Some(true));
        assert_eq!(props.bit_len(), Some(2048));

        // Other properties should remain None
        assert_eq!(props.class(), None);
        assert_eq!(props.kind(), None);
        assert_eq!(props.decrypt(), None);
        assert_eq!(props.label(), None);
    }

    #[test]
    fn test_key_prop_value_clone() {
        let value1 = KeyPropValue::Boolean(true);
        let value2 = value1.clone();
        assert_eq!(value1, value2);

        let value3 = KeyPropValue::KeyClass(AzihsmKeyClass::Private);
        let value4 = value3.clone();
        assert_eq!(value3, value4);

        let value5 = KeyPropValue::String("test".to_string());
        let value6 = value5.clone();
        assert_eq!(value5, value6);
    }

    #[test]
    fn test_comprehensive_key_scenario() {
        // Test a comprehensive scenario with mixed settable/non-settable properties
        let mut props = KeyProps::new();

        // Set non-settable properties
        props.set_class(AzihsmKeyClass::Private);
        props.set_kind(KeyKind::Rsa);
        props.set_private(true);
        props.set_copyable(false);
        props.set_destroyable(true);
        props.set_local(true);
        props.set_sensitive(true);
        props.set_always_sensitive(true);
        props.set_extractable(false);
        props.set_never_extractable(true);
        props.set_trusted(true);
        props.set_wrap_with_trusted(true);

        // Set settable properties (user configurable)
        props.set_session(false);
        props.set_modifiable(false);
        props.set_encrypt(false); // Private key typically doesn't encrypt
        props.set_decrypt(true);
        props.set_sign(true);
        props.set_verify(false); // Private key typically doesn't verify
        props.set_wrap(false);
        props.set_unwrap(true);
        props.set_derive(false);
        props.set_bit_len(2048);
        props.set_label("Production RSA-2048 Private Key".to_string());

        // Verify all properties
        assert_eq!(props.class(), Some(AzihsmKeyClass::Private));
        assert_eq!(props.kind(), Some(KeyKind::Rsa));
        assert_eq!(props.bit_len(), Some(2048));
        assert_eq!(props.private(), Some(true));
        assert_eq!(props.sensitive(), Some(true));
        assert_eq!(props.always_sensitive(), Some(true));
        assert_eq!(props.extractable(), Some(false));
        assert_eq!(props.never_extractable(), Some(true));
        assert_eq!(props.local(), Some(true));
        assert_eq!(props.modifiable(), Some(false));
        assert_eq!(props.copyable(), Some(false));
        assert_eq!(props.destroyable(), Some(true));
        assert_eq!(props.trusted(), Some(true));
        assert_eq!(props.wrap_with_trusted(), Some(true));
        assert_eq!(props.encrypt(), Some(false));
        assert_eq!(props.decrypt(), Some(true));
        assert_eq!(props.sign(), Some(true));
        assert_eq!(props.verify(), Some(false));
        assert_eq!(props.wrap(), Some(false));
        assert_eq!(props.unwrap(), Some(true));
        assert_eq!(props.derive(), Some(false));
        assert_eq!(
            props.label(),
            Some(&"Production RSA-2048 Private Key".to_string())
        );
    }
}
