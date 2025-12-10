// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(unused_imports)]
#![allow(dead_code)]

use std::ffi::c_void;

use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::DdiKeyAvailability;
use mcr_ddi_types::DdiKeyProperties;
use mcr_ddi_types::DdiKeyUsage;
use mcr_ddi_types::MaskedKey;
use strum::EnumCount;

use crate::crypto::Key;
use crate::AzihsmError;
use crate::HandleType;
use crate::Session;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY_OPERATION;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

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

impl TryFrom<u32> for KeyKind {
    type Error = AzihsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or(AZIHSM_ERROR_INVALID_ARGUMENT)
    }
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
pub enum KeyPropValue {
    None,
    Boolean(bool),
    KeyClass(AzihsmKeyClass),
    KeyType(KeyKind),
    IsSessionKey(bool), //Flag indicating if the key is a session key
    Modifiable(bool),
    Copyable(bool),
    Destroyable(bool),
    Local(bool),
    Sensitive(bool),
    AlwaysSensitive(bool),
    Extractable(bool),
    NeverExtractable(bool),
    Trusted(bool),
    WrapWithTrusted(bool),
    Encrypt(bool),
    Decrypt(bool),
    Sign(bool),
    Verify(bool),
    Wrap(bool),
    Unwrap(bool),
    Derive(bool),
    PubKeyInfo(Vec<u8>),
    EcCurve(EcCurve),
    MaskedKey(Vec<u8>),
    BitLen(u32),
    Label(String),
    String(String),
}

// Helper macros for serialization

/// Macro to write boolean value to buffer
macro_rules! write_bool_to_buffer {
    ($buffer:expr, $value:expr) => {{
        if $buffer.is_empty() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
        }
        $buffer[0] = if $value { 1 } else { 0 };
        Ok(1)
    }};
}

/// Macro to write u32 value to buffer
macro_rules! write_u32_to_buffer {
    ($buffer:expr, $value:expr) => {{
        if $buffer.len() < std::mem::size_of::<u32>() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
        }
        let bytes = $value.to_ne_bytes();
        $buffer[..4].copy_from_slice(&bytes);
        Ok(4)
    }};
}

/// Macro to write enum (as u32) to buffer
macro_rules! write_enum_to_buffer {
    ($buffer:expr, $enum_val:expr) => {{
        if $buffer.len() < std::mem::size_of::<u32>() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
        }
        let bytes = ($enum_val as u32).to_ne_bytes();
        $buffer[..4].copy_from_slice(&bytes);
        Ok(4)
    }};
}

// Helper macros for deserialization

/// Macro to read boolean value from buffer
macro_rules! read_bool_from_buffer {
    ($data:expr) => {{
        if $data.is_empty() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }
        $data[0] != 0
    }};
}

/// Macro to read u32 value from buffer
macro_rules! read_u32_from_buffer {
    ($data:expr) => {{
        if $data.len() < std::mem::size_of::<u32>() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }
        u32::from_ne_bytes([$data[0], $data[1], $data[2], $data[3]])
    }};
}

/// Macro to read enum from buffer
macro_rules! read_enum_from_buffer {
    ($data:expr, $enum_type:ty) => {{
        if $data.len() < std::mem::size_of::<u32>() {
            Err(AZIHSM_ERROR_INVALID_ARGUMENT)?
        }
        let val = u32::from_ne_bytes([$data[0], $data[1], $data[2], $data[3]]);
        <$enum_type>::from_repr(val).ok_or(AZIHSM_ERROR_INVALID_ARGUMENT)?
    }};
}

// Impl Key Property get for key

impl KeyPropValue {
    /// Get spec-defined default values for properties.
    /// These are applied during key generation, not during KeyProps construction.
    pub fn default_for_id(id: AzihsmKeyPropId) -> Self {
        match id {
            // User-specifiable properties with spec-defined defaults
            AzihsmKeyPropId::Session => KeyPropValue::IsSessionKey(true), // Spec: AZIHSM_BOOL_TRUE
            AzihsmKeyPropId::Modifiable => KeyPropValue::Boolean(false),  // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Encrypt => KeyPropValue::Boolean(false),     // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Decrypt => KeyPropValue::Boolean(false),     // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Sign => KeyPropValue::Boolean(false),        // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Verify => KeyPropValue::Boolean(false),      // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Wrap => KeyPropValue::Boolean(false),        // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Unwrap => KeyPropValue::Boolean(false),      // Spec: AZIHSM_BOOL_FALSE
            AzihsmKeyPropId::Derive => KeyPropValue::Boolean(false),      // Spec: AZIHSM_BOOL_FALSE

            // All other properties start as None
            _ => KeyPropValue::None,
        }
    }

    /// Write the byte representation of this value to the provided buffer
    /// Returns the number of bytes written
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Result<usize, AzihsmError> {
        match self {
            KeyPropValue::None => Err(AZIHSM_ERROR_INVALID_ARGUMENT),

            // Boolean values -> single byte (0 or 1)
            KeyPropValue::Boolean(v)
            | KeyPropValue::IsSessionKey(v)
            | KeyPropValue::Modifiable(v)
            | KeyPropValue::Copyable(v)
            | KeyPropValue::Destroyable(v)
            | KeyPropValue::Local(v)
            | KeyPropValue::Sensitive(v)
            | KeyPropValue::AlwaysSensitive(v)
            | KeyPropValue::Extractable(v)
            | KeyPropValue::NeverExtractable(v)
            | KeyPropValue::Trusted(v)
            | KeyPropValue::WrapWithTrusted(v)
            | KeyPropValue::Encrypt(v)
            | KeyPropValue::Decrypt(v)
            | KeyPropValue::Sign(v)
            | KeyPropValue::Verify(v)
            | KeyPropValue::Wrap(v)
            | KeyPropValue::Unwrap(v)
            | KeyPropValue::Derive(v) => write_bool_to_buffer!(buffer, *v),

            // Enum and numeric values -> 4 bytes (u32)
            KeyPropValue::KeyClass(class) => write_enum_to_buffer!(buffer, *class),
            KeyPropValue::KeyType(kind) => write_enum_to_buffer!(buffer, *kind),
            KeyPropValue::EcCurve(curve) => write_enum_to_buffer!(buffer, *curve),
            KeyPropValue::BitLen(bits) => write_u32_to_buffer!(buffer, *bits),

            // String values -> UTF-8 bytes
            KeyPropValue::Label(s) | KeyPropValue::String(s) => {
                let s_bytes = s.as_bytes();
                if buffer.len() < s_bytes.len() {
                    Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
                }
                buffer[..s_bytes.len()].copy_from_slice(s_bytes);
                Ok(s_bytes.len())
            }

            // Binary data -> raw bytes
            KeyPropValue::PubKeyInfo(data) | KeyPropValue::MaskedKey(data) => {
                if buffer.len() < data.len() {
                    Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?
                }
                buffer[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }
        }
    }

    /// Create a KeyPropValue from bytes based on the property ID
    pub fn from_bytes(prop_id: AzihsmKeyPropId, data: &[u8]) -> Result<Self, AzihsmError> {
        match prop_id {
            // Boolean properties with specific variants
            AzihsmKeyPropId::Session => {
                Ok(KeyPropValue::IsSessionKey(read_bool_from_buffer!(data)))
            }
            AzihsmKeyPropId::Modifiable => {
                Ok(KeyPropValue::Modifiable(read_bool_from_buffer!(data)))
            }
            AzihsmKeyPropId::Encrypt => Ok(KeyPropValue::Encrypt(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Decrypt => Ok(KeyPropValue::Decrypt(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Sign => Ok(KeyPropValue::Sign(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Verify => Ok(KeyPropValue::Verify(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Wrap => Ok(KeyPropValue::Wrap(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Unwrap => Ok(KeyPropValue::Unwrap(read_bool_from_buffer!(data))),
            AzihsmKeyPropId::Derive => Ok(KeyPropValue::Derive(read_bool_from_buffer!(data))),

            // Other boolean properties use generic Boolean variant
            AzihsmKeyPropId::Private
            | AzihsmKeyPropId::Copyable
            | AzihsmKeyPropId::Destroyable
            | AzihsmKeyPropId::Local
            | AzihsmKeyPropId::Sensitive
            | AzihsmKeyPropId::AlwaysSensitive
            | AzihsmKeyPropId::Extractable
            | AzihsmKeyPropId::NeverExtractable
            | AzihsmKeyPropId::Trusted
            | AzihsmKeyPropId::WrapWithTrusted => {
                Ok(KeyPropValue::Boolean(read_bool_from_buffer!(data)))
            }

            // Enum properties (4 bytes u32)
            AzihsmKeyPropId::Class => Ok(KeyPropValue::KeyClass(read_enum_from_buffer!(
                data,
                AzihsmKeyClass
            ))),
            AzihsmKeyPropId::Kind => {
                Ok(KeyPropValue::KeyType(read_enum_from_buffer!(data, KeyKind)))
            }
            AzihsmKeyPropId::EcCurve => {
                Ok(KeyPropValue::EcCurve(read_enum_from_buffer!(data, EcCurve)))
            }

            // Numeric properties (4 bytes u32)
            AzihsmKeyPropId::BitLen => Ok(KeyPropValue::BitLen(read_u32_from_buffer!(data))),

            // String properties (UTF-8)
            AzihsmKeyPropId::Label => {
                let s = std::str::from_utf8(data).map_err(|_| AZIHSM_ERROR_INVALID_ARGUMENT)?;
                Ok(KeyPropValue::Label(s.to_string()))
            }

            // Binary data properties
            AzihsmKeyPropId::PubKeyInfo => Ok(KeyPropValue::PubKeyInfo(data.to_vec())),
            AzihsmKeyPropId::MaskedKey => Ok(KeyPropValue::MaskedKey(data.to_vec())),
        }
    }
}

// Inner trait for actual key property implementations without handle type
// Used by individual key structs (RsaPkcsPrivateKeyInner, RsaPkcsPublicKeyInner, AES keys, etc.)
pub trait InnerKeyPropsOps {
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError>;
    fn set_property(&mut self, id: AzihsmKeyPropId, value: KeyPropValue)
        -> Result<(), AzihsmError>;

    /// Apply key-type-specific default values.
    /// Each key type must implement this to set appropriate defaults for:
    /// - Operation flags (encrypt/decrypt/sign/verify/wrap/unwrap/derive)
    /// - Key metadata (session, modifiable, etc.)
    /// - Any algorithm-specific properties
    ///
    /// This is called AFTER user properties are applied during key generation.
    fn apply_defaults(&mut self) -> Result<(), AzihsmError>;
}

/// Trait for symmetric key property operations (AES, HMAC).
///
/// Symmetric keys have a single set of properties that apply to the key material.
/// This trait provides get and set operations without handle type discrimination.
pub trait KeyPropsOps: Key {
    /// Get a property value from the symmetric key.
    fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError>;

    /// Set a property value on the symmetric key.
    fn set_property(&mut self, id: AzihsmKeyPropId, value: KeyPropValue)
        -> Result<(), AzihsmError>;
}

/// Trait for asymmetric key pair property operations (RSA, ECDSA).
///
/// Asymmetric key pairs have separate property sets for public and private keys.
/// This trait provides explicit methods to access each key's properties independently.
pub trait KeyPairPropsOps: Key {
    /// Get a property value from the public key.
    fn get_pub_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError>;

    /// Set a property value on the public key.
    fn set_pub_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError>;

    /// Get a property value from the private key.
    fn get_priv_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError>;

    /// Set a property value on the private key.
    fn set_priv_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError>;
}

#[derive(Debug, Clone)]
pub struct KeyProps {
    props: [KeyPropValue; AzihsmKeyPropId::COUNT + 1],
    // Track which properties have been set and are now immutable
    immutable_props: [bool; AzihsmKeyPropId::COUNT + 1],
}

impl KeyProps {
    pub(crate) fn new() -> Self {
        KeyProps {
            props: std::array::from_fn(|_| KeyPropValue::None),
            immutable_props: [false; AzihsmKeyPropId::COUNT + 1],
        }
    }

    /// Check if a property should be immutable after first set
    fn is_immutable_property(id: AzihsmKeyPropId) -> bool {
        matches!(
            id,
            AzihsmKeyPropId::BitLen
                | AzihsmKeyPropId::Kind
                | AzihsmKeyPropId::Class
                | AzihsmKeyPropId::EcCurve
        )
    }

    /// Check if a property is user-settable during key generation
    fn is_settable_property(id: AzihsmKeyPropId) -> bool {
        matches!(
            id,
            AzihsmKeyPropId::Session
                | AzihsmKeyPropId::Modifiable
                | AzihsmKeyPropId::Encrypt
                | AzihsmKeyPropId::Decrypt
                | AzihsmKeyPropId::Sign
                | AzihsmKeyPropId::Verify
                | AzihsmKeyPropId::Wrap
                | AzihsmKeyPropId::Unwrap
                | AzihsmKeyPropId::Derive
                | AzihsmKeyPropId::Label
                | AzihsmKeyPropId::BitLen
                | AzihsmKeyPropId::EcCurve
                | AzihsmKeyPropId::Kind
        )
    }

    /// Apply default values to properties as defined by the specification.
    /// This should be called during key generation to set defaults before applying user properties.
    pub(crate) fn apply_default_values(&mut self) {
        for i in 0..=AzihsmKeyPropId::COUNT {
            if let Some(prop_id) = AzihsmKeyPropId::from_repr(i as u32) {
                let default_value = KeyPropValue::default_for_id(prop_id);
                if !matches!(default_value, KeyPropValue::None) {
                    self.props[i] = default_value;
                }
            }
        }
    }

    pub fn get_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        Ok(self.props[id as usize].clone())
    }

    pub fn set_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        // Check if this property is user-settable (not read-only)
        if !Self::is_settable_property(id) {
            Err(AZIHSM_OPERATION_NOT_SUPPORTED)?
        }

        // Check if this property is immutable and has already been set
        if self.immutable_props[id as usize] {
            Err(AZIHSM_ILLEGAL_KEY_PROPERTY_OPERATION)?
        }

        self.props[id as usize] = value;

        // Mark as immutable if it's an immutable property type
        if Self::is_immutable_property(id) {
            self.immutable_props[id as usize] = true;
        }

        Ok(())
    }

    pub fn class(&self) -> Option<AzihsmKeyClass> {
        match &self.props[AzihsmKeyPropId::Class as usize] {
            KeyPropValue::KeyClass(class) => Some(*class),
            _ => None,
        }
    }

    pub(crate) fn set_class(&mut self, class: AzihsmKeyClass) {
        let prop_id = AzihsmKeyPropId::Class;
        self.props[prop_id as usize] = KeyPropValue::KeyClass(class);
        if Self::is_immutable_property(prop_id) {
            self.immutable_props[prop_id as usize] = true;
        }
    }

    pub fn kind(&self) -> Option<KeyKind> {
        match &self.props[AzihsmKeyPropId::Kind as usize] {
            KeyPropValue::KeyType(kind) => Some(*kind),
            _ => None,
        }
    }

    pub(crate) fn set_kind(&mut self, kind: KeyKind) {
        let prop_id = AzihsmKeyPropId::Kind;
        self.props[prop_id as usize] = KeyPropValue::KeyType(kind);
        if Self::is_immutable_property(prop_id) {
            self.immutable_props[prop_id as usize] = true;
        }
    }

    /// Apply HSM-managed default values based on key class and generation method.
    /// This should be called after key generation to set properties that are
    /// determined by the HSM based on key type and how it was created.
    ///
    /// # Arguments
    /// * `class` - The key class (Private, Public, or Secret)
    /// * `is_local` - Whether the key was generated locally (true) or imported (false)
    pub(crate) fn apply_hsm_defaults(&mut self, class: AzihsmKeyClass, is_local: bool) {
        // Set class and kind (already set by caller, but mark as immutable)
        self.set_class(class);

        // Session - Default to true (session key) unless explicitly set otherwise
        if self.session().is_none() {
            self.set_session(true);
        }

        // Modifiable - Default to false (user can't modify) unless explicitly set otherwise
        if self.modifiable().is_none() {
            self.set_modifiable(false);
        }

        // Private - All keys in session are private (Spec: AZIHSM_BOOL_TRUE)
        if self.private().is_none() {
            self.set_private(true);
        }

        // Local - True for generated keys, false for imported
        if self.local().is_none() {
            self.set_local(is_local);
        }

        // Sensitive - True for Private & Secret keys, False for Public keys
        if self.sensitive().is_none() {
            let is_sensitive = class != AzihsmKeyClass::Public;
            self.set_sensitive(is_sensitive);
        }

        // AlwaysSensitive - True for Private & Secret keys, False for Public keys
        if self.always_sensitive().is_none() {
            let is_always_sensitive = class != AzihsmKeyClass::Public;
            self.set_always_sensitive(is_always_sensitive);
        }

        // Copyable - All keys are not copyable (Spec: AZIHSM_BOOL_FALSE)
        if self.copyable().is_none() {
            self.set_copyable(false);
        }

        // Check if this is a session key for session-specific defaults
        let is_session_key = self.session().unwrap_or(true); // Default to true if not set

        // Destroyable - All session keys are destroyable (Spec: AZIHSM_BOOL_TRUE)
        // Device generated keys may be marked as not destroyable
        if self.destroyable().is_none() {
            self.set_destroyable(is_session_key);
        }

        // Extractable - All session keys are always extractable (Spec: AZIHSM_BOOL_TRUE)
        // Device generated keys may be marked as not extractable
        if self.extractable().is_none() {
            self.set_extractable(is_session_key);
        }

        // NeverExtractable - All session keys are always extractable, so never_extractable is false
        // Device generated keys may be marked as never extractable
        if self.never_extractable().is_none() {
            self.set_never_extractable(!is_session_key);
        }

        // WrapWithTrusted - True for Private & Secret keys
        if self.wrap_with_trusted().is_none() && class != AzihsmKeyClass::Public {
            self.set_wrap_with_trusted(true);
        }

        // Trusted - Default false (only applicable to Public keys, but default false for all)
        if self.trusted().is_none() {
            self.set_trusted(false);
        }
    }

    pub fn session(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Session as usize] {
            KeyPropValue::IsSessionKey(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_session(&mut self, session: bool) {
        self.props[AzihsmKeyPropId::Session as usize] = KeyPropValue::IsSessionKey(session);
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
            KeyPropValue::Modifiable(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_modifiable(&mut self, modifiable: bool) {
        self.props[AzihsmKeyPropId::Modifiable as usize] = KeyPropValue::Modifiable(modifiable);
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
            KeyPropValue::Encrypt(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_encrypt(&mut self, encrypt: bool) {
        self.props[AzihsmKeyPropId::Encrypt as usize] = KeyPropValue::Encrypt(encrypt);
    }

    pub fn decrypt(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Decrypt as usize] {
            KeyPropValue::Decrypt(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_decrypt(&mut self, decrypt: bool) {
        self.props[AzihsmKeyPropId::Decrypt as usize] = KeyPropValue::Decrypt(decrypt);
    }

    pub fn sign(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Sign as usize] {
            KeyPropValue::Sign(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_sign(&mut self, sign: bool) {
        self.props[AzihsmKeyPropId::Sign as usize] = KeyPropValue::Sign(sign);
    }

    pub fn verify(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Verify as usize] {
            KeyPropValue::Verify(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_verify(&mut self, verify: bool) {
        self.props[AzihsmKeyPropId::Verify as usize] = KeyPropValue::Verify(verify);
    }

    pub fn wrap(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Wrap as usize] {
            KeyPropValue::Wrap(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_wrap(&mut self, wrap: bool) {
        self.props[AzihsmKeyPropId::Wrap as usize] = KeyPropValue::Wrap(wrap);
    }

    pub fn unwrap(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Unwrap as usize] {
            KeyPropValue::Unwrap(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_unwrap(&mut self, unwrap: bool) {
        self.props[AzihsmKeyPropId::Unwrap as usize] = KeyPropValue::Unwrap(unwrap);
    }

    pub fn derive(&self) -> Option<bool> {
        match &self.props[AzihsmKeyPropId::Derive as usize] {
            KeyPropValue::Derive(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_derive(&mut self, derive: bool) {
        self.props[AzihsmKeyPropId::Derive as usize] = KeyPropValue::Derive(derive);
    }

    pub fn ecc_curve(&self) -> Option<EcCurve> {
        match &self.props[AzihsmKeyPropId::EcCurve as usize] {
            KeyPropValue::EcCurve(val) => Some(*val),
            _ => None,
        }
    }

    pub(crate) fn set_ecc_curve(&mut self, curve: EcCurve) {
        let prop_id = AzihsmKeyPropId::EcCurve;
        self.props[prop_id as usize] = KeyPropValue::EcCurve(curve);
        if Self::is_immutable_property(prop_id) {
            self.immutable_props[prop_id as usize] = true;
        }
    }

    pub fn bit_len(&self) -> Option<u32> {
        match &self.props[AzihsmKeyPropId::BitLen as usize] {
            KeyPropValue::BitLen(val) => Some(*val),
            _ => None,
        }
    }
    pub(crate) fn set_bit_len(&mut self, bit_len: u32) {
        let prop_id = AzihsmKeyPropId::BitLen;
        self.props[prop_id as usize] = KeyPropValue::BitLen(bit_len);
        if Self::is_immutable_property(prop_id) {
            self.immutable_props[prop_id as usize] = true;
        }
    }

    pub(crate) fn set_pub_key_info(&mut self, data: Vec<u8>) {
        self.props[AzihsmKeyPropId::PubKeyInfo as usize] = KeyPropValue::PubKeyInfo(data);
    }

    pub(crate) fn clear_pub_key_info(&mut self) {
        self.props[AzihsmKeyPropId::PubKeyInfo as usize] = KeyPropValue::None;
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

    /// Validate that key usage operations are mutually exclusive.
    ///
    /// The DDI layer supports these operation categories:
    /// - EncryptDecrypt: Encrypt and/or Decrypt (user can set both or either)
    /// - SignVerify: Sign and/or Verify (user can set both or either)
    /// - Unwrap: Wrap and/or Unwrap (user can set both or either)
    /// - Derive: Key derivation only
    ///
    /// A key can only belong to ONE category. For example, a key cannot be used
    /// for both encryption AND signing.
    ///
    /// This static version validates properties without needing self
    fn validate_operation_exclusivity_static(props: &[KeyPropValue]) -> Result<(), AzihsmError> {
        let mut operation_count = 0;

        // Check if encrypt/decrypt operations are enabled (EncryptDecrypt category)
        let encrypt = matches!(
            props[AzihsmKeyPropId::Encrypt as usize],
            KeyPropValue::Encrypt(true)
        );
        let decrypt = matches!(
            props[AzihsmKeyPropId::Decrypt as usize],
            KeyPropValue::Decrypt(true)
        );
        if encrypt || decrypt {
            operation_count += 1;
        }

        // Check if sign/verify operations are enabled (SignVerify category)
        let sign = matches!(
            props[AzihsmKeyPropId::Sign as usize],
            KeyPropValue::Sign(true)
        );
        let verify = matches!(
            props[AzihsmKeyPropId::Verify as usize],
            KeyPropValue::Verify(true)
        );
        if sign || verify {
            operation_count += 1;
        }

        // Check if wrap/unwrap operations are enabled (Unwrap category)
        // Note: DDI layer groups both wrap and unwrap under "Unwrap" category
        let wrap = matches!(
            props[AzihsmKeyPropId::Wrap as usize],
            KeyPropValue::Wrap(true)
        );
        let unwrap = matches!(
            props[AzihsmKeyPropId::Unwrap as usize],
            KeyPropValue::Unwrap(true)
        );
        if wrap || unwrap {
            operation_count += 1;
        }

        // Check if derive operation is enabled (Derive category)
        let derive = matches!(
            props[AzihsmKeyPropId::Derive as usize],
            KeyPropValue::Derive(true)
        );
        if derive {
            operation_count += 1;
        }

        // Only one operation category is allowed per DDI layer requirements
        if operation_count > 1 {
            Err(AZIHSM_ILLEGAL_KEY_PROPERTY)?
        }

        Ok(())
    }

    /// Validate operation exclusivity on the current key properties.
    /// This is a public wrapper for validate_operation_exclusivity_static.
    pub(crate) fn validate_operation_exclusivity(&self) -> Result<(), AzihsmError> {
        Self::validate_operation_exclusivity_static(&self.props)
    }

    /// Apply user-provided properties from the property list.
    /// This first applies user-specified values, then fills in defaults for unset properties.
    /// Only applies settable properties (user-controllable), ignoring read-only properties.
    ///
    /// # Arguments
    /// * `user_props` - KeyProps containing user-specified property values from FFI layer
    pub(crate) fn apply_user_properties(
        &mut self,
        user_props: &KeyProps,
    ) -> Result<(), AzihsmError> {
        // First, validate user properties before applying anything
        for i in 0..=AzihsmKeyPropId::COUNT {
            if let Some(prop_id) = AzihsmKeyPropId::from_repr(i as u32) {
                if let Ok(value) = user_props.get_property(prop_id) {
                    // Skip if the property was not set by user (None means not provided)
                    if matches!(value, KeyPropValue::None) {
                        continue;
                    }

                    // Check if this property is user-settable
                    if !Self::is_settable_property(prop_id) {
                        Err(AZIHSM_OPERATION_NOT_SUPPORTED)?
                    }
                }
            }
        }

        // Validate operation exclusivity on user-provided properties
        Self::validate_operation_exclusivity_static(&user_props.props)?;

        // All validation passed, now apply user-provided properties
        for i in 0..=AzihsmKeyPropId::COUNT {
            if let Some(prop_id) = AzihsmKeyPropId::from_repr(i as u32) {
                if let Ok(value) = user_props.get_property(prop_id) {
                    if !matches!(value, KeyPropValue::None) {
                        self.props[prop_id as usize] = value;
                        // Mark immutable properties as immutable after setting
                        if Self::is_immutable_property(prop_id) {
                            self.immutable_props[prop_id as usize] = true;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Key properties container for asymmetric key pairs.
///
/// This structure holds separate property sets for the public and private keys
/// in an asymmetric key pair (RSA, ECDSA). Each key in the pair has its own
/// independent set of properties managed via the nested `KeyProps` structures.
#[derive(Debug, Clone)]
pub struct KeyPairProps {
    pub_key_props: KeyProps,
    priv_key_props: KeyProps,
}

impl KeyPairProps {
    /// Create a new KeyPairProps with default values.
    pub(crate) fn new() -> Self {
        Self {
            pub_key_props: KeyProps::new(),
            priv_key_props: KeyProps::new(),
        }
    }

    /// Get a property from the public key.
    pub fn get_pub_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.pub_key_props.get_property(id)
    }

    /// Set a property on the public key.
    pub fn set_pub_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.pub_key_props.set_property(id, value)
    }

    /// Get a property from the private key.
    pub fn get_priv_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.priv_key_props.get_property(id)
    }

    /// Set a property on the private key.
    pub fn set_priv_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.priv_key_props.set_property(id, value)
    }

    /// Get direct read-only access to public key properties.
    pub fn pub_props(&self) -> &KeyProps {
        &self.pub_key_props
    }

    /// Get direct mutable access to public key properties.
    pub fn pub_props_mut(&mut self) -> &mut KeyProps {
        &mut self.pub_key_props
    }

    /// Get direct read-only access to private key properties.
    pub fn priv_props(&self) -> &KeyProps {
        &self.priv_key_props
    }

    /// Get direct mutable access to private key properties.
    pub fn priv_props_mut(&mut self) -> &mut KeyProps {
        &mut self.priv_key_props
    }

    /// Apply HSM-managed default values to both public and private keys.
    pub(crate) fn apply_hsm_defaults(&mut self, is_local: bool) {
        self.pub_key_props
            .apply_hsm_defaults(AzihsmKeyClass::Public, is_local);
        self.priv_key_props
            .apply_hsm_defaults(AzihsmKeyClass::Private, is_local);
    }

    /// Apply user-provided properties from FFI layer to both keys.
    pub(crate) fn apply_user_properties(
        &mut self,
        user_pub_props: &KeyProps,
        user_priv_props: &KeyProps,
    ) -> Result<(), AzihsmError> {
        self.pub_key_props.apply_user_properties(user_pub_props)?;
        self.priv_key_props.apply_user_properties(user_priv_props)?;
        Ok(())
    }

    /// Apply default values to both public and private key properties.
    pub(crate) fn apply_default_values(&mut self) {
        self.pub_key_props.apply_default_values();
        self.priv_key_props.apply_default_values();
    }
}

/// Builder for constructing `KeyProps` with a fluent API.
///
/// This builder is internal-only and used for converting C FFI key property lists
/// into Rust KeyProps. It allows for easy construction of key properties by chaining
/// method calls during FFI conversion.
pub(crate) struct KeyPropsBuilder {
    props: KeyProps,
}

impl KeyProps {
    /// Creates a new builder for constructing `KeyProps`.
    /// This is internal-only for C FFI conversion.
    ///
    /// # Returns
    ///
    /// A new `KeyPropsBuilder` instance with default values.
    pub(crate) fn builder() -> KeyPropsBuilder {
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

    /// Sets the kind (type) of the key.
    ///
    /// # Arguments
    ///
    /// * `kind` - The key kind (e.g., RSA, EC, AES, HMAC_SHA256)
    pub(crate) fn kind(mut self, kind: KeyKind) -> Self {
        self.props.set_kind(kind);
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
        } else if props.derive().unwrap_or(false) {
            DdiKeyUsage::Derive
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
