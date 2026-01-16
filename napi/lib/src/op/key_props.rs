// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key properties and attributes.
//!
//! This module provides types and utilities for describing cryptographic key properties,
//! including key class, type, size, usage flags, and metadata. The [`KeyProps`] structure
//! represents a complete set of key attributes, while [`KeyPropsBuilder`] provides a
//! fluent interface for constructing key properties.

use super::*;

/// Cryptographic key class.
///
/// Defines the fundamental category of a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmKeyClass {
    /// Symmetric secret key (e.g., AES, HMAC).
    Secret = 1,

    /// Public key from an asymmetric key pair.
    Public = 2,

    /// Private key from an asymmetric key pair.
    Private = 3,
}

impl TryFrom<u32> for HsmKeyClass {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HsmKeyClass::Secret),
            2 => Ok(HsmKeyClass::Public),
            3 => Ok(HsmKeyClass::Private),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

/// Cryptographic key algorithm type.
///
/// Specifies the algorithm family for a cryptographic key.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmKeyKind {
    /// RSA asymmetric key kind.
    Rsa = 1,

    /// Elliptic Curve (EC) asymmetric key kind.
    Ecc = 2,

    /// Advanced Encryption Standard (AES) symmetric key kind.
    Aes = 3,

    /// Shared secret key kind.
    SharedSecret = 5,

    /// HMAC SHA 1 is not supported.
    // HmacSha1 = 6,

    /// HMAC SHA 256
    HmacSha256 = 7,

    /// HMAC SHA 384
    HmacSha384 = 8,

    /// HMAC SHA 512
    HmacSha512 = 9,
}

impl TryFrom<u32> for HsmKeyKind {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HsmKeyKind::Rsa),
            2 => Ok(HsmKeyKind::Ecc),
            3 => Ok(HsmKeyKind::Aes),
            5 => Ok(HsmKeyKind::SharedSecret),
            7 => Ok(HsmKeyKind::HmacSha256),
            8 => Ok(HsmKeyKind::HmacSha384),
            9 => Ok(HsmKeyKind::HmacSha512),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

/// Elliptic Curve Cryptography (ECC) curve identifier.
///
/// Specifies the elliptic curve used for ECC keys, as defined by NIST.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmEccCurve {
    /// NIST P-256 curve (secp256r1), 256-bit security.
    P256 = 1,
    /// NIST P-384 curve (secp384r1), 384-bit security.
    P384 = 2,
    /// NIST P-521 curve (secp521r1), 521-bit security.
    P521 = 3,
}

impl TryFrom<u32> for HsmEccCurve {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HsmEccCurve::P256),
            2 => Ok(HsmEccCurve::P384),
            3 => Ok(HsmEccCurve::P521),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

impl HsmEccCurve {
    /// Returns the key size in bits for the ECC curve.
    pub fn key_size_bits(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 256,
            HsmEccCurve::P384 => 384,
            HsmEccCurve::P521 => 521,
        }
    }

    pub fn signature_size(&self) -> usize {
        self.component_size() * 2
    }

    pub fn component_size(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }
}

bitflags::bitflags! {
    /// Key attribute flags.
    ///
    /// Bitflags representing various key properties and allowed operations.
    /// These flags control key lifecycle, sensitivity, extractability, and
    /// permitted cryptographic operations.
    ///
    /// # Lifecycle Flags
    ///
    /// - `SESSION`: Key exists only for the current session
    /// - `LOCAL`: Key was generated locally (not imported)
    /// - `PRIVATE`: Key should be treated as private/sensitive
    /// - `MODIFIABLE`: Key attributes can be modified
    /// - `COPYABLE`: Key can be copied
    /// - `DESTROYABLE`: Key can be explicitly destroyed
    ///
    /// # Sensitivity Flags
    ///
    /// - `SENSITIVE`: Key is sensitive and should not be exposed
    /// - `ALWAYS_SENSITIVE`: Key has always been sensitive since creation
    /// - `EXTRACTABLE`: Key can be extracted/exported
    /// - `NEVER_EXTRACTABLE`: Key has never been extractable
    ///
    /// # Operation Flags
    ///
    /// - `ENCRYPT`: Key can be used for encryption
    /// - `DECRYPT`: Key can be used for decryption
    /// - `SIGN`: Key can be used for signing
    /// - `VERIFY`: Key can be used for signature verification
    /// - `WRAP`: Key can be used to wrap (encrypt) other keys
    /// - `UNWRAP`: Key can be used to unwrap (decrypt) other keys
    /// - `DERIVE`: Key can be used for key derivation
    #[derive(Debug,Default, Clone, Copy, PartialEq, Eq)]
    pub(crate)struct HsmKeyFlags: u32 {
        const SESSION = 1 << 0;
        const LOCAL = 1 << 1;
        const PRIVATE = 1 << 2;
        const MODIFIABLE = 1 << 3;
        const COPYABLE = 1 << 4;
        const DESTROYABLE = 1 << 5;
        const SENSITIVE = 1 << 6;
        const ALWAYS_SENSITIVE = 1 << 7;
        const EXTRACTABLE = 1 << 8;
        const NEVER_EXTRACTABLE = 1 << 9;
        const ENCRYPT = 1 << 10;
        const DECRYPT = 1 << 11;
        const SIGN = 1 << 12;
        const VERIFY = 1 << 13;
        const WRAP = 1 << 14;
        const UNWRAP = 1 << 15;
        const DERIVE = 1 << 16;
    }
}

#[allow(unused)]
impl HsmKeyFlags {
    /// Returns whether the key is a session key.
    pub fn is_session(&self) -> bool {
        self.contains(HsmKeyFlags::SESSION)
    }

    /// Returns whether the key is a local key.
    pub fn is_local(&self) -> bool {
        self.contains(HsmKeyFlags::LOCAL)
    }

    /// Returns whether the key is a private key.
    pub fn is_private(&self) -> bool {
        self.contains(HsmKeyFlags::PRIVATE)
    }

    /// Returns whether the key is modifiable.
    pub fn is_modifiable(&self) -> bool {
        self.contains(HsmKeyFlags::MODIFIABLE)
    }

    /// Returns whether the key is copyable.
    pub fn is_copyable(&self) -> bool {
        self.contains(HsmKeyFlags::COPYABLE)
    }

    /// Returns whether the key is destroyable.
    pub fn is_destroyable(&self) -> bool {
        self.contains(HsmKeyFlags::DESTROYABLE)
    }

    /// Returns whether the key is sensitive.
    pub fn is_sensitive(&self) -> bool {
        self.contains(HsmKeyFlags::SENSITIVE)
    }

    /// Returns whether the key has always been sensitive.
    pub fn is_always_sensitive(&self) -> bool {
        self.contains(HsmKeyFlags::ALWAYS_SENSITIVE)
    }

    /// Returns whether the key is extractable.
    pub fn is_extractable(&self) -> bool {
        self.contains(HsmKeyFlags::EXTRACTABLE)
    }

    /// Returns whether the key has never been extractable.
    pub fn is_never_extractable(&self) -> bool {
        self.contains(HsmKeyFlags::NEVER_EXTRACTABLE)
    }

    /// Returns whether the key can be used for encryption.
    pub fn can_encrypt(&self) -> bool {
        self.contains(HsmKeyFlags::ENCRYPT)
    }

    /// Returns whether the key can be used for decryption.
    pub fn can_decrypt(&self) -> bool {
        self.contains(HsmKeyFlags::DECRYPT)
    }

    /// Returns whether the key can be used for signing.
    pub fn can_sign(&self) -> bool {
        self.contains(HsmKeyFlags::SIGN)
    }

    /// Returns whether the key can be used for verification.
    pub fn can_verify(&self) -> bool {
        self.contains(HsmKeyFlags::VERIFY)
    }

    /// Returns whether the key can be used for wrapping.
    pub fn can_wrap(&self) -> bool {
        self.contains(HsmKeyFlags::WRAP)
    }

    /// Returns whether the key can be used for unwrapping.
    pub fn can_unwrap(&self) -> bool {
        self.contains(HsmKeyFlags::UNWRAP)
    }

    /// Returns whether the key can be used for key derivation.
    pub fn can_derive(&self) -> bool {
        self.contains(HsmKeyFlags::DERIVE)
    }
}
/// Key properties and attributes.
///
/// Contains comprehensive information about a cryptographic key including its
/// class, type, size, usage flags, and associated metadata. This structure
/// represents the complete set of attributes that describe a key's characteristics
/// and permitted operations.
#[derive(Debug, Clone)]
pub struct HsmKeyProps {
    class: HsmKeyClass,
    kind: HsmKeyKind,
    label: Vec<u8>,
    bits: u32,
    ecc_curve: Option<HsmEccCurve>,
    masked_key: Option<Vec<u8>>,
    pub_key_der: Option<Vec<u8>>,
    flags: HsmKeyFlags,
}

impl HsmKeyProps {
    pub(crate) fn flags(&self) -> HsmKeyFlags {
        self.flags
    }

    /// Returns the key class.
    pub fn class(&self) -> HsmKeyClass {
        self.class
    }

    /// Returns the key type.
    pub fn kind(&self) -> HsmKeyKind {
        self.kind
    }

    /// Returns the key label.
    pub fn label(&self) -> &[u8] {
        &self.label
    }

    /// Returns the key bit length.
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Returns the ECC curve if applicable.
    pub fn ecc_curve(&self) -> Option<HsmEccCurve> {
        self.ecc_curve
    }

    /// Returns the masked key data.
    pub fn masked_key(&self) -> Option<&[u8]> {
        self.masked_key.as_deref()
    }

    /// Returns the public key info.
    pub fn pub_key_der(&self) -> Option<&[u8]> {
        self.pub_key_der.as_deref()
    }

    /// Returns whether the key is a session key.
    pub fn is_session(&self) -> bool {
        self.flags.contains(HsmKeyFlags::SESSION)
    }

    /// Returns whether the key is a local key.
    pub fn is_local(&self) -> bool {
        self.flags.contains(HsmKeyFlags::LOCAL)
    }

    /// Returns whether the key is a private key.
    pub fn is_private(&self) -> bool {
        self.flags.contains(HsmKeyFlags::PRIVATE)
    }

    /// Returns whether the key is modifiable.
    pub fn is_modifiable(&self) -> bool {
        self.flags.contains(HsmKeyFlags::MODIFIABLE)
    }

    /// Returns whether the key is copyable.
    pub fn is_copyable(&self) -> bool {
        self.flags.contains(HsmKeyFlags::COPYABLE)
    }

    /// Returns whether the key is destroyable.
    pub fn is_destroyable(&self) -> bool {
        self.flags.contains(HsmKeyFlags::DESTROYABLE)
    }

    /// Returns whether the key is sensitive.
    pub fn is_sensitive(&self) -> bool {
        self.flags.contains(HsmKeyFlags::SENSITIVE)
    }

    /// Returns whether the key has always been sensitive.
    pub fn is_always_sensitive(&self) -> bool {
        self.flags.contains(HsmKeyFlags::ALWAYS_SENSITIVE)
    }

    /// Returns whether the key is extractable.
    pub fn is_extractable(&self) -> bool {
        self.flags.contains(HsmKeyFlags::EXTRACTABLE)
    }

    /// Returns whether the key has never been extractable.
    pub fn is_never_extractable(&self) -> bool {
        self.flags.contains(HsmKeyFlags::NEVER_EXTRACTABLE)
    }

    /// Returns whether the key can be used for encryption.
    pub fn can_encrypt(&self) -> bool {
        self.flags.contains(HsmKeyFlags::ENCRYPT)
    }

    /// Returns whether the key can be used for decryption.
    pub fn can_decrypt(&self) -> bool {
        self.flags.contains(HsmKeyFlags::DECRYPT)
    }

    /// Returns whether the key can be used for signing.
    pub fn can_sign(&self) -> bool {
        self.flags.contains(HsmKeyFlags::SIGN)
    }

    /// Returns whether the key can be used for verification.
    pub fn can_verify(&self) -> bool {
        self.flags.contains(HsmKeyFlags::VERIFY)
    }

    /// Returns whether the key can be used for wrapping.
    pub fn can_wrap(&self) -> bool {
        self.flags.contains(HsmKeyFlags::WRAP)
    }

    /// Returns whether the key can be used for unwrapping.
    pub fn can_unwrap(&self) -> bool {
        self.flags.contains(HsmKeyFlags::UNWRAP)
    }

    /// Returns whether the key can be used for key derivation.
    pub fn can_derive(&self) -> bool {
        self.flags.contains(HsmKeyFlags::DERIVE)
    }

    /// Creates a new builder for KeyProps.
    pub fn builder() -> HsmKeyPropsBuilder {
        HsmKeyPropsBuilder::default()
    }

    /// Sets the masked key data.
    pub(crate) fn set_masked_key(&mut self, masked_key: &[u8]) {
        self.masked_key = Some(masked_key.to_vec());
    }

    pub(crate) fn set_pub_key_der(&mut self, pub_key_der: &[u8]) {
        self.pub_key_der = Some(pub_key_der.to_vec());
    }

    pub(crate) fn check_supported_flags(&self, supported_flags: HsmKeyFlags) -> bool {
        // Allow additional flags which is settable for all keys(session flag)
        let allowed_flags = supported_flags | HsmKeyFlags::SESSION;

        // Returns `true` only if all currently-set flags are within `allowed_flags`.
        (self.flags & !allowed_flags).is_empty()
    }
}

/// Builder for constructing [`KeyProps`] instances.
#[derive(Default)]
pub struct HsmKeyPropsBuilder {
    class: Option<HsmKeyClass>,
    key_kind: Option<HsmKeyKind>,
    label: Vec<u8>,
    bit_len: Option<u32>,
    ecc_curve: Option<HsmEccCurve>,
    flags: HsmKeyFlags,
}

impl HsmKeyPropsBuilder {
    /// Sets the key class.
    ///
    /// This is a required field.
    pub fn class(mut self, class: HsmKeyClass) -> Self {
        self.class = Some(class);
        self
    }

    /// Sets the key kind.
    pub fn key_kind(mut self, key_kind: HsmKeyKind) -> Self {
        self.key_kind = Some(key_kind);
        self
    }

    /// Sets the key label.
    pub fn label(mut self, label: &[u8]) -> Self {
        self.label = label.to_vec();
        self
    }

    /// Sets the key bit length.
    pub fn bits(mut self, bit_len: u32) -> Self {
        self.bit_len = Some(bit_len);
        self
    }

    /// Sets the ECC curve.
    pub fn ecc_curve(mut self, curve: HsmEccCurve) -> Self {
        self.ecc_curve = Some(curve);
        self
    }

    /// Sets the session flag.
    pub fn is_session(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::SESSION, value);
        self
    }

    /// Sets the encrypt flag.
    pub fn can_encrypt(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::ENCRYPT, value);
        self
    }

    /// Sets the decrypt flag.
    pub fn can_decrypt(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::DECRYPT, value);
        self
    }

    /// Sets the sign flag.
    pub fn can_sign(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::SIGN, value);
        self
    }

    /// Sets the verify flag.
    pub fn can_verify(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::VERIFY, value);
        self
    }

    /// Sets the wrap flag.
    pub fn can_wrap(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::WRAP, value);
        self
    }

    /// Sets the unwrap flag.
    pub fn can_unwrap(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::UNWRAP, value);
        self
    }

    /// Sets the derive flag.
    pub fn can_derive(mut self, value: bool) -> Self {
        self.flags.set(HsmKeyFlags::DERIVE, value);
        self
    }

    /// Builds the KeyProps instance.
    pub fn build(self) -> HsmResult<HsmKeyProps> {
        let bits = if self.bit_len.is_some() {
            self.bit_len.unwrap()
        } else if let Some(curve) = self.ecc_curve {
            curve.key_size_bits() as u32
        } else {
            return Err(HsmError::KeyPropertyNotPresent);
        };

        Ok(HsmKeyProps {
            class: self.class.ok_or(HsmError::KeyClassNotSpecified)?,
            kind: self.key_kind.ok_or(HsmError::KeyKindNotSpecified)?,
            label: self.label,
            bits,
            ecc_curve: self.ecc_curve,
            masked_key: None,
            pub_key_der: None,
            flags: self.flags,
        })
    }
}
