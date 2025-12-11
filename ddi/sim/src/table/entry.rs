// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Cryptographic Keys and their Metadata.

use std::sync::Arc;
use std::time::Instant;

use attestation::report::KeyFlags;
use bitfield_struct::bitfield;
use mcr_ddi_types::DdiAesKeySize;
use mcr_ddi_types::DdiEccCurve;
use mcr_ddi_types::DdiKeyClass;
use mcr_ddi_types::DdiKeyType;
use mcr_ddi_types::DdiKeyUsage;
use parking_lot::RwLock;
use uuid::Uuid;

use self::key::Key;
use crate::crypto::aes::AesKeySize;
use crate::crypto::ecc::EccKeySize;
use crate::crypto::rsa::RsaKeySize;
use crate::errors::ManticoreError;

pub mod key;

/// Cryptographic Key Class.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyClass {
    /// RSA Private
    RsaPrivate,

    /// RSA CRT Private
    RsaCrtPrivate,

    /// AES
    Aes,

    /// AES XTS Bulk
    AesXtsBulk,

    /// AES GCM Bulk
    AesGcmBulk,

    /// AES GCM Bulk Unapproved
    AesGcmBulkUnapproved,

    /// ECC Private
    EccPrivate,
}

impl TryFrom<DdiKeyClass> for KeyClass {
    type Error = ManticoreError;

    fn try_from(value: DdiKeyClass) -> Result<Self, Self::Error> {
        match value {
            DdiKeyClass::Rsa => Ok(KeyClass::RsaPrivate),
            DdiKeyClass::RsaCrt => Ok(KeyClass::RsaCrtPrivate),
            DdiKeyClass::Aes => Ok(KeyClass::Aes),
            DdiKeyClass::AesXtsBulk => Ok(KeyClass::AesXtsBulk),
            DdiKeyClass::AesGcmBulk => Ok(KeyClass::AesGcmBulk),
            DdiKeyClass::AesGcmBulkUnapproved => Ok(KeyClass::AesGcmBulkUnapproved),
            DdiKeyClass::Ecc => Ok(KeyClass::EccPrivate),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl KeyClass {
    /// Returns whether the key class supports a usage
    pub fn allows_usage(&self, usage: DdiKeyUsage) -> bool {
        matches!(
            (self, usage),
            (
                KeyClass::RsaPrivate,
                DdiKeyUsage::SignVerify | DdiKeyUsage::EncryptDecrypt | DdiKeyUsage::Unwrap,
            ) | (
                KeyClass::RsaCrtPrivate,
                DdiKeyUsage::SignVerify | DdiKeyUsage::EncryptDecrypt | DdiKeyUsage::Unwrap,
            ) | (
                KeyClass::EccPrivate,
                DdiKeyUsage::SignVerify | DdiKeyUsage::Derive,
            ) | (
                KeyClass::Aes
                    | KeyClass::AesXtsBulk
                    | KeyClass::AesGcmBulk
                    | KeyClass::AesGcmBulkUnapproved,
                DdiKeyUsage::EncryptDecrypt,
            )
        )
    }
}

/// Kind of Cryptographic Key.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind {
    /// RSA 2048-bit Public Key.
    Rsa2kPublic,

    /// RSA 3072-bit Public Key.
    Rsa3kPublic,

    /// RSA 4096-bit Public Key.
    Rsa4kPublic,

    /// RSA 2048-bit Private Key.
    Rsa2kPrivate,

    /// RSA 3072-bit Private Key.
    Rsa3kPrivate,

    /// RSA 4096-bit Private Key.
    Rsa4kPrivate,

    /// RSA 2048-bit Private CRT Key.
    Rsa2kPrivateCrt,

    /// RSA 3072-bit Private CRT Key.
    Rsa3kPrivateCrt,

    /// RSA 4096-bit Private CRT Key.
    Rsa4kPrivateCrt,

    /// ECC 256 Public Key
    Ecc256Public,

    /// ECC 384 Public Key
    Ecc384Public,

    /// ECC 521 Public Key
    Ecc521Public,

    /// ECC 256 Private Key
    Ecc256Private,

    /// ECC 384 Private Key
    Ecc384Private,

    /// ECC 521 Private Key
    Ecc521Private,

    /// AES 128-bit Key.
    Aes128,

    /// AES 192-bit Key.
    Aes192,

    /// AES 256-bit Key.
    Aes256,

    /// AES XTS Bulk 256-bit Key.
    AesXtsBulk256,

    /// AES GCM Bulk 256-bit Key.
    AesGcmBulk256,

    /// AES GCM Bulk 256-bit Key Unapproved.
    AesGcmBulk256Unapproved,

    /// Aes 256 + HMAC 384
    AesHmac640,

    /// 256-bit Secret from key exchange
    Secret256,

    /// 384-bit Secret from key exchange
    Secret384,

    /// 521-bit Secret from key exchange
    Secret521,

    /// Session
    Session,

    /// HMAC 256-bit Key
    HmacSha256,

    /// HMAC 384-bit Key
    HmacSha384,

    /// HMAC 512-bit Key
    HmacSha512,
}

impl TryFrom<u8> for Kind {
    type Error = ManticoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Kind::Rsa2kPublic as u8 => Ok(Kind::Rsa2kPublic),
            x if x == Kind::Rsa3kPublic as u8 => Ok(Kind::Rsa3kPublic),
            x if x == Kind::Rsa4kPublic as u8 => Ok(Kind::Rsa4kPublic),
            x if x == Kind::Rsa2kPrivate as u8 => Ok(Kind::Rsa2kPrivate),
            x if x == Kind::Rsa3kPrivate as u8 => Ok(Kind::Rsa3kPrivate),
            x if x == Kind::Rsa4kPrivate as u8 => Ok(Kind::Rsa4kPrivate),
            x if x == Kind::Rsa2kPrivateCrt as u8 => Ok(Kind::Rsa2kPrivateCrt),
            x if x == Kind::Rsa3kPrivateCrt as u8 => Ok(Kind::Rsa3kPrivateCrt),
            x if x == Kind::Rsa4kPrivateCrt as u8 => Ok(Kind::Rsa4kPrivateCrt),
            x if x == Kind::Ecc256Public as u8 => Ok(Kind::Ecc256Public),
            x if x == Kind::Ecc384Public as u8 => Ok(Kind::Ecc384Public),
            x if x == Kind::Ecc521Public as u8 => Ok(Kind::Ecc521Public),
            x if x == Kind::Ecc256Private as u8 => Ok(Kind::Ecc256Private),
            x if x == Kind::Ecc384Private as u8 => Ok(Kind::Ecc384Private),
            x if x == Kind::Ecc521Private as u8 => Ok(Kind::Ecc521Private),
            x if x == Kind::Aes128 as u8 => Ok(Kind::Aes128),
            x if x == Kind::Aes192 as u8 => Ok(Kind::Aes192),
            x if x == Kind::Aes256 as u8 => Ok(Kind::Aes256),
            x if x == Kind::AesXtsBulk256 as u8 => Ok(Kind::AesXtsBulk256),
            x if x == Kind::AesGcmBulk256 as u8 => Ok(Kind::AesGcmBulk256),
            x if x == Kind::AesGcmBulk256Unapproved as u8 => Ok(Kind::AesGcmBulk256Unapproved),
            x if x == Kind::AesHmac640 as u8 => Ok(Kind::AesHmac640),
            x if x == Kind::Secret256 as u8 => Ok(Kind::Secret256),
            x if x == Kind::Secret384 as u8 => Ok(Kind::Secret384),
            x if x == Kind::Secret521 as u8 => Ok(Kind::Secret521),
            x if x == Kind::Session as u8 => Ok(Kind::Session),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl TryFrom<DdiKeyType> for Kind {
    type Error = ManticoreError;

    fn try_from(value: DdiKeyType) -> Result<Self, Self::Error> {
        match value {
            DdiKeyType::Rsa2kPublic => Ok(Kind::Rsa2kPublic),
            DdiKeyType::Rsa3kPublic => Ok(Kind::Rsa3kPublic),
            DdiKeyType::Rsa4kPublic => Ok(Kind::Rsa4kPublic),
            DdiKeyType::Rsa2kPrivate => Ok(Kind::Rsa2kPrivate),
            DdiKeyType::Rsa3kPrivate => Ok(Kind::Rsa3kPrivate),
            DdiKeyType::Rsa4kPrivate => Ok(Kind::Rsa4kPrivate),
            DdiKeyType::Rsa2kPrivateCrt => Ok(Kind::Rsa2kPrivateCrt),
            DdiKeyType::Rsa3kPrivateCrt => Ok(Kind::Rsa3kPrivateCrt),
            DdiKeyType::Rsa4kPrivateCrt => Ok(Kind::Rsa4kPrivateCrt),
            DdiKeyType::Ecc256Public => Ok(Kind::Ecc256Public),
            DdiKeyType::Ecc384Public => Ok(Kind::Ecc384Public),
            DdiKeyType::Ecc521Public => Ok(Kind::Ecc521Public),
            DdiKeyType::Ecc256Private => Ok(Kind::Ecc256Private),
            DdiKeyType::Ecc384Private => Ok(Kind::Ecc384Private),
            DdiKeyType::Ecc521Private => Ok(Kind::Ecc521Private),
            DdiKeyType::Aes128 => Ok(Kind::Aes128),
            DdiKeyType::Aes192 => Ok(Kind::Aes192),
            DdiKeyType::Aes256 => Ok(Kind::Aes256),
            DdiKeyType::AesXtsBulk256 => Ok(Kind::AesXtsBulk256),
            DdiKeyType::AesGcmBulk256 => Ok(Kind::AesGcmBulk256),
            DdiKeyType::AesGcmBulk256Unapproved => Ok(Kind::AesGcmBulk256Unapproved),
            DdiKeyType::Secret256 => Ok(Kind::Secret256),
            DdiKeyType::Secret384 => Ok(Kind::Secret384),
            DdiKeyType::Secret521 => Ok(Kind::Secret521),
            DdiKeyType::HmacSha256 => Ok(Kind::HmacSha256),
            DdiKeyType::HmacSha384 => Ok(Kind::HmacSha384),
            DdiKeyType::HmacSha512 => Ok(Kind::HmacSha512),
            _ => Err(ManticoreError::InvalidKeyType),
        }
    }
}

impl TryFrom<Kind> for DdiKeyType {
    type Error = ManticoreError;

    fn try_from(value: Kind) -> Result<Self, Self::Error> {
        let key_type = match value {
            Kind::Rsa2kPublic => DdiKeyType::Rsa2kPublic,
            Kind::Rsa3kPublic => DdiKeyType::Rsa3kPublic,
            Kind::Rsa4kPublic => DdiKeyType::Rsa4kPublic,
            Kind::Rsa2kPrivate => DdiKeyType::Rsa2kPrivate,
            Kind::Rsa3kPrivate => DdiKeyType::Rsa3kPrivate,
            Kind::Rsa4kPrivate => DdiKeyType::Rsa4kPrivate,
            Kind::Rsa2kPrivateCrt => DdiKeyType::Rsa2kPrivateCrt,
            Kind::Rsa3kPrivateCrt => DdiKeyType::Rsa3kPrivateCrt,
            Kind::Rsa4kPrivateCrt => DdiKeyType::Rsa4kPrivateCrt,
            Kind::Ecc256Public => DdiKeyType::Ecc256Public,
            Kind::Ecc384Public => DdiKeyType::Ecc384Public,
            Kind::Ecc521Public => DdiKeyType::Ecc521Public,
            Kind::Ecc256Private => DdiKeyType::Ecc256Private,
            Kind::Ecc384Private => DdiKeyType::Ecc384Private,
            Kind::Ecc521Private => DdiKeyType::Ecc521Private,
            Kind::Aes128 => DdiKeyType::Aes128,
            Kind::Aes192 => DdiKeyType::Aes192,
            Kind::Aes256 => DdiKeyType::Aes256,
            Kind::AesXtsBulk256 => DdiKeyType::AesXtsBulk256,
            Kind::AesGcmBulk256 => DdiKeyType::AesGcmBulk256,
            Kind::AesGcmBulk256Unapproved => DdiKeyType::AesGcmBulk256Unapproved,
            Kind::Secret256 => DdiKeyType::Secret256,
            Kind::Secret384 => DdiKeyType::Secret384,
            Kind::Secret521 => DdiKeyType::Secret521,
            Kind::HmacSha256 => DdiKeyType::HmacSha256,
            Kind::HmacSha384 => DdiKeyType::HmacSha384,
            Kind::HmacSha512 => DdiKeyType::HmacSha512,
            _ => Err(ManticoreError::InvalidKeyType)?,
        };

        Ok(key_type)
    }
}

impl TryFrom<DdiEccCurve> for Kind {
    type Error = ManticoreError;

    fn try_from(value: DdiEccCurve) -> Result<Self, Self::Error> {
        match value {
            DdiEccCurve::P256 => Ok(Kind::Ecc256Public),
            DdiEccCurve::P384 => Ok(Kind::Ecc384Public),
            DdiEccCurve::P521 => Ok(Kind::Ecc521Public),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl TryFrom<DdiAesKeySize> for Kind {
    type Error = ManticoreError;

    fn try_from(value: DdiAesKeySize) -> Result<Self, Self::Error> {
        match value {
            DdiAesKeySize::Aes128 => Ok(Kind::Aes128),
            DdiAesKeySize::Aes192 => Ok(Kind::Aes192),
            DdiAesKeySize::Aes256 => Ok(Kind::Aes256),
            DdiAesKeySize::AesXtsBulk256 => Ok(Kind::AesXtsBulk256),
            DdiAesKeySize::AesGcmBulk256 => Ok(Kind::AesGcmBulk256),
            DdiAesKeySize::AesGcmBulk256Unapproved => Ok(Kind::AesGcmBulk256Unapproved),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl From<RsaKeySize> for Kind {
    fn from(value: RsaKeySize) -> Self {
        match value {
            RsaKeySize::Rsa2048 => Kind::Rsa2kPrivate,
            RsaKeySize::Rsa3072 => Kind::Rsa3kPrivate,
            RsaKeySize::Rsa4096 => Kind::Rsa4kPrivate,
        }
    }
}

impl From<EccKeySize> for Kind {
    fn from(value: EccKeySize) -> Self {
        match value {
            EccKeySize::Ecc256 => Kind::Ecc256Private,
            EccKeySize::Ecc384 => Kind::Ecc384Private,
            EccKeySize::Ecc521 => Kind::Ecc521Private,
        }
    }
}

impl From<AesKeySize> for Kind {
    fn from(value: AesKeySize) -> Self {
        match value {
            AesKeySize::Aes128 => Kind::Aes128,
            AesKeySize::Aes192 => Kind::Aes192,
            AesKeySize::Aes256 => Kind::Aes256,
            AesKeySize::AesXtsBulk256 => Kind::AesXtsBulk256,
            AesKeySize::AesGcmBulk256 => Kind::AesGcmBulk256,
            AesKeySize::AesGcmBulk256Unapproved => Kind::AesGcmBulk256Unapproved,
        }
    }
}

impl Kind {
    /// Returns the size of the key in bytes as used by physical device.
    pub fn size(&self) -> usize {
        match self {
            Kind::Rsa2kPublic => 260,
            Kind::Rsa3kPublic => 388,
            Kind::Rsa4kPublic => 516,
            // We will also store public exponent in the private key at the end
            // so that we can extract the public key from the private key.
            // However, it is not in the order to be able to be used by the
            // hardware directly. An API will be provided to extract such public key
            // and the client can chose to import it into a separate slot.
            Kind::Rsa2kPrivate => 516,
            Kind::Rsa3kPrivate => 772,
            Kind::Rsa4kPrivate => 1028,
            Kind::Rsa2kPrivateCrt => 1284,
            Kind::Rsa3kPrivateCrt => 1924,
            Kind::Rsa4kPrivateCrt => 2564,
            Kind::Ecc256Public => 64,
            Kind::Ecc384Public => 96,
            Kind::Ecc521Public => 136,
            Kind::Ecc256Private => 32,
            Kind::Ecc384Private => 48,
            // 521 is ~66 bytes, but need 68 bytes as it's used by physical manticore.
            Kind::Ecc521Private => 68,
            Kind::Aes128 => 16,
            Kind::Aes192 => 24,
            Kind::Aes256 => 32,
            // In physical manticore, AesBulk256 is just a forwarding key of 2 bytes into the bulk vault.
            Kind::AesXtsBulk256 | Kind::AesGcmBulk256 | Kind::AesGcmBulk256Unapproved => 2,
            Kind::AesHmac640 => 80,
            Kind::Secret256 => 32,
            Kind::Secret384 => 48,
            Kind::Secret521 => 66,
            // In physical manticore, Session is of 8 bytes containing the API Revision.
            Kind::Session => 8,
            Kind::HmacSha256 => 32,
            Kind::HmacSha384 => 48,
            Kind::HmacSha512 => 64,
        }
    }

    /// Returns the size of the key in bytes when serialized.
    /// for DDI wire protocol validation purposes.
    pub fn serde_size(&self) -> usize {
        match self {
            // Public keys remain the same as raw size for now
            Kind::Rsa2kPublic => 260,
            Kind::Rsa3kPublic => 388,
            Kind::Rsa4kPublic => 516,
            Kind::Ecc256Public => 64,
            Kind::Ecc384Public => 96,
            Kind::Ecc521Public => 136,

            // Private keys in BCrypt format have additional overhead for non-CRT keys
            // For CRT keys, we are not serializing params for CRT, so their sizes are the same as non-CRT.
            Kind::Rsa2kPrivate => 539, // BCrypt  size for RSA 2K (was 516)
            Kind::Rsa3kPrivate => 795, // BCrypt  size for RSA 3K (was 772 raw)
            Kind::Rsa4kPrivate => 1051, // BCrypt  size for RSA 4K (was 1028)
            Kind::Rsa2kPrivateCrt => 539, // Not using CRT, same as Rsa2kPrivate
            Kind::Rsa3kPrivateCrt => 795, // Same as Rsa3kPrivate
            Kind::Rsa4kPrivateCrt => 1051, // Same as Rsa4kPrivate

            // ECC private keys have significant PKCS#8 DER overhead
            Kind::Ecc256Private => 138, // DER size for P-256 (was 32 raw)
            Kind::Ecc384Private => 185, // DER size for P-384 (was 48 raw)
            Kind::Ecc521Private => 241, // DER size for P-521 (was 68 raw)

            // Symmetric keys and others remain the same as raw size
            Kind::Aes128 => 16,
            Kind::Aes192 => 24,
            Kind::Aes256 => 32,
            Kind::AesXtsBulk256 | Kind::AesGcmBulk256 | Kind::AesGcmBulk256Unapproved => 32,
            Kind::AesHmac640 => 80,
            Kind::Secret256 => 32,
            Kind::Secret384 => 48,
            Kind::Secret521 => 66,
            Kind::Session => 8,
            Kind::HmacSha256 => 32,
            Kind::HmacSha384 => 48,
            Kind::HmacSha512 => 64,
        }
    }

    /// Returns whether the key type supports a usage
    pub fn allows_usage(&self, usage: DdiKeyUsage) -> bool {
        matches!(
            (self, usage),
            (
                Kind::Rsa2kPublic | Kind::Rsa3kPublic | Kind::Rsa4kPublic,
                DdiKeyUsage::SignVerify | DdiKeyUsage::EncryptDecrypt | DdiKeyUsage::Unwrap,
            ) | (
                Kind::Rsa2kPrivate | Kind::Rsa3kPrivate | Kind::Rsa4kPrivate,
                DdiKeyUsage::SignVerify | DdiKeyUsage::EncryptDecrypt | DdiKeyUsage::Unwrap,
            ) | (
                Kind::Rsa2kPrivateCrt | Kind::Rsa3kPrivateCrt | Kind::Rsa4kPrivateCrt,
                DdiKeyUsage::SignVerify | DdiKeyUsage::EncryptDecrypt | DdiKeyUsage::Unwrap,
            ) | (
                Kind::Ecc256Private | Kind::Ecc384Private | Kind::Ecc521Private,
                DdiKeyUsage::SignVerify | DdiKeyUsage::Derive,
            ) | (
                Kind::Ecc256Public | Kind::Ecc384Public | Kind::Ecc521Public,
                DdiKeyUsage::SignVerify | DdiKeyUsage::Derive,
            ) | (
                Kind::Aes128
                    | Kind::Aes192
                    | Kind::Aes256
                    | Kind::AesXtsBulk256
                    | Kind::AesGcmBulk256
                    | Kind::AesGcmBulk256Unapproved,
                DdiKeyUsage::EncryptDecrypt,
            ) | (
                Kind::Secret256 | Kind::Secret384 | Kind::Secret521,
                DdiKeyUsage::Derive
            ) | (
                Kind::HmacSha256 | Kind::HmacSha384 | Kind::HmacSha512,
                DdiKeyUsage::SignVerify,
            ) | (Kind::AesHmac640, DdiKeyUsage::EncryptDecrypt)
        )
    }

    pub fn as_crt(&self) -> Result<Kind, ManticoreError> {
        match self {
            Kind::Rsa2kPrivate => Ok(Kind::Rsa2kPrivateCrt),
            Kind::Rsa3kPrivate => Ok(Kind::Rsa3kPrivateCrt),
            Kind::Rsa4kPrivate => Ok(Kind::Rsa4kPrivateCrt),
            _ => Err(ManticoreError::InvalidKeyType),
        }
    }

    pub fn as_pub(&self) -> Result<Kind, ManticoreError> {
        match self {
            Kind::Rsa2kPublic | Kind::Rsa2kPrivate | Kind::Rsa2kPrivateCrt => Ok(Kind::Rsa2kPublic),
            Kind::Rsa3kPublic | Kind::Rsa3kPrivate | Kind::Rsa3kPrivateCrt => Ok(Kind::Rsa3kPublic),
            Kind::Rsa4kPublic | Kind::Rsa4kPrivate | Kind::Rsa4kPrivateCrt => Ok(Kind::Rsa4kPublic),
            Kind::Ecc256Public | Kind::Ecc256Private => Ok(Kind::Ecc256Public),
            Kind::Ecc384Public | Kind::Ecc384Private => Ok(Kind::Ecc384Public),
            Kind::Ecc521Public | Kind::Ecc521Private => Ok(Kind::Ecc521Public),
            _ => Err(ManticoreError::InvalidKeyType),
        }
    }

    pub fn is_bulk_key(&self) -> bool {
        matches!(
            self,
            Kind::AesXtsBulk256 | Kind::AesGcmBulk256 | Kind::AesGcmBulk256Unapproved
        )
    }
}

/// Metadata flags for an Entry.
#[bitfield(u16)]
pub(crate) struct EntryFlags {
    // Public flags that can be set by the caller.
    /// Tells if the Entry is generated or not
    pub(crate) generated: bool,

    /// Tells if the Entry was imported or not
    pub(crate) imported: bool,

    /// Below 4 bits are mutually exclusive
    /// Below 4 bits are set by user
    /// Tells if the Entry can sign and verify attestation report
    pub(crate) allow_sign_verify: bool,

    /// Tells if the Entry can encrypt and decrypt
    pub(crate) allow_encrypt_decrypt: bool,

    /// Tells if the Entry can unwrap key.
    /// There is no use case for wrapping key for now, so flag for wrapping key is omnitted.
    pub(crate) allow_unwrap: bool,

    /// Tells if the Entry can be used to derive other keys
    pub(crate) allow_derive: bool,

    /// Tells if the Entry is available for session only or not
    pub(crate) session_only: bool,

    // Private flags internal to Entry.
    /// Tells if the Entry was disabled or not
    disabled: bool,

    /// Internal use
    /// Tells if this Entry is a key for signing/verifying attestation report
    pub(crate) is_attestation_key: bool,

    #[bits(7)]
    reserved: u16,
}

/// Convert EntryFlags to KeyAttestationReport's flags bitfield representation
impl From<EntryFlags> for KeyFlags {
    fn from(entry_flags: EntryFlags) -> Self {
        let mut flags = KeyFlags::new();

        if entry_flags.imported() {
            flags.set_is_imported(true);
        }

        if entry_flags.session_only() {
            flags.set_is_session_key(true);
        }

        if entry_flags.generated() {
            flags.set_is_generated(true);
        }

        if entry_flags.allow_encrypt_decrypt() {
            flags.set_can_encrypt(true);
            flags.set_can_decrypt(true);
        }

        if entry_flags.allow_sign_verify() {
            flags.set_can_sign(true);
            flags.set_can_verify(true);
        }

        if entry_flags.allow_unwrap() {
            flags.set_can_unwrap(true);
        }

        if entry_flags.allow_derive() {
            flags.set_can_derive(true);
        }

        flags
    }
}

/// Logical entity for the key in the [Table]. It stores the key and its metadata.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    inner: Arc<RwLock<EntryInner>>,
}

impl Entry {
    /// Creates a new [Entry] instance.
    /// # Arguments
    /// * `app_id` - Application ID that owns the Entry.
    /// * `flags` - Metadata flags for the Entry.
    /// * `kind` - Kind of the Entry.
    /// * `key` - Cryptographic Key for the Entry.
    /// * `sess_id` - Optional App Session ID that owns the session_only entry.
    ///
    /// # Returns
    /// * A new [Entry] instance.
    pub(crate) fn new(
        app_id: Uuid,
        flags: EntryFlags,
        kind: Kind,
        key: Key,
        sess_id_or_key_tag: u16,
    ) -> Self {
        Entry {
            inner: Arc::new(RwLock::new(EntryInner::new(
                app_id,
                flags,
                kind,
                key,
                sess_id_or_key_tag,
            ))),
        }
    }

    /// Returns the size of the key in bytes as used by physical device.
    /// For emulation, the actual size may be different but we need to still
    /// account as per the physical device.
    ///
    /// # Returns
    /// * Size of the key in bytes.
    pub(crate) fn size(&self) -> usize {
        self.inner.read().size()
    }

    /// Returns the Application ID that owns the Entry.
    ///
    /// # Returns
    /// * Application ID that owns the Entry.
    pub(crate) fn app_id(&self) -> Uuid {
        self.inner.read().app_id()
    }

    /// Returns the Kind of the Entry.
    ///
    /// # Returns
    /// * Kind of the Entry.
    pub(crate) fn kind(&self) -> Kind {
        self.inner.read().kind()
    }

    /// Returns the Cryptographic Key for the Entry.
    /// This is a clone of the actual key.
    ///
    /// # Returns
    /// * Cryptographic Key for the Entry.
    pub(crate) fn key(&self) -> Key {
        self.inner.read().key()
    }

    /// Returns the physical sess_id key for the Entry
    ///
    /// # Returns
    /// * App session ID that owns this Entry.
    pub(crate) fn physical_sess_id(&self) -> Option<u16> {
        self.inner.read().physical_sess_id()
    }

    pub(crate) fn key_tag(&self) -> Option<u16> {
        self.inner.read().key_tag()
    }

    pub(crate) fn flags(&self) -> EntryFlags {
        self.inner.read().flags()
    }

    /// Returns if the Entry is disabled or not.
    ///
    /// # Returns
    /// * True if the Entry is disabled, false otherwise.
    pub(crate) fn disabled(&self) -> bool {
        self.inner.read().disabled()
    }

    /// Marks the Entry as disabled.
    pub(crate) fn set_disabled(&mut self) {
        self.inner.write().set_disabled();
    }

    pub(crate) fn disabled_at(&self) -> Option<Instant> {
        self.inner.read().disabled_at()
    }

    /// Returns the strong reference count of the Entry.
    ///
    /// # Returns
    /// * Strong reference count of the Entry.
    ///
    /// # Safety
    /// This method by itself is safe, but using it correctly requires extra care.
    /// Another thread can change the strong count at any time, including potentially
    /// between calling this method and acting on the result.
    #[allow(unused)]
    pub(crate) fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Returns the session_only flag for the Entry.
    ///
    /// # Returns
    /// * Session_only flag for the Entry.
    pub(crate) fn session_only(&self) -> bool {
        self.inner.read().session_only()
    }

    /// Returns the generated flag for the Entry.
    ///
    /// # Returns
    /// * Generated flag for the Entry.
    #[allow(unused)]
    pub(crate) fn generated(&self) -> bool {
        self.inner.read().generated()
    }

    /// Returns the imported flag for the Entry.
    ///
    /// # Returns
    /// * Imported flag for the Entry.
    #[allow(unused)]
    pub(crate) fn imported(&self) -> bool {
        self.inner.read().imported()
    }

    /// Returns the allow_sign_verify flag for the Entry.
    ///
    /// # Returns
    /// * allow_sign_verify flag for the Entry.
    pub(crate) fn allow_sign_verify(&self) -> bool {
        self.inner.read().allow_sign_verify()
    }

    /// Returns the allow_encrypt_decrypt flag for the Entry.
    ///
    /// # Returns
    /// * allow_encrypt_decrypt flag for the Entry.
    pub(crate) fn allow_encrypt_decrypt(&self) -> bool {
        self.inner.read().allow_encrypt_decrypt()
    }

    /// Returns the allow_unwrap flag for the Entry.
    ///
    /// # Returns
    /// * allow_unwrap flag for the Entry.
    pub(crate) fn allow_unwrap(&self) -> bool {
        self.inner.read().allow_unwrap()
    }

    /// Returns the allow_derive flag for the Entry.
    ///
    /// # Returns
    /// * allow_derive flag for the Entry.
    pub(crate) fn allow_derive(&self) -> bool {
        self.inner.read().allow_derive()
    }

    /// Returns the is_attestation_key flag for the Entry.
    ///
    /// # Returns
    /// * is_attestation_key flag for the Entry.
    pub(crate) fn is_attestation_key(&self) -> bool {
        self.inner.read().is_attestation_key()
    }
}

#[derive(Debug, Clone)]
struct EntryInner {
    app_id: Uuid,
    flags: EntryFlags,
    kind: Kind,
    key: Key,
    disabled_at: Option<Instant>,
    sess_id_or_key_tag: u16,
}

impl EntryInner {
    fn new(app_id: Uuid, flags: EntryFlags, kind: Kind, key: Key, sess_id_or_key_tag: u16) -> Self {
        Self {
            app_id,
            flags,
            kind,
            key,
            disabled_at: None,
            sess_id_or_key_tag,
        }
    }

    fn size(&self) -> usize {
        self.kind.size()
    }

    fn app_id(&self) -> Uuid {
        self.app_id
    }

    fn kind(&self) -> Kind {
        self.kind
    }

    fn key(&self) -> Key {
        self.key.clone()
    }

    fn physical_sess_id(&self) -> Option<u16> {
        if self.flags.session_only() {
            Some(self.sess_id_or_key_tag)
        } else {
            None
        }
    }

    fn key_tag(&self) -> Option<u16> {
        if !self.flags.session_only() && self.sess_id_or_key_tag != 0 {
            Some(self.sess_id_or_key_tag)
        } else {
            None
        }
    }

    fn flags(&self) -> EntryFlags {
        self.flags
    }

    fn disabled(&self) -> bool {
        self.flags.disabled()
    }

    fn set_disabled(&mut self) {
        self.disabled_at = Some(Instant::now());
        self.flags.set_disabled(true);
    }

    fn disabled_at(&self) -> Option<Instant> {
        self.disabled_at
    }

    fn session_only(&self) -> bool {
        self.flags.session_only()
    }

    #[allow(unused)]
    fn generated(&self) -> bool {
        self.flags.generated()
    }

    #[allow(unused)]
    fn imported(&self) -> bool {
        self.flags.imported()
    }

    fn allow_sign_verify(&self) -> bool {
        self.flags.allow_sign_verify()
    }

    fn allow_encrypt_decrypt(&self) -> bool {
        self.flags.allow_encrypt_decrypt()
    }

    fn allow_unwrap(&self) -> bool {
        self.flags.allow_unwrap()
    }

    fn allow_derive(&self) -> bool {
        self.flags.allow_derive()
    }

    fn is_attestation_key(&self) -> bool {
        self.flags.is_attestation_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rsa::generate_rsa;

    #[test]
    fn test_kind_get_size() {
        assert_eq!(Kind::Rsa2kPublic.size(), 260);
        assert_eq!(Kind::Rsa3kPublic.size(), 388);
        assert_eq!(Kind::Rsa4kPublic.size(), 516);
        assert_eq!(Kind::Rsa2kPrivate.size(), 516);
        assert_eq!(Kind::Rsa3kPrivate.size(), 772);
        assert_eq!(Kind::Rsa4kPrivate.size(), 1028);
        assert_eq!(Kind::Rsa2kPrivateCrt.size(), 1284);
        assert_eq!(Kind::Rsa3kPrivateCrt.size(), 1924);
        assert_eq!(Kind::Rsa4kPrivateCrt.size(), 2564);
    }

    // This test helps achieve 100% test coverage
    #[test]
    fn test_debug_trait_print() {
        let key_tag = 0x5453;

        let (rsa_private_key, _rsa_public_key) = generate_rsa(3072).unwrap();
        let kind = Kind::Rsa3kPrivate;
        let entry = Entry::new(
            Uuid::from_bytes([0x1; 16]),
            EntryFlags::default(),
            kind,
            Key::RsaPrivate(rsa_private_key),
            key_tag,
        );

        println!("Kind {:?}", kind.clone());
        println!("Entry {:?}", entry);
        println!("key = {:?}", entry.key());
        println!("app_session_id (physical) = {:?}", entry.physical_sess_id());
    }

    #[test]
    fn test_create_persistent_entry() {
        let key_tag = 0x5453;

        let (rsa_private_key, _rsa_public_key) = generate_rsa(2048).unwrap();
        let entry = Entry::new(
            Uuid::from_bytes([0x1; 16]),
            EntryFlags::default(),
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            key_tag,
        );

        assert!(!entry.session_only());
    }

    #[test]
    fn test_create_session_only_entry() {
        let (rsa_private_key, _rsa_public_key) = generate_rsa(2048).unwrap();
        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        let entry = Entry::new(
            Uuid::from_bytes([0x1; 16]),
            flags,
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            1,
        );

        assert!(entry.session_only());
    }

    #[test]
    fn test_to_keyflags() {
        let (rsa_private_key, _) = generate_rsa(2048).unwrap();
        let mut flags = EntryFlags::default();
        flags.set_imported(true);
        flags.set_session_only(true);
        flags.set_generated(true);
        flags.set_allow_encrypt_decrypt(true);
        flags.set_allow_sign_verify(true);
        flags.set_allow_unwrap(true);
        flags.set_allow_derive(true);
        let entry = Entry::new(
            Uuid::from_bytes([0x1; 16]),
            flags,
            Kind::Rsa2kPrivate,
            Key::RsaPrivate(rsa_private_key),
            1,
        );

        let keyflags: KeyFlags = entry.flags().into();
        assert!(keyflags.is_imported());
        assert!(keyflags.is_session_key());
        assert!(keyflags.is_generated());
        assert!(keyflags.can_encrypt());
        assert!(keyflags.can_decrypt());
        assert!(keyflags.can_sign());
        assert!(keyflags.can_verify());
        assert!(!keyflags.can_wrap());
        assert!(keyflags.can_unwrap());
        assert!(keyflags.can_derive());
    }
}
