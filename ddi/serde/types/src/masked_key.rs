// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use crate::*;

pub const HMAC384_TAG_SIZE: usize = 48;
pub const HMAC384_KEY_SIZE: usize = 48;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_CBC_IV_SIZE: usize = 16;
pub const AES_CBC_TAG_SIZE: usize = HMAC384_TAG_SIZE;
pub const AES_CBC_256_KEY_SIZE: usize = 32;

pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_TAG_SIZE: usize = 16;

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, KnownLayout, PartialEq, Eq, Clone, Copy, TryFromBytes, Immutable)]
pub struct MaskedKeyHeader {
    /// Version of the masked key format.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub version: u16,

    /// Masking Algorithm.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub algorithm: MaskingKeyAlgorithm,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[repr(C, packed)]
#[derive(Debug, IntoBytes, KnownLayout, PartialEq, Eq, Clone, Copy, TryFromBytes, Immutable)]
pub struct MaskedKeyAesHeader {
    /// Length of the metadata in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub iv_len: u16,

    /// Length of post IV padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_iv_pad_len: u16,

    /// Length of the metadata in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub metadata_len: u16,

    /// Length of the post metadata padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_metadata_pad_len: u16,

    /// Length of the encrypted key in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub encrypted_key_len: u16,

    /// Length of the post encrypted key padding in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub post_encrypted_key_pad_len: u16,

    /// Length of the integrity tag in bytes.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub tag_len: u16,

    /// Reserved.
    ///     Integrity protected: Yes, by the integrity tag.
    ///     Encrypted: No.
    pub reserved: [u8; 34],
    //
    // Following fields are variable length fields
    // IV (Initialization Vector).
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // iv: [u8; iv_len],

    // Post IV Padding.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // post_iv_pad: [u8; post_iv_pad_len],

    // Masked key metadata in MBOR format.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // metadata: [u8; metadata_len],

    // Post Metadata Padding.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: No.
    // post_metadata_pad: [u8; post_metadata_pad_len],

    // Encrypted key in device native format.
    //     Integrity protected: Yes, by the integrity tag.
    //     Encrypted: Yes.
    // encrypted_key: [u8; encrypted_key_len],

    // Post Encrypted Key Padding.
    //     Integrity protected: Yes (for AES CBS), by the integrity tag.
    //     Encrypted: No.
    // post_encrypted_key_pad: [u8; post_encrypted_key_pad_len],

    // Integrity tag.
    //     Integrity protected: Not applicable.
    //     Encrypted: No.
    // tag: [u8; tag_len],
}

const _: () = {
    assert!(
        core::mem::size_of::<MaskedKeyHeader>().is_multiple_of(4),
        "MaskedKeyHeader size must be a multiple of 4 bytes"
    );

    assert!(
        core::mem::size_of::<MaskedKeyAesHeader>().is_multiple_of(4),
        "MaskedKeyAesHeader size must be a multiple of 4 bytes"
    );
};

/// Base trait for all masked key types
pub trait MaskedKeyBase<'a> {
    /// Returns the header
    fn header(&self) -> &MaskedKeyHeader;

    /// Returns the encrypted key data
    fn encrypted_key(&self) -> &[u8];

    /// Returns the metadata
    fn metadata(&self) -> &[u8];

    /// Returns the algorithm used
    fn algorithm(&self) -> MaskingKeyAlgorithm;
}

/// AES-specific masked key
#[derive(Debug)]
pub struct MaskedKeyAes<'a> {
    header: MaskedKeyHeader,
    layout: MaskedKeyAesLayout,
    payload: &'a [u8],
}

impl<'a> MaskedKeyAes<'a> {
    pub fn new(header: MaskedKeyHeader, layout: MaskedKeyAesLayout, payload: &'a [u8]) -> Self {
        Self {
            header,
            layout,
            payload,
        }
    }

    /// Returns the header
    pub fn header(&self) -> &MaskedKeyHeader {
        &self.header
    }

    /// Returns the layout information
    pub fn layout(&self) -> &MaskedKeyAesLayout {
        &self.layout
    }

    /// Returns the IV (Initialization Vector) slice
    pub fn iv(&self) -> &[u8] {
        let payload_data = &self.payload[size_of::<MaskedKeyAesHeader>()..];
        &payload_data[..self.layout.iv_len]
    }

    /// Returns the encrypted key data slice
    pub fn encrypted_key(&self) -> &[u8] {
        let payload_data = &self.payload[size_of::<MaskedKeyAesHeader>()..];
        let start = self.layout.iv_len
            + self.layout.post_iv_pad_len
            + self.layout.metadata_len
            + self.layout.post_metadata_pad_len;
        &payload_data[start..start + self.layout.encrypted_key_len]
    }

    /// Returns the metadata slice
    pub fn metadata(&self) -> &[u8] {
        let payload_data = &self.payload[size_of::<MaskedKeyAesHeader>()..];
        let start = self.layout.iv_len + self.layout.post_iv_pad_len;
        &payload_data[start..start + self.layout.metadata_len]
    }

    /// Returns the authentication tag slice
    pub fn tag(&self) -> &[u8] {
        let payload_data = &self.payload[size_of::<MaskedKeyAesHeader>()..];
        let start = self.layout.iv_len
            + self.layout.post_iv_pad_len
            + self.layout.metadata_len
            + self.layout.post_metadata_pad_len
            + self.layout.encrypted_key_len
            + self.layout.post_encrypted_key_pad_len;
        &payload_data[start..start + self.layout.tag_len]
    }
}

/// AES-specific layout
#[derive(Debug)]
pub struct MaskedKeyAesLayout {
    pub metadata_len: usize,
    pub post_metadata_pad_len: usize,
    pub encrypted_key_len: usize,
    pub post_encrypted_key_pad_len: usize,
    pub iv_len: usize,
    pub post_iv_pad_len: usize,
    pub tag_len: usize,
}

/// Masked Key Format
/// This structure represents the format of a masked key, which includes metadata and encrypted key material.
/// This is a runtime structure that holds references to parsed data, not a wire format.
#[derive(Debug)]
pub struct MaskedKey<'a> {
    /// Masked Key Header.
    pub header: MaskedKeyHeader,

    /// Pre-computed layout information for efficient access.
    pub layout: MaskedKeyLayout,

    /// Masked Key Payload.
    pub payload: &'a [u8],
}

/// Enum representing different types of key layouts
#[derive(Debug, Clone)]
pub enum KeyLayoutType {
    /// AES-based key layout (CBC, GCM)
    Aes {
        iv_len: usize,
        post_iv_pad_len: usize,
        tag_len: usize,
    },
    // Future: Other key types can be added here
}

impl KeyLayoutType {
    /// Returns the total length of key-specific fields
    pub fn key_specific_len(&self) -> usize {
        match self {
            KeyLayoutType::Aes {
                iv_len,
                post_iv_pad_len,
                tag_len,
            } => size_of::<MaskedKeyAesHeader>() + iv_len + post_iv_pad_len + tag_len,
        }
    }

    /// Returns the IV length (if applicable)
    pub fn iv_len(&self) -> Option<usize> {
        match self {
            KeyLayoutType::Aes { iv_len, .. } => Some(*iv_len),
        }
    }

    /// Returns the post-IV padding length (if applicable)
    pub fn post_iv_pad_len(&self) -> Option<usize> {
        match self {
            KeyLayoutType::Aes {
                post_iv_pad_len, ..
            } => Some(*post_iv_pad_len),
        }
    }

    /// Returns the tag length (if applicable)
    pub fn tag_len(&self) -> Option<usize> {
        match self {
            KeyLayoutType::Aes { tag_len, .. } => Some(*tag_len),
        }
    }
}

/// Holds the calculated layout of a masked key.
#[derive(Debug)]
pub struct MaskedKeyLayout {
    // Common fields for all key types
    metadata_len: usize,
    post_metadata_pad_len: usize,
    encrypted_key_len: usize,
    post_encrypted_key_pad_len: usize,

    // Key-type specific layout
    pub key_type: KeyLayoutType,
}

impl MaskedKeyLayout {
    /// Creates a new AES-based layout
    pub fn new_aes(
        metadata_len: usize,
        post_metadata_pad_len: usize,
        encrypted_key_len: usize,
        post_encrypted_key_pad_len: usize,
        iv_len: usize,
        post_iv_pad_len: usize,
        tag_len: usize,
    ) -> Self {
        Self {
            metadata_len,
            post_metadata_pad_len,
            encrypted_key_len,
            post_encrypted_key_pad_len,
            key_type: KeyLayoutType::Aes {
                iv_len,
                post_iv_pad_len,
                tag_len,
            },
        }
    }

    /// Returns the total length of the masked key structure.
    pub fn total_len(&self) -> usize {
        size_of::<MaskedKeyHeader>()
            + self.metadata_len
            + self.post_metadata_pad_len
            + self.encrypted_key_len
            + self.post_encrypted_key_pad_len
            + self.key_type.key_specific_len()
    }

    /// Returns the IV length (for AES keys)
    pub fn iv_len(&self) -> usize {
        self.key_type.iv_len().unwrap_or(0)
    }

    /// Returns the post-IV padding length (for AES keys)
    pub fn post_iv_pad_len(&self) -> usize {
        self.key_type.post_iv_pad_len().unwrap_or(0)
    }

    /// Returns the tag length (for AES keys)
    pub fn tag_len(&self) -> usize {
        self.key_type.tag_len().unwrap_or(0)
    }

    /// Checks if this layout is for an AES key
    pub fn is_aes(&self) -> bool {
        matches!(self.key_type, KeyLayoutType::Aes { .. })
    }

    pub fn metadata_len(&self) -> usize {
        self.metadata_len
    }

    pub fn post_metadata_pad_len(&self) -> usize {
        self.post_metadata_pad_len
    }

    pub fn encrypted_key_len(&self) -> usize {
        self.encrypted_key_len
    }

    pub fn post_encrypted_key_pad_len(&self) -> usize {
        self.post_encrypted_key_pad_len
    }
}

/// Pre-encoded masked key structure.
/// This structure is used to prepare a masked key for encoding.
/// Contains only methods that are common to all key types.
#[derive(Debug)]
pub struct PreEncodedMaskedKey<'a> {
    /// The masking key algorithm used for this masked key.
    algo: MaskingKeyAlgorithm,
    /// The buffer that holds the masked key data.
    buffer: &'a mut [u8],
    /// The calculated layout of the masked key structure.
    layout: MaskedKeyLayout,
}

/// AES-specific pre-encoded masked key
#[derive(Debug)]
pub struct PreEncodeMaskedKeyAes<'a> {
    /// The base pre-encoded masked key
    base: PreEncodedMaskedKey<'a>,
}

/// Enum to handle different pre-encoded masked key types
#[derive(Debug)]
pub enum PreEncodeMaskedKeyType<'a> {
    Aes(PreEncodeMaskedKeyAes<'a>),
}

impl<'a> PreEncodedMaskedKey<'a> {
    /// Creates a new `PreEncodeMaskedKey` from the output buffer and layout.
    pub fn new(algo: MaskingKeyAlgorithm, buffer: &'a mut [u8], layout: MaskedKeyLayout) -> Self {
        Self {
            algo,
            buffer,
            layout,
        }
    }

    /// Convert to a type-safe enum variant based on the algorithm
    pub fn into_typed(self) -> PreEncodeMaskedKeyType<'a> {
        match self.algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 | MaskingKeyAlgorithm::AesGcm256 => {
                PreEncodeMaskedKeyType::Aes(PreEncodeMaskedKeyAes { base: self })
            }
            _ => unreachable!("Unsupported algorithm"),
        }
    }

    /// Returns the masking key algorithm used for this masked key.
    pub fn algo(&self) -> MaskingKeyAlgorithm {
        self.algo
    }
}

impl PreEncodeMaskedKeyAes<'_> {
    /// Returns an immutable slice of the Initialization Vector (IV).
    pub fn iv(&self) -> &[u8] {
        let start = size_of::<MaskedKeyHeader>() + size_of::<MaskedKeyAesHeader>();
        let end = start + self.base.layout.iv_len();
        &self.base.buffer[start..end]
    }

    /// Returns a mutable slice of the Initialization Vector (IV).
    pub fn iv_mut(&mut self) -> &mut [u8] {
        let start = size_of::<MaskedKeyHeader>() + size_of::<MaskedKeyAesHeader>();
        let end = start + self.base.layout.iv_len();
        &mut self.base.buffer[start..end]
    }

    /// Returns an immutable slice of the encrypted key data.
    pub fn encrypted_key(&self) -> &[u8] {
        let start = size_of::<MaskedKeyHeader>()
            + size_of::<MaskedKeyAesHeader>()
            + self.base.layout.iv_len()
            + self.base.layout.post_iv_pad_len()
            + self.base.layout.metadata_len
            + self.base.layout.post_metadata_pad_len;
        let end = start + self.base.layout.encrypted_key_len;
        &self.base.buffer[start..end]
    }

    /// Returns a mutable slice of the encrypted key data.
    pub fn encrypted_key_mut(&mut self) -> &mut [u8] {
        let start = size_of::<MaskedKeyHeader>()
            + size_of::<MaskedKeyAesHeader>()
            + self.base.layout.iv_len()
            + self.base.layout.post_iv_pad_len()
            + self.base.layout.metadata_len
            + self.base.layout.post_metadata_pad_len;
        let end = start + self.base.layout.encrypted_key_len;
        &mut self.base.buffer[start..end]
    }

    /// Returns an immutable slice of the metadata.
    pub fn metadata(&self) -> &[u8] {
        let start = size_of::<MaskedKeyHeader>()
            + size_of::<MaskedKeyAesHeader>()
            + self.base.layout.iv_len()
            + self.base.layout.post_iv_pad_len();
        let end = start + self.base.layout.metadata_len;
        &self.base.buffer[start..end]
    }

    /// Returns a mutable slice of the metadata.
    pub fn metadata_mut(&mut self) -> &mut [u8] {
        let start = size_of::<MaskedKeyHeader>()
            + size_of::<MaskedKeyAesHeader>()
            + self.base.layout.iv_len()
            + self.base.layout.post_iv_pad_len();
        let end = start + self.base.layout.metadata_len;
        &mut self.base.buffer[start..end]
    }

    /// Returns an immutable slice of the integrity tag.
    pub fn tag(&self) -> &[u8] {
        let start: usize = self.base.buffer.len() - self.base.layout.tag_len();
        &self.base.buffer[start..]
    }

    /// Returns a mutable slice of the integrity tag.
    pub fn tag_mut(&mut self) -> &mut [u8] {
        let start = self.base.buffer.len() - self.base.layout.tag_len();
        &mut self.base.buffer[start..]
    }

    /// Returns the masking key algorithm used for this masked key.
    pub fn algo(&self) -> MaskingKeyAlgorithm {
        self.base.algo()
    }

    /// Returns the data to be tagged based on the algorithm type.
    /// For AES CBC: everything except the tag itself
    /// For AES GCM: data up to (but not including) the encrypted_key
    pub fn tagged_data(&self) -> &[u8] {
        match self.base.algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => {
                // For AES CBC, tag everything except the tag itself
                let end = self.base.buffer.len() - self.base.layout.tag_len();
                &self.base.buffer[..end]
            }
            MaskingKeyAlgorithm::AesGcm256 => {
                // For AES GCM, tag only up to (but not including) the encrypted_key
                let end = size_of::<MaskedKeyHeader>()
                    + size_of::<MaskedKeyAesHeader>()
                    + self.base.layout.iv_len()
                    + self.base.layout.post_iv_pad_len()
                    + self.base.layout.metadata_len
                    + self.base.layout.post_metadata_pad_len;
                &self.base.buffer[..end]
            }
            _ => {
                unreachable!()
            }
        }
    }
}

impl PreEncodeMaskedKeyType<'_> {
    /// Returns an immutable slice of the encrypted key data.
    pub fn encrypted_key(&self) -> &[u8] {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.encrypted_key(),
        }
    }

    /// Returns a mutable slice of the encrypted key data.
    pub fn encrypted_key_mut(&mut self) -> &mut [u8] {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.encrypted_key_mut(),
        }
    }

    /// Returns an immutable slice of the metadata.
    pub fn metadata(&self) -> &[u8] {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.metadata(),
        }
    }

    /// Returns a mutable slice of the metadata.
    pub fn metadata_mut(&mut self) -> &mut [u8] {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.metadata_mut(),
        }
    }

    /// Returns the masking key algorithm used for this masked key.
    pub fn algo(&self) -> MaskingKeyAlgorithm {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.algo(),
        }
    }

    /// Returns the data to be tagged based on the algorithm type.
    pub fn tagged_data(&self) -> &[u8] {
        match self {
            PreEncodeMaskedKeyType::Aes(aes) => aes.tagged_data(),
        }
    }
}

impl<'a> MaskedKey<'a> {
    /// Creates a new MaskedKey with the provided layout.
    ///
    /// # Arguments
    /// * `header` - The masked key header containing version and algorithm information.
    /// * `layout` - The layout information for efficient field access.
    /// * `payload` - The raw payload data containing the AES payload structure and key data.
    ///
    /// # Returns
    /// * `MaskedKey<'a>` - A new MaskedKey instance with the layout information.
    pub fn new(header: MaskedKeyHeader, layout: MaskedKeyLayout, payload: &'a [u8]) -> Self {
        Self {
            header,
            layout,
            payload,
        }
    }

    /// Returns the buffer size needed to encode a masked key.
    ///
    /// # Arguments
    /// * `algo` - The masking key algorithm used.
    /// * `metadata_len` - The length of the metadata.
    /// * `encrypted_key_len` - The length of the encrypted key.
    ///
    /// # Returns
    /// * `usize` - The total length of the masked key structure after encoding
    pub fn encoded_length(
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
    ) -> usize {
        Self::calculate_layout(algo, metadata_len, encrypted_key_len).total_len()
    }

    /// Calculates the layout of the masked key structure.
    fn calculate_layout(
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
    ) -> MaskedKeyLayout {
        let (iv_len, tag_len) = match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => (AES_CBC_IV_SIZE, AES_CBC_TAG_SIZE),
            MaskingKeyAlgorithm::AesGcm256 => (AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE),
            _ => unreachable!(), // Invalid algorithm, should not happen
        };

        // Calculate padding needed to align each component to a 4-byte boundary.
        let post_iv_pad_len = iv_len.next_multiple_of(4) - iv_len;
        let post_metadata_pad_len = metadata_len.next_multiple_of(4) - metadata_len;
        let post_encrypted_key_pad_len = encrypted_key_len.next_multiple_of(4) - encrypted_key_len;

        // Create AES layout since both current algorithms are AES-based
        MaskedKeyLayout::new_aes(
            metadata_len,
            post_metadata_pad_len,
            encrypted_key_len,
            post_encrypted_key_pad_len,
            iv_len,
            post_iv_pad_len,
            tag_len,
        )
    }

    /// Pre-encodes a masked key.
    /// This function prepares the masked key for encoding by calculating the layout and filling the header.
    ///
    /// # Arguments
    /// * `version` - The version of the masked key format.
    /// * `algo` - The masking key algorithm used.
    /// * `metadata_len` - The length of the metadata.
    /// * `encrypted_key_len` - The length of the key after encryption.
    /// * `out_data` - The output buffer to hold the pre-encoded masked key.
    ///
    /// # Returns
    /// * `Result<PreEncodeMaskedKeyType<'a>, MaskedKeyError>` - The pre-encoded masked key structure.
    pub fn pre_encode(
        version: u16,
        algo: MaskingKeyAlgorithm,
        metadata_len: usize,
        encrypted_key_len: usize,
        out_data: &mut [u8],
    ) -> Result<PreEncodeMaskedKeyType<'_>, MaskedKeyError> {
        if encrypted_key_len == 0 {
            Err(MaskedKeyError::InvalidLength)?;
        }

        // Calculate the layout of the masked key.
        let layout = Self::calculate_layout(algo, metadata_len, encrypted_key_len);

        // Check if the output buffer is exactly the right size.
        if out_data.len() != layout.total_len() {
            Err(MaskedKeyError::InvalidLength)?;
        }

        let (header_slice, remaining) = out_data.split_at_mut(size_of::<MaskedKeyHeader>());
        let header: &mut MaskedKeyHeader = MaskedKeyHeader::try_mut_from_bytes(header_slice)
            .map_err(|_| MaskedKeyError::InvalidLength)?;

        header.version = version;
        header.algorithm = algo;

        // Set up the payload based on the algorithm
        match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 | MaskingKeyAlgorithm::AesGcm256 => {
                // For AES algorithms, we need to set up the AES payload
                let (aes_payload, _) = remaining.split_at_mut(size_of::<MaskedKeyAesHeader>());
                let payload: &mut MaskedKeyAesHeader =
                    MaskedKeyAesHeader::try_mut_from_bytes(aes_payload)
                        .map_err(|_| MaskedKeyError::InvalidLength)?;

                payload.iv_len = layout.iv_len() as u16;
                payload.post_iv_pad_len = layout.post_iv_pad_len() as u16;
                payload.metadata_len = layout.metadata_len() as u16;
                payload.post_metadata_pad_len = layout.post_metadata_pad_len() as u16;
                payload.encrypted_key_len = layout.encrypted_key_len() as u16;
                payload.post_encrypted_key_pad_len = layout.post_encrypted_key_pad_len() as u16;
                payload.tag_len = layout.tag_len() as u16;
            }
            _ => {
                Err(MaskedKeyError::InvalidAlgorithm)?;
            }
        }
        let pre_encoded = PreEncodedMaskedKey::new(algo, out_data, layout);
        Ok(pre_encoded.into_typed())
    }
}

#[derive(Debug)]
pub enum MaskedKeyError {
    /// Invalid algorithm
    InvalidAlgorithm,
    /// Invalid length
    InvalidLength,
    /// The destination buffer is too small to hold the encoded data.
    InsufficientBuffer,
    /// Decoding error
    DecodeError,
    /// The header is malformed or contains invalid data.
    HeaderDecodeError,
    /// The header could not be encoded.
    HeaderEncodeError,
    /// The masking key algorithm specified is not supported.
    InvalidMaskingKeyAlgorithm,
    /// The HMAC tag generation failed.
    HmacTagGenerationFailed,
    /// The HMAC tag verification failed.
    HmacTagVerificationFailed,
    /// Invalid AES key.
    AesKeyInvalid,
    /// AES encryption failed.
    AesEncryptionFailed,
    /// AES decryption failed.
    AesDecryptionFailed,
    /// The AES key is not set in the environment.
    AesKeyNotSet,
    /// The HMAC key is not set in the environment.
    HmacKeyNotSet,
    /// The HMAC key is invalid.
    HmacKeyInvalid,
    /// The metadata encoding failed.
    MetadataEncodeError,
    /// The metadata decoding failed.
    MetadataDecodeError,
    /// The combined AES and HMAC key is invalid.
    AesHmacComboKeyInvalid,
    /// The key derivation function (KBKDF) failed.
    KbkdfFailed,
    /// Invalid Encrypted Key Length
    InvalidEncryptedKeyLength,
}

#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u16)]
pub enum MaskingKeyAlgorithm {
    /// AES CBC 256 with HMAC 384
    AesCbc256Hmac384 = 1,

    /// AES GCM 256
    AesGcm256 = 2,
}

impl TryFrom<u16> for MaskingKeyAlgorithm {
    type Error = MaskedKeyError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AesCbc256Hmac384),
            2 => Ok(Self::AesGcm256),
            _ => Err(MaskedKeyError::InvalidAlgorithm),
        }
    }
}

impl From<MaskingKeyAlgorithm> for u16 {
    fn from(algo: MaskingKeyAlgorithm) -> u16 {
        match algo {
            MaskingKeyAlgorithm::AesCbc256Hmac384 => 1,
            MaskingKeyAlgorithm::AesGcm256 => 2,
            _ => unreachable!(),
        }
    }
}

/// Masked Key Metadata
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiMaskedKeyMetadata {
    /// SVN
    #[ddi(id = 1)]
    pub svn: Option<u64>,

    /// Key Kind
    #[ddi(id = 2)]
    pub key_type: DdiKeyType,

    /// Key Attributes
    #[ddi(id = 3)]
    pub key_attributes: DdiMaskedKeyAttributes,

    /// Key BKS2 Number
    #[ddi(id = 4)]
    /// The BKS2 index ndicating which BKS2 this key belongs to.
    pub bks2_index: Option<u16>,

    /// Key Name
    #[ddi(id = 5)]
    pub key_tag: Option<u16>,

    /// Key label
    #[ddi(id = 6)]
    pub key_label: MborByteArray<DDI_MAX_KEY_LABEL_LENGTH>,
}

/// DDI Key Properties Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiMaskedKeyAttributes {
    /// Key Attributes Blob
    #[ddi(id = 1)]
    pub blob: [u8; 32],
}
