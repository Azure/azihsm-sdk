// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Masked-key blob layout and header serialization.
//!
//! Mirrors the host-side `MaskedKey` wire format so blobs produced by
//! the firmware can be parsed by host tooling without any conversion.
//!
//! Internal to the crate — only the public masking-key length
//! constant and [`mask`](crate::cbc::mask) are exposed through
//! [`crate`].

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use zerocopy::little_endian::U16 as Le16;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

// =============================================================================
// Constants
// =============================================================================

/// AES-256 key size in bytes.
pub(crate) const AES_CBC_256_KEY_SIZE: usize = 32;

/// AES-CBC IV size in bytes (= one AES block).
pub(crate) const AES_CBC_IV_SIZE: usize = 16;

/// HMAC-SHA-384 key size in bytes (matches the HMAC output length).
pub(crate) const HMAC384_KEY_SIZE: usize = 48;

/// HMAC-SHA-384 tag size in bytes.
pub(crate) const HMAC384_TAG_SIZE: usize = 48;

/// Masking key length for AES-CBC-256 + HMAC-SHA-384 in bytes:
/// 32-byte AES-256 encryption key followed by 48-byte HMAC-SHA-384
/// authentication key (low half ‖ high half).
pub const MASKING_KEY_AES_CBC_256_HMAC_384_LEN: usize = AES_CBC_256_KEY_SIZE + HMAC384_KEY_SIZE;

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// On-wire version identifier for the current `MaskedKey` blob format.
const MASKED_KEY_VERSION_V1: u16 = 1;

/// On-wire algorithm identifier for AES-CBC-256 + HMAC-SHA-384.
const MASKING_ALGO_AES_CBC_256_HMAC_384: u16 = 1;

/// Reserved tail length inside `MaskedKeyAesHeader`.
const MASKED_KEY_AES_HEADER_RESERVED: usize = 34;

const MASKED_KEY_HEADER_SIZE: usize = core::mem::size_of::<MaskedKeyHeader>();
const MASKED_KEY_AES_HEADER_SIZE: usize = core::mem::size_of::<MaskedKeyAesHeader>();

/// Combined size of the leading version+algo header and the AES-mode
/// length descriptors (52 B).
pub(crate) const HEADER_PREFIX_SIZE: usize = MASKED_KEY_HEADER_SIZE + MASKED_KEY_AES_HEADER_SIZE;

const _: () = {
    assert!(MASKED_KEY_HEADER_SIZE == 4);
    assert!(MASKED_KEY_AES_HEADER_SIZE == 48);
    // IV and tag are 4-byte aligned, so no post-IV or post-tag pad.
    assert!(AES_CBC_IV_SIZE.is_multiple_of(4));
    assert!(HMAC384_TAG_SIZE.is_multiple_of(4));
};

// =============================================================================
// On-wire header structs
// =============================================================================

/// Top-level `MaskedKey` envelope header: 4 bytes covering the format
/// version and the masking algorithm identifier.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub(crate) struct MaskedKeyHeader {
    version: Le16,
    algorithm: Le16,
}

impl MaskedKeyHeader {
    /// On-wire size in bytes.
    pub(crate) const SIZE: usize = core::mem::size_of::<Self>();

    /// Build the outer envelope header for an AES-CBC-256 +
    /// HMAC-SHA-384 blob.
    pub(crate) fn new_cbc() -> Self {
        Self {
            version: Le16::new(MASKED_KEY_VERSION_V1),
            algorithm: Le16::new(MASKING_ALGO_AES_CBC_256_HMAC_384),
        }
    }

    /// Parse + validate the outer envelope header from a byte slice.
    ///
    /// Accepts any slice of length `>= Self::SIZE`; only the leading
    /// `Self::SIZE` bytes are consumed.  Returns
    /// [`HsmError::MaskedKeyDecodeFailed`] for any mismatch
    /// (insufficient length, wrong version, wrong algorithm).
    pub(crate) fn parse_cbc(bytes: &[u8]) -> HsmResult<&Self> {
        if bytes.len() < Self::SIZE {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        let hdr = Self::ref_from_bytes(&bytes[..Self::SIZE])
            .map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
        if hdr.version.get() != MASKED_KEY_VERSION_V1
            || hdr.algorithm.get() != MASKING_ALGO_AES_CBC_256_HMAC_384
        {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        Ok(hdr)
    }

    /// Write self into `out[..Self::SIZE]`.
    pub(crate) fn write_into(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(self.as_bytes());
    }
}

/// AES-mode header: the seven `u16` per-component length descriptors
/// followed by the reserved tail.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub(crate) struct MaskedKeyAesHeader {
    iv_len: Le16,
    post_iv_pad_len: Le16,
    metadata_len: Le16,
    post_metadata_pad_len: Le16,
    encrypted_key_len: Le16,
    post_encrypted_key_pad_len: Le16,
    tag_len: Le16,
    rsvd: [u8; MASKED_KEY_AES_HEADER_RESERVED],
}

impl MaskedKeyAesHeader {
    /// On-wire size in bytes.
    pub(crate) const SIZE: usize = core::mem::size_of::<Self>();

    /// Build the on-wire AES header for an AES-CBC-256 + HMAC-SHA-384
    /// blob from the plaintext length.  Computes the post-padding
    /// ciphertext length internally, validates that every per-component
    /// length fits in `u16`, and rejects an empty plaintext.
    pub(crate) fn new_cbc(metadata_len: usize, plaintext_len: usize) -> HsmResult<Self> {
        if plaintext_len == 0 {
            return Err(HsmError::InvalidArg);
        }
        let encrypted_key_len = aes_cbc_encrypted_len(plaintext_len);
        let metadata_len_u16 = u16::try_from(metadata_len).map_err(|_| HsmError::InvalidArg)?;
        let encrypted_key_len_u16 =
            u16::try_from(encrypted_key_len).map_err(|_| HsmError::InvalidArg)?;
        Ok(Self {
            iv_len: Le16::new(AES_CBC_IV_SIZE as u16),
            post_iv_pad_len: Le16::new(pad4(AES_CBC_IV_SIZE) as u16),
            metadata_len: Le16::new(metadata_len_u16),
            post_metadata_pad_len: Le16::new(pad4(metadata_len) as u16),
            encrypted_key_len: Le16::new(encrypted_key_len_u16),
            post_encrypted_key_pad_len: Le16::new(pad4(encrypted_key_len) as u16),
            tag_len: Le16::new(HMAC384_TAG_SIZE as u16),
            rsvd: [0; MASKED_KEY_AES_HEADER_RESERVED],
        })
    }

    /// Parse + validate the AES-mode header from a byte slice.
    ///
    /// Accepts any slice of length `>= Self::SIZE`; only the leading
    /// `Self::SIZE` bytes are consumed.  Validates every per-component
    /// length field for self-consistency (IV/tag sizes, AES block
    /// alignment of ciphertext, 4-byte alignment of all components,
    /// non-empty ciphertext, zero reserved tail).  Returns
    /// [`HsmError::MaskedKeyDecodeFailed`] for any violation.
    pub(crate) fn parse_cbc(bytes: &[u8]) -> HsmResult<&Self> {
        if bytes.len() < Self::SIZE {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        let hdr = Self::ref_from_bytes(&bytes[..Self::SIZE])
            .map_err(|_| HsmError::MaskedKeyDecodeFailed)?;

        let iv_len = hdr.iv_len.get() as usize;
        let post_iv_pad_len = hdr.post_iv_pad_len.get() as usize;
        let metadata_len = hdr.metadata_len.get() as usize;
        let post_metadata_pad_len = hdr.post_metadata_pad_len.get() as usize;
        let ct_len = hdr.encrypted_key_len.get() as usize;
        let post_ct_pad_len = hdr.post_encrypted_key_pad_len.get() as usize;
        let tag_len = hdr.tag_len.get() as usize;

        if iv_len != AES_CBC_IV_SIZE
            || post_iv_pad_len != pad4(iv_len)
            || post_metadata_pad_len != pad4(metadata_len)
            || ct_len == 0
            || !ct_len.is_multiple_of(AES_BLOCK_SIZE)
            || post_ct_pad_len != pad4(ct_len)
            || tag_len != HMAC384_TAG_SIZE
            || !hdr.rsvd.iter().all(|&b| b == 0)
        {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        Ok(hdr)
    }

    /// Metadata length in bytes.
    pub(crate) fn metadata_len_bytes(&self) -> usize {
        self.metadata_len.get() as usize
    }

    /// Ciphertext length in bytes (post AES-CBC padding).
    pub(crate) fn ciphertext_len(&self) -> usize {
        self.encrypted_key_len.get() as usize
    }

    /// Total length of the encoded blob in bytes.
    pub(crate) fn total_len(&self) -> usize {
        HEADER_PREFIX_SIZE
            + self.iv_len.get() as usize
            + self.post_iv_pad_len.get() as usize
            + self.metadata_len.get() as usize
            + self.post_metadata_pad_len.get() as usize
            + self.encrypted_key_len.get() as usize
            + self.post_encrypted_key_pad_len.get() as usize
            + self.tag_len.get() as usize
    }

    /// Byte offset of the IV within the encoded blob.
    pub(crate) fn iv_offset(&self) -> usize {
        HEADER_PREFIX_SIZE
    }

    /// Byte offset of the metadata within the encoded blob.
    pub(crate) fn metadata_offset(&self) -> usize {
        self.iv_offset() + self.iv_len.get() as usize + self.post_iv_pad_len.get() as usize
    }

    /// Byte offset of the ciphertext within the encoded blob.
    pub(crate) fn ciphertext_offset(&self) -> usize {
        self.metadata_offset()
            + self.metadata_len.get() as usize
            + self.post_metadata_pad_len.get() as usize
    }

    /// Byte offset of the HMAC tag within the encoded blob.
    pub(crate) fn tag_offset(&self) -> usize {
        self.ciphertext_offset()
            + self.encrypted_key_len.get() as usize
            + self.post_encrypted_key_pad_len.get() as usize
    }

    /// Write self into `out[..Self::SIZE]`.
    pub(crate) fn write_into(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(self.as_bytes());
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// AES-CBC zero-padded ciphertext length for `plaintext_len` bytes.
///
/// Pads to the next multiple of the AES block size **only if** the
/// plaintext is not already block-aligned.  Unlike PKCS#7, no extra
/// block is appended when the plaintext is aligned.
///
/// The decoder recovers the original plaintext length from the
/// metadata's `key_length` field, so trailing zero-pad bytes (if any)
/// are discarded after decryption.
const fn aes_cbc_encrypted_len(plaintext_len: usize) -> usize {
    let rem = plaintext_len % AES_BLOCK_SIZE;
    if rem == 0 {
        plaintext_len
    } else {
        plaintext_len + (AES_BLOCK_SIZE - rem)
    }
}

/// 4-byte alignment pad for a field of length `len`.
const fn pad4(len: usize) -> usize {
    let r = len % 4;
    if r == 0 {
        0
    } else {
        4 - r
    }
}
