// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for TBOR encoding and decoding.
//!
//! Variants carry a payload only when a consumer needs it:
//! * [`DecodeError::UnsupportedVersion`] preserves the offending version byte
//!   so error messages can identify it.
//! * [`DecodeError::FwError`] carries the firmware status code so callers
//!   (`azihsm_ddi_interface`) can surface the exact FW error.
//!
//! All other variants are bare — diagnostic context (offsets, lengths,
//! field names) is intentionally omitted to keep the API small.

/// Wire-level decode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Message buffer shorter than the minimum required size.
    BufferTooShort,
    /// Protocol version not supported.
    UnsupportedVersion(u8),
    /// Declared TOC count implies more bytes than the buffer holds.
    MessageTruncated,
    /// A TOC entry's offset+length exceeds the data section.
    OffsetLengthOutOfBounds,
    /// A fixed-size type (uint32/uint64) has the wrong length.
    InvalidFixedLength,
    /// TOC entry type does not match the expected type at this position.
    UnexpectedTocType,
    /// `None` TOC entry has non-zero reserved payload bits.
    InvalidNonePayload,
    /// Response carries a non-zero firmware status code.
    FwError(u32),
}

/// Wire-level encode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Output buffer too small for the encoded message.
    BufferTooSmall,
    /// Already at the maximum 32 TOC entries.
    TooManyTocEntries,
    /// Required TOC entry missing — caller invoked
    /// [`RequestEncoder::finish`](crate::RequestEncoder::finish) (or
    /// the response equivalent) without pushing at least one TOC
    /// entry.  The TBOR wire format requires every message to carry
    /// ≥ 1 TOC entry.
    MissingTocEntries,
    /// Variable-length data exceeds the 8191-byte limit.
    DataTooLarge,
    /// Data section total exceeds the 13-bit offset range.
    DataOffsetOverflow,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("buffer too short"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: 0x{:02X}", v),
            Self::MessageTruncated => f.write_str("message truncated"),
            Self::OffsetLengthOutOfBounds => f.write_str("TOC offset+length out of bounds"),
            Self::InvalidFixedLength => f.write_str("TOC entry has invalid length"),
            Self::UnexpectedTocType => f.write_str("unexpected TOC entry type"),
            Self::InvalidNonePayload => f.write_str("none entry has non-zero reserved bits"),
            Self::FwError(status) => write!(f, "firmware error: 0x{:08X}", status),
        }
    }
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::TooManyTocEntries => f.write_str("too many TOC entries (max 32)"),
            Self::MissingTocEntries => f.write_str("missing required TOC entries"),
            Self::DataTooLarge => f.write_str("data too large (max 8191 bytes)"),
            Self::DataOffsetOverflow => f.write_str("data offset overflow (max 8191)"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}
