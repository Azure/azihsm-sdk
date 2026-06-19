// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for TBOR encoding and decoding.

/// Wire-level decode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Message buffer shorter than minimum header size.
    BufferTooShort { needed: usize, available: usize },
    /// Protocol version not supported.
    UnsupportedVersion(u8),
    /// Message truncated: declared TOC count implies more bytes than available.
    MessageTruncated { needed: usize, available: usize },
    /// TOC entry's offset+length exceeds data section.
    OffsetLengthOutOfBounds {
        entry_index: usize,
        offset: usize,
        length: usize,
        data_size: usize,
    },
    /// Fixed-size type (uint32/uint64) has wrong length.
    InvalidFixedLength {
        entry_index: usize,
        entry_type: u8,
        expected: usize,
        actual: usize,
    },
    /// Opcode does not match the expected value (typed decode).
    OpcodeMismatch { expected: u8, actual: u8 },
    /// Expected TOC entry type at a given position.
    UnexpectedTocType {
        entry_index: usize,
        expected: u8,
        actual: u8,
    },
    /// A required field is missing from the message.
    MissingField { name: &'static str, entry_type: u8 },
    /// A duplicate field was found.
    DuplicateField { name: &'static str, entry_type: u8 },
    /// None TOC entry (type 8) has non-zero reserved payload bits.
    InvalidNonePayload { entry_index: usize, raw_bits: u32 },
    /// Invalid enum discriminant value.
    InvalidEnumValue { field: &'static str, value: u32 },
    /// Response carries a non-zero firmware status code (a typed
    /// [`HsmError`](azihsm_fw_hsm_pal_traits::HsmError) discriminant
    /// emitted by the FW dispatcher via `encode_tbor_err`). Surfaced
    /// by typed `decode_response` so that host callers can recover the
    /// specific FW error instead of silently accepting the placeholder
    /// error envelope or failing with a generic `UnexpectedTocType`.
    FwError(u32),
    /// Data-section TOC offsets are not monotonically non-decreasing
    /// across consecutive fields. Raised only by the `decode_mut`
    /// fast path, which performs a single forward `split_at_mut`
    /// pass and therefore requires field regions to be ordered by
    /// offset (the canonical encoder always produces this layout).
    NonMonotonicTocOffsets {
        prev_entry: usize,
        curr_entry: usize,
    },
}

/// Wire-level encode errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Output buffer too small for the encoded message.
    BufferTooSmall { needed: usize, available: usize },
    /// Already at maximum 32 TOC entries.
    TooManyTocEntries,
    /// Variable-length data exceeds 8191-byte limit.
    DataTooLarge { size: usize },
    /// Data section total exceeds 13-bit offset range.
    DataOffsetOverflow { offset: usize },
}

impl From<DecodeError> for azihsm_fw_hsm_pal_traits::HsmError {
    #[inline]
    fn from(_: DecodeError) -> Self {
        Self::DdiDecodeFailed
    }
}

impl From<EncodeError> for azihsm_fw_hsm_pal_traits::HsmError {
    #[inline]
    fn from(_: EncodeError) -> Self {
        Self::DdiEncodeFailed
    }
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort { needed, available } => {
                write!(
                    f,
                    "buffer too short: need {} bytes, have {}",
                    needed, available
                )
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: 0x{:02X}", v),
            Self::MessageTruncated { needed, available } => {
                write!(
                    f,
                    "message truncated: need {} bytes, have {}",
                    needed, available
                )
            }
            Self::OffsetLengthOutOfBounds {
                entry_index,
                offset,
                length,
                data_size,
            } => {
                write!(
                    f,
                    "TOC[{}] offset+length out of bounds: offset={}, length={}, data_size={}",
                    entry_index, offset, length, data_size
                )
            }
            Self::InvalidFixedLength {
                entry_index,
                entry_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "TOC[{}] type {} has invalid length: expected {}, got {}",
                    entry_index, entry_type, expected, actual
                )
            }
            Self::OpcodeMismatch { expected, actual } => {
                write!(
                    f,
                    "opcode mismatch: expected 0x{:02X}, got 0x{:02X}",
                    expected, actual
                )
            }
            Self::UnexpectedTocType {
                entry_index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "TOC[{}] unexpected type: expected {}, got {}",
                    entry_index, expected, actual
                )
            }
            Self::MissingField { name, entry_type } => {
                write!(f, "missing required field '{}' (type {})", name, entry_type)
            }
            Self::DuplicateField { name, entry_type } => {
                write!(f, "duplicate field '{}' (type {})", name, entry_type)
            }
            Self::InvalidNonePayload {
                entry_index,
                raw_bits,
            } => {
                write!(
                    f,
                    "TOC[{}] none entry has non-zero reserved bits: 0x{:08X}",
                    entry_index, raw_bits
                )
            }
            Self::InvalidEnumValue { field, value } => {
                write!(f, "invalid enum value for '{}': {}", field, value)
            }
            Self::FwError(status) => {
                write!(f, "firmware returned error status 0x{:08X}", status)
            }
            Self::NonMonotonicTocOffsets {
                prev_entry,
                curr_entry,
            } => {
                write!(
                    f,
                    "non-monotonic TOC offsets between entries {} and {}",
                    prev_entry, curr_entry
                )
            }
        }
    }
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => {
                write!(
                    f,
                    "buffer too small: need {} bytes, have {}",
                    needed, available
                )
            }
            Self::TooManyTocEntries => write!(f, "too many TOC entries (max 32)"),
            Self::DataTooLarge { size } => {
                write!(f, "data too large: {} bytes (max 8191)", size)
            }
            Self::DataOffsetOverflow { offset } => {
                write!(f, "data offset overflow: {} (max 8191)", offset)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}
