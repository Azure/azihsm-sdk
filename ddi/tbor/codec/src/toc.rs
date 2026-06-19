// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TOC (Table of Contents) entry types and wire-level primitives.
//!
//! Each TOC entry is a 32-bit word stored on the wire in **big-endian**
//! order. The top 6 bits identify the entry type; the remaining 26 bits
//! carry a type-specific encoding:
//!
//! - inline `u8`  — 18 reserved bits + 8-bit value
//! - inline `u16` — 10 reserved bits + 16-bit value
//! - offset/length — 13-bit length + 13-bit offset

/// Maximum number of TOC entries per message.
pub const MAX_TOC_ENTRIES: usize = 32;

/// Maximum variable-length data size (13-bit field).
pub const MAX_DATA_SIZE: usize = 8191;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Wire size of a single TOC entry in bytes.
pub(crate) const TOC_ENTRY_LEN: usize = 4;

/// 6-bit entry-type mask.
const TYPE_MASK: u32 = 0x3F;
/// 13-bit offset/length field mask.
const FIELD_13_MASK: u32 = 0x1FFF;
/// 26-bit inline payload mask (all bits below the entry-type field).
pub(crate) const INLINE_PAYLOAD_MASK: u32 = 0x03FF_FFFF;

// ── TocType ────────────────────────────────────────────────────────────

/// Known TOC entry type identifiers (6-bit, 0–63).
///
/// Acts as the single source of truth for both encoders and decoders:
/// every match on the entry type goes through this enum, not through
/// raw `u8` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TocType {
    /// Session identifier (inline 16-bit).
    SessionId = 0,
    /// Key identifier (inline 16-bit).
    KeyId = 1,
    /// Sealed key blob (offset/length into data section).
    SealedKey = 2,
    /// 8-bit unsigned integer (inline 8-bit).
    Uint8 = 3,
    /// 16-bit unsigned integer (inline 16-bit).
    Uint16 = 4,
    /// 32-bit unsigned integer (offset/length, 4 bytes in data section).
    Uint32 = 5,
    /// 64-bit unsigned integer (offset/length, 8 bytes in data section).
    Uint64 = 6,
    /// Variable-length byte buffer (offset/length into data section).
    Buffer = 7,
    /// Absent value placeholder for optional fields.
    None = 8,
    /// Alignment padding (offset/length, data bytes ignored).
    Padding = 9,
}

/// Whether a known TOC entry stores its value inline in the TOC word or
/// references the variable-length data section by offset/length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TocShape {
    /// Value lives entirely in the 26-bit TOC payload.
    Inline,
    /// Value lives in the data section, referenced by 13-bit offset + 13-bit length.
    /// `fixed_length = Some(n)` constrains the length to exactly `n` bytes;
    /// `None` permits any length.
    OffsetLen { fixed_length: Option<usize> },
}

impl TocType {
    /// Try to convert a raw 6-bit type value to a known type.
    /// Returns `None` for unknown / forward-compat types (10–63).
    pub fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0 => Self::SessionId,
            1 => Self::KeyId,
            2 => Self::SealedKey,
            3 => Self::Uint8,
            4 => Self::Uint16,
            5 => Self::Uint32,
            6 => Self::Uint64,
            7 => Self::Buffer,
            8 => Self::None,
            9 => Self::Padding,
            _ => return None,
        })
    }

    /// Wire-shape classification used by validator and encoder.
    pub(crate) fn shape(self) -> TocShape {
        match self {
            Self::SessionId | Self::KeyId | Self::Uint8 | Self::Uint16 | Self::None => {
                TocShape::Inline
            }
            Self::Uint32 => TocShape::OffsetLen {
                fixed_length: Some(4),
            },
            Self::Uint64 => TocShape::OffsetLen {
                fixed_length: Some(8),
            },
            Self::SealedKey | Self::Buffer | Self::Padding => {
                TocShape::OffsetLen { fixed_length: None }
            }
        }
    }
}

// ── Decoded TOC entry ──────────────────────────────────────────────────

/// A decoded TOC entry. Lifetime `'a` borrows from the message buffer
/// for types that reference the variable-length data section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TocEntry<'a> {
    /// Session identifier (type 0, inline 16-bit).
    SessionId(u16),
    /// Key identifier (type 1, inline 16-bit).
    KeyId(u16),
    /// Sealed key blob (type 2, offset/length).
    SealedKey(&'a [u8]),
    /// 8-bit unsigned integer (type 3, inline 8-bit).
    Uint8(u8),
    /// 16-bit unsigned integer (type 4, inline 16-bit).
    Uint16(u16),
    /// 32-bit unsigned integer (type 5, offset/length, len must be 4).
    Uint32(u32),
    /// 64-bit unsigned integer (type 6, offset/length, len must be 8).
    Uint64(u64),
    /// Variable-length byte buffer (type 7, offset/length).
    Buffer(&'a [u8]),
    /// Absent value (type 8). Used as a placeholder for optional fields.
    None,
    /// Alignment padding (type 9, offset/length). Data bytes are ignored.
    Padding(&'a [u8]),
    /// Unrecognized entry type (10–63). Preserved for forward compatibility.
    Unknown { entry_type: u8, raw_bits: u32 },
}

// ── Raw word accessors (private to the crate) ──────────────────────────

/// Decode the wire TOC-count byte (5-bit field, biased by 1).
#[inline]
pub(crate) fn toc_count_from_byte(byte: u8) -> usize {
    (byte & 0x1F) as usize + 1
}

/// Extract the 6-bit entry type from a raw TOC word.
#[inline]
pub(crate) fn raw_entry_type(word: u32) -> u8 {
    ((word >> 26) & TYPE_MASK) as u8
}

/// Extract the 13-bit length from an offset/length TOC word.
#[inline]
pub(crate) fn raw_length(word: u32) -> usize {
    ((word >> 13) & FIELD_13_MASK) as usize
}

/// Extract the 13-bit offset from an offset/length TOC word.
#[inline]
pub(crate) fn raw_offset(word: u32) -> usize {
    (word & FIELD_13_MASK) as usize
}

/// Read the raw 32-bit TOC word at the given index.
///
/// TOC entries are big-endian packed bitfields: entry_type occupies the
/// MSBs of the first wire byte, and inline 16-bit values occupy bytes 2–3
/// in big-endian order. Reading as BE makes all bit-shift extractions
/// work naturally.
#[inline]
pub(crate) fn read_toc_word(buf: &[u8], header_len: usize, toc_index: usize) -> u32 {
    let base = header_len + toc_index * TOC_ENTRY_LEN;
    u32::from_be_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]])
}

/// Read a slice of the data section pointed to by an offset/length TOC entry.
#[inline]
pub(crate) fn read_toc_slice(
    buf: &[u8],
    header_len: usize,
    toc_index: usize,
    data_start: usize,
) -> &[u8] {
    let word = read_toc_word(buf, header_len, toc_index);
    let offset = raw_offset(word);
    let length = raw_length(word);
    &buf[data_start + offset..data_start + offset + length]
}

// ── Builders (private to the crate) ────────────────────────────────────

/// Build an inline-`u8` TOC word for the given entry type.
#[inline]
pub(crate) fn build_inline_u8(ty: TocType, value: u8) -> u32 {
    ((ty as u32) << 26) | (value as u32)
}

/// Build an inline-`u16` TOC word for the given entry type.
///
/// The 16-bit value occupies the lower 16 bits of the BE word, which
/// maps to bytes 2–3 on the wire in big-endian order.
#[inline]
pub(crate) fn build_inline_u16(ty: TocType, value: u16) -> u32 {
    ((ty as u32) << 26) | (value as u32)
}

/// Build an offset/length TOC word for the given entry type.
#[inline]
pub(crate) fn build_offset_len(ty: TocType, length: usize, offset: usize) -> u32 {
    ((ty as u32) << 26) | ((length as u32 & FIELD_13_MASK) << 13) | (offset as u32 & FIELD_13_MASK)
}

/// Build a TOC word for type 8 (`None`), with all payload bits zero.
#[inline]
pub(crate) fn build_none() -> u32 {
    (TocType::None as u32) << 26
}

/// Write a raw TOC word in big-endian order into the buffer at the given index.
#[inline]
pub(crate) fn write_toc_word(buf: &mut [u8], header_len: usize, toc_index: usize, word: u32) {
    let base = header_len + toc_index * TOC_ENTRY_LEN;
    buf[base..base + TOC_ENTRY_LEN].copy_from_slice(&word.to_be_bytes());
}

// ── Full-entry decode ──────────────────────────────────────────────────

/// Decode a single TOC entry at the given index.
///
/// Assumes the buffer has already been structurally validated by
/// [`crate::view::View::parse`]; bounds checks here are infallible.
pub(crate) fn decode_entry<'a>(
    buf: &'a [u8],
    header_len: usize,
    toc_index: usize,
    data_start: usize,
) -> TocEntry<'a> {
    let word = read_toc_word(buf, header_len, toc_index);
    let raw = raw_entry_type(word);

    let Some(ty) = TocType::from_raw(raw) else {
        return TocEntry::Unknown {
            entry_type: raw,
            raw_bits: word,
        };
    };

    // Inline u16 value (used by SessionId, KeyId, Uint16).
    let inline_u16 = || (word & 0xFFFF) as u16;
    // Slice from the data section (used by all offset/length variants).
    let slice = || read_toc_slice(buf, header_len, toc_index, data_start);

    match ty {
        TocType::SessionId => TocEntry::SessionId(inline_u16()),
        TocType::KeyId => TocEntry::KeyId(inline_u16()),
        TocType::SealedKey => TocEntry::SealedKey(slice()),
        TocType::Uint8 => TocEntry::Uint8((word & 0xFF) as u8),
        TocType::Uint16 => TocEntry::Uint16(inline_u16()),
        TocType::Uint32 => {
            let s = slice();
            TocEntry::Uint32(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
        TocType::Uint64 => {
            let s = slice();
            TocEntry::Uint64(u64::from_le_bytes([
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            ]))
        }
        TocType::Buffer => TocEntry::Buffer(slice()),
        TocType::None => TocEntry::None,
        TocType::Padding => TocEntry::Padding(slice()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toc_type_from_raw_round_trips_known_values() {
        for raw in 0..=9u8 {
            let ty = TocType::from_raw(raw).expect("0..=9 are known types");
            assert_eq!(ty as u8, raw);
        }
    }

    #[test]
    fn toc_type_from_raw_returns_none_for_unknown_values() {
        for raw in 10..=63u8 {
            assert!(
                TocType::from_raw(raw).is_none(),
                "raw={} should be unknown",
                raw
            );
        }
    }

    #[test]
    fn build_inline_u16_round_trips_through_raw_accessors() {
        let word = build_inline_u16(TocType::SessionId, 0xBEEF);
        assert_eq!(raw_entry_type(word), TocType::SessionId as u8);
        assert_eq!(word & 0xFFFF, 0xBEEF);
    }

    #[test]
    fn build_inline_u8_round_trips_through_raw_accessors() {
        let word = build_inline_u8(TocType::Uint8, 0xA5);
        assert_eq!(raw_entry_type(word), TocType::Uint8 as u8);
        assert_eq!(word & 0xFF, 0xA5);
    }

    #[test]
    fn build_offset_len_round_trips_through_raw_accessors() {
        let word = build_offset_len(TocType::Buffer, 0x1ABC, 0x0123);
        assert_eq!(raw_entry_type(word), TocType::Buffer as u8);
        assert_eq!(raw_length(word), 0x1ABC);
        assert_eq!(raw_offset(word), 0x0123);
    }

    #[test]
    fn build_offset_len_masks_to_13_bit_fields() {
        // Values outside the 13-bit range are silently truncated by
        // construction; verify the mask is applied so adjacent fields
        // are not corrupted.
        let word = build_offset_len(TocType::Buffer, 0xFFFF, 0xFFFF);
        assert_eq!(raw_length(word), 0x1FFF);
        assert_eq!(raw_offset(word), 0x1FFF);
        assert_eq!(raw_entry_type(word), TocType::Buffer as u8);
    }

    #[test]
    fn build_none_has_zero_payload() {
        let word = build_none();
        assert_eq!(raw_entry_type(word), TocType::None as u8);
        assert_eq!(word & INLINE_PAYLOAD_MASK, 0);
    }

    #[test]
    fn write_then_read_toc_word_round_trips_big_endian() {
        let mut buf = [0u8; 8];
        let word = 0xDEAD_BEEF;
        write_toc_word(&mut buf, 0, 1, word);
        // Entry 1 starts at offset 0 + 1 * 4 = 4.
        assert_eq!(&buf[4..8], &word.to_be_bytes());
        assert_eq!(read_toc_word(&buf, 0, 1), word);
    }

    #[test]
    fn toc_count_from_byte_decodes_low_five_bits_biased_by_one() {
        assert_eq!(toc_count_from_byte(0b0000_0000), 1);
        assert_eq!(toc_count_from_byte(0b0001_1111), 32);
        // Upper bits are reserved and must be ignored.
        assert_eq!(toc_count_from_byte(0b1110_0000), 1);
    }
}
