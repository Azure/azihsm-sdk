// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TOC (Table of Contents) entry types and wire-level helpers.
//!
//! Each TOC entry is a 32-bit word stored on the wire in **big-endian**
//! byte order (matches the host-side codec at
//! `ddi/tbor/codec/src/toc.rs`).  The top 6 bits identify the entry
//! type; the remaining 26 bits carry a type-specific encoding.  All
//! bit-shift extractions and packs in this module operate on the word
//! after the BE load (`from_be_bytes`) or before the BE store
//! (`to_be_bytes`), so the high bits of the in-memory `u32` are the
//! first bits on the wire.

use azihsm_fw_hsm_pal_traits::DmaBuf;

/// Maximum number of TOC entries per message.
pub const MAX_TOC_ENTRIES: usize = 32;

/// Maximum variable-length data size (13-bit field).
pub const MAX_DATA_SIZE: usize = 8191;

/// Request header size in bytes.
pub const REQ_HEADER_LEN: usize = 4;

/// Response header size in bytes.
pub const RESP_HEADER_LEN: usize = 8;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

// ── TOC entry type IDs ─────────────────────────────────────────────────

/// Known TOC entry type identifiers (6-bit, 0–63).
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

impl TocType {
    /// Try to convert a raw 6-bit type value to a known type.
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::SessionId),
            1 => Some(Self::KeyId),
            2 => Some(Self::SealedKey),
            3 => Some(Self::Uint8),
            4 => Some(Self::Uint16),
            5 => Some(Self::Uint32),
            6 => Some(Self::Uint64),
            7 => Some(Self::Buffer),
            8 => Some(Self::None),
            9 => Some(Self::Padding),
            _ => None,
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
    SealedKey(&'a DmaBuf),
    /// 8-bit unsigned integer (type 3, inline 8-bit).
    Uint8(u8),
    /// 16-bit unsigned integer (type 4, inline 16-bit).
    Uint16(u16),
    /// 32-bit unsigned integer (type 5, offset/length, len must be 4).
    Uint32(u32),
    /// 64-bit unsigned integer (type 6, offset/length, len must be 8).
    Uint64(u64),
    /// Variable-length byte buffer (type 7, offset/length).
    Buffer(&'a DmaBuf),
    /// Absent value (type 8). Used as a placeholder for optional fields.
    None,
    /// Alignment padding (type 9, offset/length). Data bytes are ignored.
    Padding(&'a DmaBuf),
    /// Unrecognized entry type (10–63). Preserved for forward compatibility.
    Unknown { entry_type: u8, raw_bits: u32 },
}

// ── Raw TOC word manipulation ──────────────────────────────────────────

/// Extract the 6-bit entry type from a raw 32-bit LE TOC word.
#[inline(always)]
pub fn raw_toc_entry_type(word: u32) -> u8 {
    ((word >> 26) & 0x3F) as u8
}

/// Extract the 13-bit length from an offset/length TOC word.
#[inline(always)]
pub fn raw_toc_length(word: u32) -> usize {
    ((word >> 13) & 0x1FFF) as usize
}

/// Extract the 13-bit offset from an offset/length TOC word.
#[inline(always)]
pub fn raw_toc_offset(word: u32) -> usize {
    (word & 0x1FFF) as usize
}

/// Extract the inline 8-bit value from a uint8 TOC word.
#[inline(always)]
pub fn raw_toc_inline_u8(word: u32) -> u8 {
    (word & 0xFF) as u8
}

/// Extract the inline 16-bit big-endian value from a TOC word.
/// Used by session_id, key_id, uint16.
#[inline(always)]
pub fn raw_toc_inline_u16(word: u32) -> u16 {
    (word & 0xFFFF) as u16
}

// ── TOC word read helpers (from buffer) ────────────────────────────────

/// Read the raw 32-bit TOC word at the given index.
///
/// TOC entries are big-endian packed bitfields: entry_type occupies the
/// MSBs of the first wire byte, and inline 16-bit values occupy bytes 2–3
/// in big-endian order. Reading as BE makes all bit-shift extractions
/// work naturally.
#[inline(always)]
pub fn read_toc_word(buf: &[u8], header_len: usize, toc_index: usize) -> u32 {
    let base = header_len + toc_index * 4;
    u32::from_be_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]])
}

/// Read inline uint8 value from TOC entry at the given index.
#[inline(always)]
pub fn read_toc_inline_u8(buf: &[u8], header_len: usize, toc_index: usize) -> u8 {
    raw_toc_inline_u8(read_toc_word(buf, header_len, toc_index))
}

/// Read inline uint16 value from TOC entry at the given index.
///
/// The value is in the lower 16 bits of the BE-interpreted TOC word,
/// which corresponds to bytes 2–3 of the entry in big-endian order.
#[inline(always)]
pub fn read_toc_inline_u16(buf: &[u8], header_len: usize, toc_index: usize) -> u16 {
    raw_toc_inline_u16(read_toc_word(buf, header_len, toc_index))
}

/// Read a DMA-branded buffer slice from the data section via an
/// offset/length TOC entry.  Sub-slicing a `&DmaBuf` preserves the
/// brand so handlers can hand the result directly to PAL crypto
/// primitives without copying.
#[inline(always)]
pub fn read_toc_buffer(
    buf: &DmaBuf,
    header_len: usize,
    toc_index: usize,
    data_start: usize,
) -> &DmaBuf {
    let word = read_toc_word(buf, header_len, toc_index);
    let length = raw_toc_length(word);
    let offset = raw_toc_offset(word);
    &buf[data_start + offset..data_start + offset + length]
}

/// Read a uint32 from the data section via an offset/length TOC entry.
#[inline(always)]
pub fn read_toc_uint32(buf: &[u8], header_len: usize, toc_index: usize, data_start: usize) -> u32 {
    let word = read_toc_word(buf, header_len, toc_index);
    let offset = raw_toc_offset(word);
    let base = data_start + offset;
    u32::from_le_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]])
}

/// Read a uint64 from the data section via an offset/length TOC entry.
#[inline(always)]
pub fn read_toc_uint64(buf: &[u8], header_len: usize, toc_index: usize, data_start: usize) -> u64 {
    let word = read_toc_word(buf, header_len, toc_index);
    let offset = raw_toc_offset(word);
    let base = data_start + offset;
    u64::from_le_bytes([
        buf[base],
        buf[base + 1],
        buf[base + 2],
        buf[base + 3],
        buf[base + 4],
        buf[base + 5],
        buf[base + 6],
        buf[base + 7],
    ])
}

// ── TOC word write helpers ─────────────────────────────────────────────

/// Build a raw 32-bit TOC word for an inline uint8 entry.
#[inline(always)]
pub fn build_toc_inline_u8(entry_type: u8, value: u8) -> u32 {
    ((entry_type as u32) << 26) | (value as u32)
}

/// Build a raw 32-bit TOC word for an inline uint16 entry.
///
/// The 16-bit value occupies the lower 16 bits of the BE word, which
/// maps to bytes 2–3 on the wire in big-endian order.
#[inline(always)]
pub fn build_toc_inline_u16(entry_type: u8, value: u16) -> u32 {
    ((entry_type as u32) << 26) | (value as u32)
}

/// Build a raw 32-bit TOC word for a none entry (type 8, all payload zero).
#[inline(always)]
pub fn build_toc_none() -> u32 {
    (TocType::None as u32) << 26
}

/// Build a raw 32-bit TOC word for an offset/length entry.
#[inline(always)]
pub fn build_toc_offset_len(entry_type: u8, length: usize, offset: usize) -> u32 {
    ((entry_type as u32) << 26) | ((length as u32 & 0x1FFF) << 13) | (offset as u32 & 0x1FFF)
}

/// Write a raw 32-bit BE TOC word into the buffer at the given index.
#[inline(always)]
pub fn write_toc_word(buf: &mut [u8], header_len: usize, toc_index: usize, word: u32) {
    let base = header_len + toc_index * 4;
    buf[base..base + 4].copy_from_slice(&word.to_be_bytes());
}

// ── Decode a full TOC entry from a validated buffer ────────────────────

/// Decode a single TOC entry at the given index.
///
/// This function assumes the buffer has already been structurally validated
/// (header, TOC count, offset/length bounds). It is used by `RequestView`
/// and `ResponseView` iterators.
pub fn decode_toc_entry<'a>(
    buf: &'a DmaBuf,
    header_len: usize,
    toc_index: usize,
    data_start: usize,
) -> TocEntry<'a> {
    let word = read_toc_word(buf, header_len, toc_index);
    let entry_type = raw_toc_entry_type(word);

    match entry_type {
        0 => TocEntry::SessionId(read_toc_inline_u16(buf, header_len, toc_index)),
        1 => TocEntry::KeyId(read_toc_inline_u16(buf, header_len, toc_index)),
        2 => TocEntry::SealedKey(read_toc_buffer(buf, header_len, toc_index, data_start)),
        3 => TocEntry::Uint8(raw_toc_inline_u8(word)),
        4 => TocEntry::Uint16(read_toc_inline_u16(buf, header_len, toc_index)),
        5 => TocEntry::Uint32(read_toc_uint32(buf, header_len, toc_index, data_start)),
        6 => TocEntry::Uint64(read_toc_uint64(buf, header_len, toc_index, data_start)),
        7 => TocEntry::Buffer(read_toc_buffer(buf, header_len, toc_index, data_start)),
        8 => TocEntry::None,
        9 => TocEntry::Padding(read_toc_buffer(buf, header_len, toc_index, data_start)),
        _ => TocEntry::Unknown {
            entry_type,
            raw_bits: word,
        },
    }
}
