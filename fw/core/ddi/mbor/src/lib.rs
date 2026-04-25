// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

mod decode;
mod encode;
mod len;

pub use decode::MborDecode;
pub use decode::MborDecodeError;
pub use decode::MborDecoder;
pub use encode::MborEncode;
pub use encode::MborEncodeError;
pub use encode::MborEncoder;
pub use len::MborLen;
pub use len::MborLenAccumulator;

/// MBOR field identifier type.
pub type MborId = u8;

/// MBOR map with a field count.
pub struct MborMap(pub u8);

/// Borrowed byte slice for MBOR encoding.
pub struct MborByteSlice<'a>(pub &'a [u8]);

/// Padded byte slice for MBOR encoding.
///
/// The first element is the data slice, the second is the padding byte count
/// (0–3) inserted before the data to achieve 4-byte alignment.
pub struct MborPaddedByteSlice<'a>(pub &'a [u8], pub u8);

/// Compute the number of padding bytes needed to reach the next 4-byte
/// boundary.
#[inline(always)]
pub fn pad4(len: u32) -> u32 {
    ((len + 0x3) & !0x3) - len
}

// ── Wire-format constants (identical to `ddi/serde/mbor`) ──────────────

pub const MAP_MARKER: u8 = 0xA0;
pub const MAP_FIELD_COUNT_MASK: u8 = 0b000_11111;

pub const BOOL_MARKER: u8 = 0x14;
pub const BYTES_MARKER: u8 = 0x80;

pub const BYTES_PAD_MASK: u8 = 0b0000_0011;

pub const UINT_MARKER: u8 = 0x18;
pub const U8_MASK: u8 = 0x00;
pub const U16_MASK: u8 = 0x01;
pub const U32_MASK: u8 = 0x02;
pub const U64_MASK: u8 = 0x03;

pub const U8_MARKER: u8 = UINT_MARKER | U8_MASK;
pub const U16_MARKER: u8 = UINT_MARKER | U16_MASK;
pub const U32_MARKER: u8 = UINT_MARKER | U32_MASK;
pub const U64_MARKER: u8 = UINT_MARKER | U64_MASK;
