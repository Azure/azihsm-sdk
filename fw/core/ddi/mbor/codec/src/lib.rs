// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

mod decode;
mod encode;
mod len;

pub use azihsm_fw_hsm_pal_traits::DmaBuf;
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

/// Trait for DDI structs that support the frame-then-fill encoding pattern.
///
/// Enables nested structs to participate in a parent's frame by exposing
/// their frame parameters and frame output as associated types. The derive
/// macro generates this for any `#[ddi(map)]` struct that has at least one
/// non-optional slice field or `#[ddi(frame)]` child.
///
/// # Usage
///
/// This trait is derive-only — do not implement manually. Use
/// `#[ddi(frame)]` on a parent field to opt in to nested framing:
///
/// ```ignore
/// #[derive(Ddi)]
/// #[ddi(map)]
/// pub struct Parent<'a> {
///     #[ddi(id = 1, frame)]
///     pub child: Child<'a>,    // child participates in frame
///     #[ddi(id = 2, len = 32)]
///     pub data: &'a [u8],      // direct slice
/// }
/// ```
pub trait MborFrameable {
    /// Parameters needed by [`mbor_frame`](Self::mbor_frame) — lengths for
    /// slice fields and values for inline primitive fields.
    type FrameParams;

    /// The companion frame struct with `&'a mut [u8]` slots for each
    /// reservable byte-slice field (including nested frames).
    type Frame<'a>;

    /// Layout struct mirroring [`Frame`](Self::Frame), but recording each
    /// reservable region as an offset range within the encoder's buffer
    /// instead of a borrow. Produced by [`mbor_reserve`](Self::mbor_reserve)
    /// and consumed by [`mbor_from_layout`](Self::mbor_from_layout).
    type Layout;

    /// Encode MBOR structure (map header, field IDs, inline primitives)
    /// and reserve mutable slots for byte-slice fields.
    ///
    /// Returns the frame struct whose fields point into the encoder's
    /// output buffer.
    fn mbor_frame<'a>(
        encoder: &mut MborEncoder<'a>,
        params: Self::FrameParams,
    ) -> Result<Self::Frame<'a>, MborEncodeError>;

    /// Like [`mbor_frame`](Self::mbor_frame), but returns a layout
    /// recording where each reservable region was written instead of
    /// borrowing those regions. Used to defer fill across an `await` or
    /// other point where holding a borrow of the buffer is inconvenient.
    fn mbor_reserve(
        encoder: &mut MborEncoder<'_>,
        params: Self::FrameParams,
    ) -> Result<Self::Layout, MborEncodeError>;

    /// Materialize a [`Frame`](Self::Frame) from a previously recorded
    /// [`Layout`](Self::Layout).
    ///
    /// # Safety
    ///
    /// `buf_ptr` must point to the start of the same buffer that was
    /// passed to the encoder when [`mbor_reserve`](Self::mbor_reserve)
    /// produced `layout`, and that buffer must be at least as long as
    /// the largest `end` recorded in `layout`. The caller must also
    /// ensure no other live `&mut` references alias any byte covered by
    /// `layout`'s recorded ranges for the lifetime `'a`.
    #[allow(unsafe_code)]
    unsafe fn mbor_from_layout<'a>(buf_ptr: *mut u8, layout: &Self::Layout) -> Self::Frame<'a>;
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
