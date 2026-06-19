// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy view over a parsed TBOR message.
//!
//! `View<H>` borrows the input buffer and provides infallible accessors
//! after a single upfront [`parse`](View::parse) pass. The header-kind
//! parameter `H` selects request vs. response framing; request- and
//! response-specific accessors are added via inherent impls on the
//! [`RequestView`] / [`ResponseView`] aliases.

use core::marker::PhantomData;

use crate::error::DecodeError;
use crate::header::Header;
use crate::header::Request;
use crate::header::Response;
use crate::toc::*;
use crate::validate::validate_toc_entries;

/// Zero-copy view over a parsed TBOR message.
///
/// Construct via [`View::parse`]. All accessors are infallible.
#[derive(Debug)]
pub struct View<'a, H: Header> {
    buf: &'a [u8],
    _phantom: PhantomData<fn() -> H>,
}

/// Zero-copy view over a TBOR **request** message.
pub type RequestView<'a> = View<'a, Request>;

/// Zero-copy view over a TBOR **response** message.
pub type ResponseView<'a> = View<'a, Response>;

impl<'a, H: Header> View<'a, H> {
    /// Parse and structurally validate a message.
    ///
    /// Validates: minimum buffer size, protocol version, TOC-count
    /// consistency with buffer length, per-entry bounds, fixed-size type
    /// lengths, and the `None`-entry reserved-bits invariant.
    ///
    /// Reserved bits outside the validated set are silently ignored per spec.
    pub fn parse(buf: &'a [u8]) -> Result<Self, DecodeError> {
        // Minimum: header + 1 TOC entry.
        if buf.len() < H::LEN + TOC_ENTRY_LEN {
            return Err(DecodeError::BufferTooShort);
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        let toc_count = toc_count_from_byte(buf[H::TOC_COUNT_BYTE]);
        let data_start = H::LEN + toc_count * TOC_ENTRY_LEN;
        if buf.len() < data_start {
            return Err(DecodeError::MessageTruncated);
        }

        validate_toc_entries(buf, H::LEN, toc_count, buf.len() - data_start)?;

        Ok(Self {
            buf,
            _phantom: PhantomData,
        })
    }

    /// Protocol version byte from the header.
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf[0]
    }

    /// Number of TOC entries (1–32).
    #[inline]
    pub fn toc_count(&self) -> usize {
        toc_count_from_byte(self.buf[H::TOC_COUNT_BYTE])
    }

    /// Byte offset where the variable-length data section starts.
    #[inline]
    pub fn data_start(&self) -> usize {
        H::LEN + self.toc_count() * TOC_ENTRY_LEN
    }

    /// Size of the variable-length data section in bytes.
    #[inline]
    pub fn data_size(&self) -> usize {
        self.buf.len() - self.data_start()
    }

    /// Total encoded message length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Always `false` for a parsed message.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The raw message bytes the view borrows from.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The raw variable-length data section.
    #[inline]
    pub fn data_section(&self) -> &'a [u8] {
        &self.buf[self.data_start()..]
    }

    /// The raw 6-bit entry-type field at the given TOC index.
    ///
    /// Useful when constructing [`DecodeError::UnexpectedTocType`] from
    /// typed-decode code: returns the wire byte even for types that
    /// [`TocType::from_raw`] would reject.
    #[inline]
    pub fn toc_entry_type(&self, index: usize) -> u8 {
        raw_entry_type(read_toc_word(self.buf, H::LEN, index))
    }

    /// Decode a single TOC entry at the given index.
    ///
    /// Infallible after [`parse`](Self::parse) succeeds.
    #[inline]
    pub fn toc_entry(&self, index: usize) -> TocEntry<'a> {
        decode_entry(self.buf, H::LEN, index, self.data_start())
    }

    /// Iterate over all TOC entries in wire order.
    pub fn toc_iter(&self) -> impl Iterator<Item = TocEntry<'a>> + '_ {
        let header_len = H::LEN;
        let data_start = self.data_start();
        (0..self.toc_count()).map(move |i| decode_entry(self.buf, header_len, i, data_start))
    }
}

// ── Request-only accessors ─────────────────────────────────────────────

impl<'a> RequestView<'a> {
    /// Operation code from the request header.
    #[inline]
    pub fn opcode(&self) -> u8 {
        self.buf[3]
    }
}

// ── Response-only accessors ────────────────────────────────────────────

impl<'a> ResponseView<'a> {
    /// Flags byte from the response header.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf[1]
    }

    /// FIPS_APPROVED flag (bit 0 of [`flags`](Self::flags)).
    #[inline]
    pub fn fips_approved(&self) -> bool {
        self.buf[1] & Response::FIPS_APPROVED_FLAG != 0
    }

    /// Status code (4-byte little-endian).
    #[inline]
    pub fn status(&self) -> u32 {
        u32::from_le_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
    }
}
