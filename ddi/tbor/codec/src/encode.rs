// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent encoder for TBOR messages.
//!
//! Strategy: data bytes are staged forward of the maximum possible TOC
//! region while building, then shifted left into their final position on
//! [`Encoder::finish`] once the final TOC count is known. This keeps the
//! API allocation-free and copies each payload byte exactly once.
//!
//! `Encoder<H>` is generic over header kind; [`RequestEncoder`] and
//! [`ResponseEncoder`] are the public type aliases consumers use.

use core::marker::PhantomData;

use crate::error::EncodeError;
use crate::header::Header;
use crate::header::Request;
use crate::header::Response;
use crate::toc::*;

/// Fluent encoder for TBOR messages.
///
/// Use [`RequestEncoder::new`] or [`ResponseEncoder::new`] (the type
/// aliases) to construct, chain `*_entry` methods, then call
/// [`finish`](Self::finish) to backpatch the header and obtain the
/// completed wire bytes.
#[derive(Debug)]
pub struct Encoder<'a, H: Header> {
    buf: &'a mut [u8],
    header: H,
    toc_words: [u32; MAX_TOC_ENTRIES],
    toc_count: usize,
    /// Bytes written so far to the staged data region (relative to
    /// [`stage_base`](Self::stage_base)).
    data_offset: usize,
    _phantom: PhantomData<fn() -> H>,
}

/// Fluent encoder for TBOR **request** messages.
pub type RequestEncoder<'a> = Encoder<'a, Request>;

/// Fluent encoder for TBOR **response** messages.
pub type ResponseEncoder<'a> = Encoder<'a, Response>;

// ── Construction ───────────────────────────────────────────────────────

impl<'a> RequestEncoder<'a> {
    /// Create a new request encoder writing into `buf`.
    pub fn new(buf: &'a mut [u8], version: u8, opcode: u8) -> Self {
        Self::with_header(buf, Request { version, opcode })
    }
}

impl<'a> ResponseEncoder<'a> {
    /// Create a new response encoder writing into `buf`.
    pub fn new(buf: &'a mut [u8], version: u8, status: u32, fips_approved: bool) -> Self {
        Self::with_header(
            buf,
            Response {
                version,
                flags: if fips_approved {
                    Response::FIPS_APPROVED_FLAG
                } else {
                    0
                },
                status,
            },
        )
    }
}

// ── Shared encoder surface ─────────────────────────────────────────────

impl<'a, H: Header> Encoder<'a, H> {
    fn with_header(buf: &'a mut [u8], header: H) -> Self {
        Self {
            buf,
            header,
            toc_words: [0u32; MAX_TOC_ENTRIES],
            toc_count: 0,
            data_offset: 0,
            _phantom: PhantomData,
        }
    }

    /// Compute the total encoded message length without writing.
    pub fn encoded_len(&self) -> usize {
        H::LEN + self.toc_count * TOC_ENTRY_LEN + self.data_offset
    }

    // ── TOC builders ───────────────────────────────────────────────

    /// Add a `session_id` TOC entry (inline 16-bit).
    pub fn session_id(mut self, id: u16) -> Result<Self, EncodeError> {
        self.push_toc(build_inline_u16(TocType::SessionId, id))?;
        Ok(self)
    }

    /// Add a `key_id` TOC entry (inline 16-bit).
    pub fn key_id(mut self, id: u16) -> Result<Self, EncodeError> {
        self.push_toc(build_inline_u16(TocType::KeyId, id))?;
        Ok(self)
    }

    /// Add a `uint8` TOC entry (inline 8-bit).
    pub fn uint8(mut self, value: u8) -> Result<Self, EncodeError> {
        self.push_toc(build_inline_u8(TocType::Uint8, value))?;
        Ok(self)
    }

    /// Add a `uint16` TOC entry (inline 16-bit).
    pub fn uint16(mut self, value: u16) -> Result<Self, EncodeError> {
        self.push_toc(build_inline_u16(TocType::Uint16, value))?;
        Ok(self)
    }

    /// Add a `uint32` TOC entry (offset/length, 4 bytes in data section).
    pub fn uint32(mut self, value: u32) -> Result<Self, EncodeError> {
        let offset = self.data_offset;
        self.push_toc(build_offset_len(TocType::Uint32, 4, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a `uint64` TOC entry (offset/length, 8 bytes in data section).
    pub fn uint64(mut self, value: u64) -> Result<Self, EncodeError> {
        let offset = self.data_offset;
        self.push_toc(build_offset_len(TocType::Uint64, 8, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a variable-length `buffer` TOC entry, copying `data`.
    pub fn buffer(self, data: &[u8]) -> Result<Self, EncodeError> {
        self.offset_len_with_data(TocType::Buffer, data)
    }

    /// Add a variable-length `buffer` TOC entry reserving `len` bytes
    /// without writing data. The reserved bytes' contents in the final
    /// message are whatever the caller previously placed there.
    pub fn buffer_reserve(mut self, len: usize) -> Result<Self, EncodeError> {
        check_data_size(len)?;
        let offset = self.data_offset;
        self.push_toc(build_offset_len(TocType::Buffer, len, offset))?;
        self.data_offset += len;
        Ok(self)
    }

    /// Add a `sealed_key` TOC entry, copying `data`.
    pub fn sealed_key(self, data: &[u8]) -> Result<Self, EncodeError> {
        self.offset_len_with_data(TocType::SealedKey, data)
    }

    /// Add a `none` TOC entry (placeholder for an absent optional field).
    pub fn none(mut self) -> Result<Self, EncodeError> {
        self.push_toc(build_none())?;
        Ok(self)
    }

    /// Add a `padding` TOC entry reserving `len` zero bytes in the data section.
    pub fn padding(mut self, len: usize) -> Result<Self, EncodeError> {
        check_data_size(len)?;
        let offset = self.data_offset;
        self.push_toc(build_offset_len(TocType::Padding, len, offset))?;
        if len > 0 {
            let range = self.stage_range(len)?;
            self.buf[range].fill(0);
            self.data_offset += len;
            self.check_offset_overflow()?;
        }
        Ok(self)
    }

    // ── Finalize ───────────────────────────────────────────────────

    /// Finalize the message.
    ///
    /// Shifts staged data into place, writes the header and TOC entries,
    /// and returns the complete message as a sub-slice of the caller's buffer.
    pub fn finish(self) -> Result<&'a [u8], EncodeError> {
        if self.toc_count == 0 {
            // At least one TOC entry is required by spec.
            return Err(EncodeError::MissingTocEntries);
        }

        let data_start = H::LEN + self.toc_count * TOC_ENTRY_LEN;
        let total = data_start + self.data_offset;

        if total > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }

        // Shift staged data from its max-TOC parking spot into its final
        // position. No-op when toc_count is already MAX_TOC_ENTRIES.
        let stage_base = Self::stage_base();
        if self.data_offset > 0 && stage_base != data_start {
            self.buf
                .copy_within(stage_base..stage_base + self.data_offset, data_start);
        }

        H::write_header(self.buf, &self.header, self.toc_count);

        for i in 0..self.toc_count {
            write_toc_word(self.buf, H::LEN, i, self.toc_words[i]);
        }

        Ok(&self.buf[..total])
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Byte offset of the data-staging area: past header + the maximum
    /// possible TOC region. Final data is shifted left from here on
    /// [`finish`](Self::finish) once the real TOC count is known.
    #[inline]
    fn stage_base() -> usize {
        H::LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN
    }

    fn push_toc(&mut self, word: u32) -> Result<(), EncodeError> {
        if self.toc_count >= MAX_TOC_ENTRIES {
            return Err(EncodeError::TooManyTocEntries);
        }
        self.toc_words[self.toc_count] = word;
        self.toc_count += 1;
        Ok(())
    }

    /// Shared offset/length entry path: bounds-check `data.len()`, push
    /// the TOC word, copy the bytes into the staging area.
    fn offset_len_with_data(mut self, ty: TocType, data: &[u8]) -> Result<Self, EncodeError> {
        check_data_size(data.len())?;
        let offset = self.data_offset;
        self.push_toc(build_offset_len(ty, data.len(), offset))?;
        self.stage_data(data)?;
        Ok(self)
    }

    /// Compute the destination range in `self.buf` for `len` new staged
    /// bytes, returning `BufferTooSmall` if it would overflow the buffer.
    fn stage_range(&self, len: usize) -> Result<core::ops::Range<usize>, EncodeError> {
        let start = Self::stage_base() + self.data_offset;
        let end = start + len;
        if end > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        Ok(start..end)
    }

    fn stage_data(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        let range = self.stage_range(data.len())?;
        self.buf[range].copy_from_slice(data);
        self.data_offset += data.len();
        self.check_offset_overflow()
    }

    #[inline]
    fn check_offset_overflow(&self) -> Result<(), EncodeError> {
        if self.data_offset > MAX_DATA_SIZE {
            return Err(EncodeError::DataOffsetOverflow);
        }
        Ok(())
    }
}

#[inline]
fn check_data_size(size: usize) -> Result<(), EncodeError> {
    if size > MAX_DATA_SIZE {
        return Err(EncodeError::DataTooLarge);
    }
    Ok(())
}
