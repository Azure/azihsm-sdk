// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent encoders for TBOR request and response messages.
//!
//! The encoder uses a forward-write strategy with front reservation:
//! 1. Reserve space for header + TOC entries at the front
//! 2. Write data section forward immediately after the TOC region
//! 3. On `finish()`, backpatch the header and TOC entries
//!
//! This results in one copy of each payload into the output buffer and
//! zero heap allocations.

use azihsm_fw_hsm_pal_traits::HsmError;

use crate::toc::*;

// ── RequestEncoder ─────────────────────────────────────────────────────

/// Fluent builder for encoding a TBOR request message.
///
/// Methods are chained to add TOC entries. `finish()` writes the header
/// and returns the encoded message as a sub-slice of the output buffer.
#[derive(Debug)]
pub struct RequestEncoder<'a> {
    buf: &'a mut [u8],
    version: u8,
    opcode: u8,
    toc_words: [u32; MAX_TOC_ENTRIES],
    toc_count: usize,
    data_offset: usize,
}

impl<'a> RequestEncoder<'a> {
    /// Create a new request encoder writing into `buf`.
    pub fn new(buf: &'a mut [u8], version: u8, opcode: u8) -> Self {
        Self {
            buf,
            version,
            opcode,
            toc_words: [0u32; MAX_TOC_ENTRIES],
            toc_count: 0,
            data_offset: 0,
        }
    }

    /// Add a `session_id` TOC entry (type 0, inline 16-bit).
    pub fn session_id(mut self, id: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::SessionId as u8, id))?;
        Ok(self)
    }

    /// Add a `key_id` TOC entry (type 1, inline 16-bit).
    pub fn key_id(mut self, id: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::KeyId as u8, id))?;
        Ok(self)
    }

    /// Add a `uint8` TOC entry (type 3, inline 8-bit).
    pub fn uint8(mut self, value: u8) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u8(TocType::Uint8 as u8, value))?;
        Ok(self)
    }

    /// Add a `uint16` TOC entry (type 4, inline 16-bit).
    pub fn uint16(mut self, value: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::Uint16 as u8, value))?;
        Ok(self)
    }

    /// Add a `uint32` TOC entry (type 5, offset/length).
    pub fn uint32(mut self, value: u32) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        self.push_toc(build_toc_offset_len(TocType::Uint32 as u8, 4, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a `uint64` TOC entry (type 6, offset/length).
    pub fn uint64(mut self, value: u64) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        self.push_toc(build_toc_offset_len(TocType::Uint64 as u8, 8, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a `buffer` TOC entry (type 7, offset/length).
    pub fn buffer(mut self, data: &[u8]) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if data.len() > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(
            TocType::Buffer as u8,
            data.len(),
            offset,
        ))?;
        self.stage_data(data)?;
        Ok(self)
    }

    /// Add a `buffer` TOC entry reserving `len` bytes (for fill-later).
    /// Returns the byte range in the final message where data should be written.
    pub fn buffer_reserve(mut self, len: usize) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if len > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(TocType::Buffer as u8, len, offset))?;
        self.data_offset += len;
        Ok(self)
    }

    /// Add a `sealed_key` TOC entry (type 2, offset/length).
    pub fn sealed_key(mut self, data: &[u8]) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if data.len() > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(
            TocType::SealedKey as u8,
            data.len(),
            offset,
        ))?;
        self.stage_data(data)?;
        Ok(self)
    }

    /// Add a `none` TOC entry (type 8, placeholder for absent optional field).
    pub fn none(mut self) -> Result<Self, HsmError> {
        self.push_toc(build_toc_none())?;
        Ok(self)
    }

    /// Add a `padding` TOC entry (type 9, alignment padding in data section).
    pub fn padding(mut self, len: usize) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if len > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(TocType::Padding as u8, len, offset))?;
        // Zero-fill the padding bytes.
        if len > 0 {
            let stage_base = REQ_HEADER_LEN + MAX_TOC_ENTRIES * 4;
            let dst_start = stage_base + self.data_offset;
            let dst_end = dst_start + len;
            if dst_end > self.buf.len() {
                return Err(HsmError::TborBufferTooSmall);
            }
            for i in dst_start..dst_end {
                self.buf[i] = 0;
            }
            self.data_offset += len;
        }
        Ok(self)
    }

    /// Finalize the message. Writes header + TOC entries, shifts staged
    /// data into place, returns the complete message as a sub-slice.
    pub fn finish(self) -> Result<&'a [u8], HsmError> {
        if self.toc_count == 0 {
            return Err(HsmError::TborTooManyTocEntries); // at least 1 required
        }

        let data_start = REQ_HEADER_LEN + self.toc_count * 4;
        let total = data_start + self.data_offset;

        if total > self.buf.len() {
            return Err(HsmError::TborBufferTooSmall);
        }

        // Shift staged data from max-TOC position to actual data_start.
        let stage_base = REQ_HEADER_LEN + MAX_TOC_ENTRIES * 4; // = 132
        if self.data_offset > 0 && stage_base != data_start {
            self.buf
                .copy_within(stage_base..stage_base + self.data_offset, data_start);
        }

        // Write header as a single u32.
        let hdr = u32::from_le_bytes([self.version, 0x00, (self.toc_count - 1) as u8, self.opcode]);
        self.buf[..4].copy_from_slice(&hdr.to_le_bytes());

        // Write TOC entries.
        for i in 0..self.toc_count {
            write_toc_word(self.buf, REQ_HEADER_LEN, i, self.toc_words[i]);
        }

        Ok(&self.buf[..total])
    }

    /// Compute the total encoded message length without writing.
    pub fn encoded_len(&self) -> usize {
        REQ_HEADER_LEN + self.toc_count * 4 + self.data_offset
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn push_toc(&mut self, word: u32) -> Result<(), HsmError> {
        if self.toc_count >= MAX_TOC_ENTRIES {
            return Err(HsmError::TborTooManyTocEntries);
        }
        self.toc_words[self.toc_count] = word;
        self.toc_count += 1;
        Ok(())
    }

    fn stage_data(&mut self, data: &[u8]) -> Result<(), HsmError> {
        let stage_base = REQ_HEADER_LEN + MAX_TOC_ENTRIES * 4; // = 132
        let dst_start = stage_base + self.data_offset;
        let dst_end = dst_start + data.len();

        if dst_end > self.buf.len() {
            return Err(HsmError::TborBufferTooSmall);
        }

        self.buf[dst_start..dst_end].copy_from_slice(data);
        self.data_offset += data.len();

        if self.data_offset > MAX_DATA_SIZE {
            return Err(HsmError::TborDataOffsetOverflow);
        }

        Ok(())
    }
}

// ── ResponseEncoder ────────────────────────────────────────────────────

/// Fluent builder for encoding a TBOR response message.
#[derive(Debug)]
pub struct ResponseEncoder<'a> {
    buf: &'a mut [u8],
    version: u8,
    flags: u8,
    status: u32,
    toc_words: [u32; MAX_TOC_ENTRIES],
    toc_count: usize,
    data_offset: usize,
}

impl<'a> ResponseEncoder<'a> {
    /// Create a new response encoder.
    pub fn new(buf: &'a mut [u8], version: u8, status: u32, fips_approved: bool) -> Self {
        Self {
            buf,
            version,
            flags: if fips_approved { 0x01 } else { 0x00 },
            status,
            toc_words: [0u32; MAX_TOC_ENTRIES],
            toc_count: 0,
            data_offset: 0,
        }
    }

    /// Add a `session_id` TOC entry.
    pub fn session_id(mut self, id: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::SessionId as u8, id))?;
        Ok(self)
    }

    /// Add a `key_id` TOC entry.
    pub fn key_id(mut self, id: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::KeyId as u8, id))?;
        Ok(self)
    }

    /// Add a `uint8` TOC entry.
    pub fn uint8(mut self, value: u8) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u8(TocType::Uint8 as u8, value))?;
        Ok(self)
    }

    /// Add a `uint16` TOC entry.
    pub fn uint16(mut self, value: u16) -> Result<Self, HsmError> {
        self.push_toc(build_toc_inline_u16(TocType::Uint16 as u8, value))?;
        Ok(self)
    }

    /// Add a `uint32` TOC entry.
    pub fn uint32(mut self, value: u32) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        self.push_toc(build_toc_offset_len(TocType::Uint32 as u8, 4, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a `uint64` TOC entry.
    pub fn uint64(mut self, value: u64) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        self.push_toc(build_toc_offset_len(TocType::Uint64 as u8, 8, offset))?;
        self.stage_data(&value.to_le_bytes())?;
        Ok(self)
    }

    /// Add a `buffer` TOC entry with data (fill-now).
    pub fn buffer(mut self, data: &[u8]) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if data.len() > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(
            TocType::Buffer as u8,
            data.len(),
            offset,
        ))?;
        self.stage_data(data)?;
        Ok(self)
    }

    /// Add a `buffer` TOC entry reserving `len` bytes (fill-later).
    pub fn buffer_reserve(mut self, len: usize) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if len > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(TocType::Buffer as u8, len, offset))?;
        self.data_offset += len;
        Ok(self)
    }

    /// Add a `sealed_key` TOC entry.
    pub fn sealed_key(mut self, data: &[u8]) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if data.len() > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(
            TocType::SealedKey as u8,
            data.len(),
            offset,
        ))?;
        self.stage_data(data)?;
        Ok(self)
    }

    /// Add a `none` TOC entry (type 8, placeholder for absent optional field).
    pub fn none(mut self) -> Result<Self, HsmError> {
        self.push_toc(build_toc_none())?;
        Ok(self)
    }

    /// Add a `padding` TOC entry (type 9, alignment padding in data section).
    pub fn padding(mut self, len: usize) -> Result<Self, HsmError> {
        let offset = self.data_offset;
        if len > MAX_DATA_SIZE {
            return Err(HsmError::TborDataTooLarge);
        }
        self.push_toc(build_toc_offset_len(TocType::Padding as u8, len, offset))?;
        if len > 0 {
            let stage_base = RESP_HEADER_LEN + MAX_TOC_ENTRIES * 4;
            let dst_start = stage_base + self.data_offset;
            let dst_end = dst_start + len;
            if dst_end > self.buf.len() {
                return Err(HsmError::TborBufferTooSmall);
            }
            for i in dst_start..dst_end {
                self.buf[i] = 0;
            }
            self.data_offset += len;
        }
        Ok(self)
    }

    /// Finalize the response message.
    pub fn finish(self) -> Result<&'a [u8], HsmError> {
        if self.toc_count == 0 {
            return Err(HsmError::TborTooManyTocEntries);
        }

        let data_start = RESP_HEADER_LEN + self.toc_count * 4;
        let total = data_start + self.data_offset;

        if total > self.buf.len() {
            return Err(HsmError::TborBufferTooSmall);
        }

        // Shift staged data from max-TOC position to actual data_start.
        let stage_base = RESP_HEADER_LEN + MAX_TOC_ENTRIES * 4; // = 136
        if self.data_offset > 0 && stage_base != data_start {
            self.buf
                .copy_within(stage_base..stage_base + self.data_offset, data_start);
        }

        // Write header as two u32 words.
        let hdr0 = u32::from_le_bytes([self.version, self.flags, 0x00, (self.toc_count - 1) as u8]);
        self.buf[..4].copy_from_slice(&hdr0.to_le_bytes());
        self.buf[4..8].copy_from_slice(&self.status.to_le_bytes());

        // Write TOC entries.
        for i in 0..self.toc_count {
            write_toc_word(self.buf, RESP_HEADER_LEN, i, self.toc_words[i]);
        }

        Ok(&self.buf[..total])
    }

    /// Compute the total encoded message length.
    pub fn encoded_len(&self) -> usize {
        RESP_HEADER_LEN + self.toc_count * 4 + self.data_offset
    }

    // ── Internal helpers ───────────────────────────────────────────

    fn push_toc(&mut self, word: u32) -> Result<(), HsmError> {
        if self.toc_count >= MAX_TOC_ENTRIES {
            return Err(HsmError::TborTooManyTocEntries);
        }
        self.toc_words[self.toc_count] = word;
        self.toc_count += 1;
        Ok(())
    }

    fn stage_data(&mut self, data: &[u8]) -> Result<(), HsmError> {
        let stage_base = RESP_HEADER_LEN + MAX_TOC_ENTRIES * 4; // = 136
        let dst_start = stage_base + self.data_offset;
        let dst_end = dst_start + data.len();

        if dst_end > self.buf.len() {
            return Err(HsmError::TborBufferTooSmall);
        }

        self.buf[dst_start..dst_end].copy_from_slice(data);
        self.data_offset += data.len();

        if self.data_offset > MAX_DATA_SIZE {
            return Err(HsmError::TborDataOffsetOverflow);
        }

        Ok(())
    }
}
