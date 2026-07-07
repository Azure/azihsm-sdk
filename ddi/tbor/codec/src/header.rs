// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Header trait and marker types that abstract the only structural
//! differences between a TBOR request and response message.
//!
//! Generic codec types ([`crate::view::View`] and [`crate::encode::Encoder`])
//! are parameterised over a [`Header`] impl; everything else — TOC
//! layout, validation, framing — is identical for both message kinds.

use crate::toc::PROTOCOL_VERSION;

mod sealed {
    pub trait Sealed {}
}

/// Per-message-kind structural constants and serialisation glue.
///
/// Implemented only by [`Request`] and [`Response`]; downstream code
/// cannot add new headers (sealed trait).
pub trait Header: sealed::Sealed {
    /// Header size in bytes.
    const LEN: usize;

    /// Byte index inside the header that carries the (5-bit + 1) TOC-count field.
    const TOC_COUNT_BYTE: usize;

    /// Write a header into `buf[..Self::LEN]`. `toc_count` is the
    /// caller-provided count (1..=32); it is encoded biased by 1.
    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize);
}

// ── Request ────────────────────────────────────────────────────────────

/// Request-message header data: protocol version + opcode.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub version: u8,
    pub opcode: u8,
}

impl Request {
    /// Construct a request header with the current protocol version.
    #[inline]
    pub const fn new(opcode: u8) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            opcode,
        }
    }
}

impl sealed::Sealed for Request {}

impl Header for Request {
    const LEN: usize = 4;
    const TOC_COUNT_BYTE: usize = 2;

    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize) {
        // Wire layout (LE u32): [version, 0x00, toc_count-1, opcode].
        let word = u32::from_le_bytes([hdr.version, 0x00, (toc_count - 1) as u8, hdr.opcode]);
        buf[..Self::LEN].copy_from_slice(&word.to_le_bytes());
    }
}

// ── Response ───────────────────────────────────────────────────────────

/// Response-message header data: protocol version + flags + status.
#[derive(Debug, Clone, Copy)]
pub struct Response {
    pub version: u8,
    pub flags: u8,
    pub status: u32,
}

impl Response {
    /// FIPS_APPROVED flag bit inside the flags byte.
    pub const FIPS_APPROVED_FLAG: u8 = 0x01;

    /// Construct a response header with the current protocol version.
    #[inline]
    pub const fn new(status: u32, fips_approved: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: if fips_approved {
                Self::FIPS_APPROVED_FLAG
            } else {
                0
            },
            status,
        }
    }
}

impl sealed::Sealed for Response {}

impl Header for Response {
    const LEN: usize = 8;
    const TOC_COUNT_BYTE: usize = 3;

    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize) {
        // Wire layout (two LE u32 words):
        //   [version, flags, 0x00, toc_count-1] [status u32 LE]
        let word0 = u32::from_le_bytes([hdr.version, hdr.flags, 0x00, (toc_count - 1) as u8]);
        buf[..4].copy_from_slice(&word0.to_le_bytes());
        buf[4..8].copy_from_slice(&hdr.status.to_le_bytes());
    }
}
