// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validator rejection tests — malformed headers and malformed TOC entries
//! produced by mutating a valid encoding.

use super::common::*;

// ── Malformed headers ──────────────────────────────────────────────────

#[test]
fn parse_rejects_short_buffer() {
    let buf = [0u8; 2];
    let err = RequestView::parse(&buf).unwrap_err();
    assert!(matches!(err, DecodeError::BufferTooShort));
}

#[test]
fn parse_rejects_unsupported_version() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish()?
        .len();
    buf[0] = 0xFF;
    let err = RequestView::parse(&buf[..len]).unwrap_err();
    assert_eq!(err, DecodeError::UnsupportedVersion(0xFF));
    Ok(())
}

#[test]
fn parse_rejects_truncated_message() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .uint64(1)?
        .finish()?
        .len();
    // Cut the message inside the data section.
    let err = RequestView::parse(&buf[..len - 4]).unwrap_err();
    assert!(matches!(
        err,
        DecodeError::OffsetLengthOutOfBounds | DecodeError::MessageTruncated
    ));
    Ok(())
}

// ── Malformed TOC entries (via mutation of a valid encoding) ──────────

#[test]
fn parse_rejects_offset_length_out_of_bounds() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .buffer(b"ok")?
        .finish()?
        .len();
    // Inflate the length field of TOC[0] beyond the data section.
    let word = read_toc_word(&buf, REQ_HEADER_LEN, 0);
    let bad = (word & !(0x1FFF << 13)) | ((0x100_u32) << 13);
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, bad);
    let err = RequestView::parse(&buf[..len]).unwrap_err();
    assert!(matches!(err, DecodeError::OffsetLengthOutOfBounds));
    Ok(())
}

#[test]
fn parse_rejects_uint32_with_wrong_length() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .uint32(0x1234_5678)?
        .finish()?
        .len();
    // Force length=3 instead of 4 on the Uint32 entry.
    let word = read_toc_word(&buf, REQ_HEADER_LEN, 0);
    let bad = (word & !(0x1FFF << 13)) | (3u32 << 13);
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, bad);
    let err = RequestView::parse(&buf[..len]).unwrap_err();
    assert!(matches!(err, DecodeError::InvalidFixedLength));
    Ok(())
}

#[test]
fn parse_rejects_uint64_with_wrong_length() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .uint64(0x0123_4567_89AB_CDEF)?
        .finish()?
        .len();
    // Force length=7 instead of 8 on the Uint64 entry.
    let word = read_toc_word(&buf, REQ_HEADER_LEN, 0);
    let bad = (word & !(0x1FFF << 13)) | (7u32 << 13);
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, bad);
    let err = RequestView::parse(&buf[..len]).unwrap_err();
    assert!(matches!(err, DecodeError::InvalidFixedLength));
    Ok(())
}

#[test]
fn parse_rejects_none_with_nonzero_reserved_bits() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish()?
        .len();
    // Set a low bit of the None TOC word (type stays 8, payload must be zero).
    let word = read_toc_word(&buf, REQ_HEADER_LEN, 0);
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, word | 0x01);
    let err = RequestView::parse(&buf[..len]).unwrap_err();
    assert!(matches!(err, DecodeError::InvalidNonePayload));
    Ok(())
}
