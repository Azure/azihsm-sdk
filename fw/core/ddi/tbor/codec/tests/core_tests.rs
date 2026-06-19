// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for tbor-core: round-trip encoding/decoding, spec worked examples,
//! edge cases, and error handling.

#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use std::vec::Vec;

use azihsm_fw_ddi_tbor::*;
use azihsm_fw_hsm_pal_traits::DmaBuf;

// SAFETY: test-only branding. Host-side tests have no real DMA engine,
// so the DMA-reachability contract is moot; the brand is needed purely
// to satisfy the `RequestView::parse` / `ResponseView::parse` signatures.
fn brand(b: &[u8]) -> &DmaBuf {
    // SAFETY: see fn-level doc comment.
    unsafe { DmaBuf::from_raw(b) }
}

// ── Spec Worked Example 1: Simple Request ──────────────────────────────

#[test]
fn spec_example1_request_decode() {
    // From spec: opcode 0x0A, session_id=43, buffer="Hello"
    // Note: spec hex dump shows `1C 0A 00 00` for TOC[1] but the correct
    // encoding per the field definitions (type=7, len=5, offset=0) is
    // `1C 00 A0 00` (BE packed bitfield).
    let wire: &[u8] = &[
        0x01, 0x00, 0x01, 0x0A, // header: v1, reserved, 2 entries, opcode 0x0A
        0x00, 0x00, 0x00, 0x2B, // TOC[0]: session_id = 0x002B (43)
        0x1C, 0x00, 0xA0, 0x00, // TOC[1]: buffer, len=5, offset=0
        0x48, 0x65, 0x6C, 0x6C, 0x6F, // data: "Hello"
    ];

    let view = RequestView::parse(brand(wire)).unwrap();
    assert_eq!(view.version(), 0x01);
    assert_eq!(view.opcode(), 0x0A);
    assert_eq!(view.toc_count(), 2);
    assert_eq!(view.len(), 17);

    match view.toc_entry(0) {
        TocEntry::SessionId(v) => assert_eq!(v, 43),
        other => panic!("expected SessionId, got {:?}", other),
    }

    match view.toc_entry(1) {
        TocEntry::Buffer(data) => assert_eq!(data, b"Hello"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn spec_example1_request_encode() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .session_id(43)
        .unwrap()
        .buffer(b"Hello")
        .unwrap()
        .finish()
        .unwrap();

    assert_eq!(msg.len(), 17);

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.opcode(), 0x0A);
    assert_eq!(view.toc_count(), 2);

    match view.toc_entry(0) {
        TocEntry::SessionId(v) => assert_eq!(v, 43),
        other => panic!("expected SessionId, got {:?}", other),
    }
    match view.toc_entry(1) {
        TocEntry::Buffer(data) => assert_eq!(data, b"Hello"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

// ── Spec Worked Example 2: Simple Response ─────────────────────────────

#[test]
fn spec_example2_response_decode() {
    // Note: spec hex dump shows `1C 06 00 00` for TOC[0] but the correct
    // encoding per field definitions (type=7, len=3, offset=0) is
    // `1C 00 60 00` (BE packed bitfield).
    let wire: &[u8] = &[
        0x01, 0x01, 0x00, 0x00, // header: v1, flags=0x01 (FIPS), reserved, 1 entry
        0x00, 0x00, 0x00, 0x00, // status: 0 (Success)
        0x1C, 0x00, 0x60, 0x00, // TOC[0]: buffer, len=3, offset=0
        0x4F, 0x4B, 0x21, // data: "OK!"
    ];

    let view = ResponseView::parse(brand(wire)).unwrap();
    assert_eq!(view.version(), 0x01);
    assert!(view.fips_approved());
    assert_eq!(view.status(), 0);
    assert_eq!(view.toc_count(), 1);
    assert_eq!(view.len(), 15);

    match view.toc_entry(0) {
        TocEntry::Buffer(data) => assert_eq!(data, b"OK!"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn spec_example2_response_encode() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, true)
        .buffer(b"OK!")
        .unwrap()
        .finish()
        .unwrap();

    assert_eq!(msg.len(), 15);

    let view = ResponseView::parse(brand(msg)).unwrap();
    assert!(view.fips_approved());
    assert_eq!(view.status(), 0);
    match view.toc_entry(0) {
        TocEntry::Buffer(data) => assert_eq!(data, b"OK!"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

// ── Round-trip tests for all TOC types ─────────────────────────────────

#[test]
fn round_trip_session_id() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x01)
        .session_id(0x1234)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::SessionId(v) => assert_eq!(v, 0x1234),
        other => panic!("expected SessionId, got {:?}", other),
    }
}

#[test]
fn round_trip_key_id() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x02)
        .key_id(0xABCD)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::KeyId(v) => assert_eq!(v, 0xABCD),
        other => panic!("expected KeyId, got {:?}", other),
    }
}

#[test]
fn round_trip_uint8() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x03)
        .uint8(0xFF)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Uint8(v) => assert_eq!(v, 0xFF),
        other => panic!("expected Uint8, got {:?}", other),
    }
}

#[test]
fn round_trip_uint16() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x04)
        .uint16(0xBEEF)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Uint16(v) => assert_eq!(v, 0xBEEF),
        other => panic!("expected Uint16, got {:?}", other),
    }
}

#[test]
fn round_trip_uint32() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x05)
        .uint32(0xDEADBEEF)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Uint32(v) => assert_eq!(v, 0xDEADBEEF),
        other => panic!("expected Uint32, got {:?}", other),
    }
}

#[test]
fn round_trip_uint64() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x06)
        .uint64(0x0123456789ABCDEF)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Uint64(v) => assert_eq!(v, 0x0123456789ABCDEF),
        other => panic!("expected Uint64, got {:?}", other),
    }
}

#[test]
fn round_trip_sealed_key() {
    let key_data = b"sealed-key-blob-here";
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x07)
        .sealed_key(key_data)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::SealedKey(data) => assert_eq!(data, key_data),
        other => panic!("expected SealedKey, got {:?}", other),
    }
}

#[test]
fn round_trip_multiple_entries() {
    let mut buf = [0u8; 512];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x72)
        .session_id(43)
        .unwrap()
        .key_id(16)
        .unwrap()
        .uint8(1)
        .unwrap()
        .buffer(&[0u8; 16])
        .unwrap()
        .buffer(b"hello world")
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 5);

    match view.toc_entry(0) {
        TocEntry::SessionId(v) => assert_eq!(v, 43),
        other => panic!("expected SessionId, got {:?}", other),
    }
    match view.toc_entry(1) {
        TocEntry::KeyId(v) => assert_eq!(v, 16),
        other => panic!("expected KeyId, got {:?}", other),
    }
    match view.toc_entry(2) {
        TocEntry::Uint8(v) => assert_eq!(v, 1),
        other => panic!("expected Uint8, got {:?}", other),
    }
    match view.toc_entry(3) {
        TocEntry::Buffer(data) => assert_eq!(data.len(), 16),
        other => panic!("expected Buffer, got {:?}", other),
    }
    match view.toc_entry(4) {
        TocEntry::Buffer(data) => assert_eq!(data, b"hello world"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

// ── Response round-trip ────────────────────────────────────────────────

#[test]
fn round_trip_response_with_status_and_data() {
    let mut buf = [0u8; 512];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0x00000005, false)
        .uint8(42)
        .unwrap()
        .buffer(b"error details")
        .unwrap()
        .finish()
        .unwrap();

    let view = ResponseView::parse(brand(msg)).unwrap();
    assert_eq!(view.status(), 0x00000005);
    assert!(!view.fips_approved());
    assert_eq!(view.toc_count(), 2);

    match view.toc_entry(0) {
        TocEntry::Uint8(v) => assert_eq!(v, 42),
        other => panic!("expected Uint8, got {:?}", other),
    }
    match view.toc_entry(1) {
        TocEntry::Buffer(data) => assert_eq!(data, b"error details"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

// ── Edge cases ─────────────────────────────────────────────────────────

#[test]
fn decode_minimum_request() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0xFF)
        .uint8(0)
        .unwrap()
        .finish()
        .unwrap();

    assert_eq!(msg.len(), 8);
    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 1);
    assert_eq!(view.data_size(), 0);
}

#[test]
fn decode_minimum_response() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, false)
        .uint8(0)
        .unwrap()
        .finish()
        .unwrap();

    assert_eq!(msg.len(), 12);
    let view = ResponseView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 1);
    assert_eq!(view.data_size(), 0);
}

#[test]
fn empty_buffer_field() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .buffer(&[])
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Buffer(data) => assert_eq!(data.len(), 0),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn max_toc_entries() {
    let mut buf = [0u8; 8192];
    let mut enc = RequestEncoder::new(&mut buf, 0x01, 0x0A);
    for i in 0..32u8 {
        enc = enc.uint8(i).unwrap();
    }
    let msg = enc.finish().unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 32);
    for i in 0..32 {
        match view.toc_entry(i) {
            TocEntry::Uint8(v) => assert_eq!(v, i as u8),
            other => panic!("expected Uint8, got {:?}", other),
        }
    }
}

// ── Error cases ────────────────────────────────────────────────────────

#[test]
fn decode_buffer_too_short() {
    let wire = [0x01, 0x00];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(err, DecodeError::BufferTooShort { .. }));
}

#[test]
fn decode_unsupported_version() {
    let wire = [0x02, 0x00, 0x00, 0x0A, 0x0C, 0x00, 0x00, 0x00];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(err, DecodeError::UnsupportedVersion(0x02)));
}

#[test]
fn decode_message_truncated() {
    let wire = [
        0x01, 0x00, 0x01, 0x0A, // 2 TOC entries expected
        0x00, 0x00, 0x00, 0x2B, // only 1 present
    ];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(err, DecodeError::MessageTruncated { .. }));
}

#[test]
fn decode_offset_out_of_bounds() {
    // buffer (type=7) with length=127, offset=0 — but no data section
    let word = toc::build_toc_offset_len(TocType::Buffer as u8, 127, 0);
    let wb = word.to_be_bytes();
    let wire = [0x01, 0x00, 0x00, 0x0A, wb[0], wb[1], wb[2], wb[3]];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(err, DecodeError::OffsetLengthOutOfBounds { .. }));
}

#[test]
fn decode_invalid_uint32_length() {
    // uint32 (type=5) with length=3 — should be 4
    let word = toc::build_toc_offset_len(TocType::Uint32 as u8, 3, 0);
    let wb = word.to_be_bytes();
    let wire = [
        0x01, 0x00, 0x00, 0x0A, wb[0], wb[1], wb[2], wb[3], 0x00, 0x00,
        0x00, // 3 bytes of data
    ];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(
        err,
        DecodeError::InvalidFixedLength {
            entry_type: 5,
            expected: 4,
            actual: 3,
            ..
        }
    ));
}

#[test]
fn encode_too_many_toc_entries() {
    let mut buf = [0u8; 8192];
    let mut enc = RequestEncoder::new(&mut buf, 0x01, 0x0A);
    for _ in 0..32 {
        enc = enc.uint8(0).unwrap();
    }
    let err = enc.uint8(0).unwrap_err();
    assert!(matches!(err, EncodeError::TooManyTocEntries));
}

#[test]
fn encode_buffer_too_small() {
    let mut buf = [0u8; 8];
    let err = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .buffer(b"this is way too long for the buffer")
        .unwrap_err();
    assert!(matches!(err, EncodeError::BufferTooSmall { .. }));
}

// ── Unknown TOC types (forward compat) ─────────────────────────────────

#[test]
fn decode_unknown_toc_type_preserved() {
    let unknown_word: u32 = (10 << 26) | 0x12345;
    let uw = unknown_word.to_be_bytes();
    let known_word = toc::build_toc_inline_u8(TocType::Uint8 as u8, 42);
    let kw = known_word.to_be_bytes();

    let wire = [
        0x01, 0x00, 0x01, 0x0A, uw[0], uw[1], uw[2], uw[3], kw[0], kw[1], kw[2], kw[3],
    ];

    let view = RequestView::parse(brand(&wire)).unwrap();
    assert_eq!(view.toc_count(), 2);

    match view.toc_entry(0) {
        TocEntry::Unknown { entry_type, .. } => assert_eq!(entry_type, 10),
        other => panic!("expected Unknown, got {:?}", other),
    }
    match view.toc_entry(1) {
        TocEntry::Uint8(v) => assert_eq!(v, 42),
        other => panic!("expected Uint8, got {:?}", other),
    }
}

// ── Nonzero reserved bits must be accepted ─────────────────────────────

#[test]
fn decode_nonzero_reserved_bits_accepted() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .uint8(1)
        .unwrap()
        .finish()
        .unwrap();

    let mut wire: Vec<u8> = msg.to_vec();
    wire[1] = 0xFF; // reserved byte
    wire[2] |= 0xE0; // upper 3 reserved bits of byte 2

    let view = RequestView::parse(brand(&wire)).unwrap();
    assert_eq!(view.toc_count(), 1);
    match view.toc_entry(0) {
        TocEntry::Uint8(v) => assert_eq!(v, 1),
        other => panic!("expected Uint8, got {:?}", other),
    }
}

// ── Iterator ───────────────────────────────────────────────────────────

#[test]
fn toc_iter_yields_all_entries() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .session_id(1)
        .unwrap()
        .uint8(2)
        .unwrap()
        .uint16(3)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    let entries: Vec<_> = view.toc_iter().collect();
    assert_eq!(entries.len(), 3);
    assert!(matches!(entries[0], TocEntry::SessionId(1)));
    assert!(matches!(entries[1], TocEntry::Uint8(2)));
    assert!(matches!(entries[2], TocEntry::Uint16(3)));
}

// ── Display / Pretty Print ─────────────────────────────────────────────

#[test]
fn display_request_view() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .session_id(43)
        .unwrap()
        .buffer(b"Hello")
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    let output = std::format!("{}", view);
    assert!(output.contains("Request v1"));
    assert!(output.contains("opcode=0x0A"));
    assert!(output.contains("session_id"));
    assert!(output.contains("buffer"));
}

#[test]
fn display_response_view() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, true)
        .buffer(b"OK!")
        .unwrap()
        .finish()
        .unwrap();

    let view = ResponseView::parse(brand(msg)).unwrap();
    let output = std::format!("{}", view);
    assert!(output.contains("Response v1"));
    assert!(output.contains("Success"));
    assert!(output.contains("FIPS"));
    assert!(output.contains("buffer"));
}

#[test]
fn hex_dump_format() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .uint8(42)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    let output = std::format!("{:#}", view);
    assert!(output.contains("0000"));
}

// ── None TOC entry (type 8) ───────────────────────────────────────────

#[test]
fn round_trip_none_entry() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .none()
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 1);
    assert!(matches!(view.toc_entry(0), TocEntry::None));
}

#[test]
fn none_mixed_with_other_entries() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .session_id(42)
        .unwrap()
        .none()
        .unwrap()
        .buffer(b"data")
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 3);
    assert!(matches!(view.toc_entry(0), TocEntry::SessionId(42)));
    assert!(matches!(view.toc_entry(1), TocEntry::None));
    match view.toc_entry(2) {
        TocEntry::Buffer(data) => assert_eq!(data, b"data"),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

#[test]
fn none_response_round_trip() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, false)
        .none()
        .unwrap()
        .uint8(7)
        .unwrap()
        .finish()
        .unwrap();

    let view = ResponseView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 2);
    assert!(matches!(view.toc_entry(0), TocEntry::None));
    assert!(matches!(view.toc_entry(1), TocEntry::Uint8(7)));
}

#[test]
fn all_none_entries() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .none()
        .unwrap()
        .none()
        .unwrap()
        .none()
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 3);
    assert_eq!(view.data_size(), 0);
    for i in 0..3 {
        assert!(matches!(view.toc_entry(i), TocEntry::None));
    }
}

#[test]
fn none_entry_nonzero_payload_rejected() {
    // Manually construct a type-8 entry with non-zero payload bits.
    let bad_word: u32 = (8u32 << 26) | 0x0001;
    let bw = bad_word.to_be_bytes();
    let wire = [
        0x01, 0x00, 0x00, 0x0A, // header
        bw[0], bw[1], bw[2], bw[3],
    ];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(
        err,
        DecodeError::InvalidNonePayload { entry_index: 0, .. }
    ));
}

#[test]
fn none_display() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .none()
        .unwrap()
        .uint8(1)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    let output = std::format!("{}", view);
    assert!(output.contains("none"));
}

// ── Padding TOC entry (type 9) ────────────────────────────────────────

#[test]
fn round_trip_padding_entry() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .buffer(b"hi")
        .unwrap()
        .padding(2)
        .unwrap()
        .uint32(42)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    assert_eq!(view.toc_count(), 3);
    match view.toc_entry(1) {
        TocEntry::Padding(p) => assert_eq!(p.len(), 2),
        other => panic!("expected Padding, got {:?}", other),
    }
}

#[test]
fn zero_length_padding_round_trip() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .padding(0)
        .unwrap()
        .uint8(1)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Padding(p) => assert_eq!(p.len(), 0),
        other => panic!("expected Padding, got {:?}", other),
    }
}

// ── Data boundary tests ───────────────────────────────────────────────

#[test]
fn request_buffer_over_max_rejected() {
    let mut buf = [0u8; 16384];
    let big = [0u8; 8192]; // > MAX_DATA_SIZE (8191)
    let err = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .buffer(&big)
        .unwrap_err();
    assert!(matches!(err, EncodeError::DataTooLarge { .. }));
}

#[test]
fn request_exact_max_data_succeeds() {
    let mut buf = [0u8; 8400];
    let data = [0u8; 8191];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .buffer(&data)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::Buffer(b) => assert_eq!(b.len(), 8191),
        other => panic!("expected Buffer, got {:?}", other),
    }
}

// ── Response-specific coverage ────────────────────────────────────────

#[test]
fn response_reserved_bits_accepted() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, false)
        .uint8(1)
        .unwrap()
        .finish()
        .unwrap();

    let mut wire: Vec<u8> = msg.to_vec();
    wire[2] = 0xFF; // reserved byte
    wire[3] |= 0xE0; // upper 3 reserved bits of toc_count byte

    let view = ResponseView::parse(brand(&wire)).unwrap();
    assert_eq!(view.toc_count(), 1);
}

#[test]
fn response_toc_iter() {
    let mut buf = [0u8; 256];
    let msg = ResponseEncoder::new(&mut buf, 0x01, 0, true)
        .session_id(10)
        .unwrap()
        .uint8(5)
        .unwrap()
        .finish()
        .unwrap();

    let view = ResponseView::parse(brand(msg)).unwrap();
    let entries: Vec<_> = view.toc_iter().collect();
    assert_eq!(entries.len(), 2);
    assert!(matches!(entries[0], TocEntry::SessionId(10)));
    assert!(matches!(entries[1], TocEntry::Uint8(5)));
}

#[test]
fn display_padding_and_sealed_key() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .sealed_key(b"keyblob")
        .unwrap()
        .padding(3)
        .unwrap()
        .uint32(0)
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    let output = std::format!("{}", view);
    assert!(output.contains("sealed_key"));
    assert!(output.contains("padding"));
}

#[test]
fn empty_sealed_key_round_trip() {
    let mut buf = [0u8; 256];
    let msg = RequestEncoder::new(&mut buf, 0x01, 0x0A)
        .sealed_key(&[])
        .unwrap()
        .finish()
        .unwrap();

    let view = RequestView::parse(brand(msg)).unwrap();
    match view.toc_entry(0) {
        TocEntry::SealedKey(data) => assert_eq!(data.len(), 0),
        other => panic!("expected SealedKey, got {:?}", other),
    }
}

#[test]
fn decode_invalid_uint64_length() {
    let word = toc::build_toc_offset_len(TocType::Uint64 as u8, 4, 0); // should be 8
    let wb = word.to_be_bytes();
    let wire = [
        0x01, 0x00, 0x00, 0x0A, wb[0], wb[1], wb[2], wb[3], 0x00, 0x00, 0x00, 0x00,
    ];
    let err = RequestView::parse(brand(&wire)).unwrap_err();
    assert!(matches!(
        err,
        DecodeError::InvalidFixedLength {
            entry_type: 6,
            expected: 8,
            actual: 4,
            ..
        }
    ));
}
