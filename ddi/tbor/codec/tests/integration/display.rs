// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Display-impl coverage: pretty (`{}`) and hex-dump (`{:#}`) formatting
//! for `RequestView` / `ResponseView`, plus per-`TocEntry`-variant
//! rendering. Also exercises the read-only `View` accessors that don't
//! appear in the round-trip tests.

use super::common::*;

fn build_kitchen_sink_request(buf: &mut [u8]) -> &[u8] {
    RequestEncoder::new(buf, PROTOCOL_VERSION, OPCODE)
        .session_id(0xDEAD)
        .expect("session_id")
        .key_id(0xBEEF)
        .expect("key_id")
        .uint8(0x12)
        .expect("uint8")
        .uint16(0x3456)
        .expect("uint16")
        .uint32(0x789A_BCDE)
        .expect("uint32")
        .uint64(0x0123_4567_89AB_CDEF)
        .expect("uint64")
        .buffer(&[0xAA; 4])
        .expect("short buffer")
        .buffer(&[0x55; 32])
        .expect("long buffer")
        .sealed_key(&[0x11; 8])
        .expect("sealed_key")
        .none()
        .expect("none")
        .padding(3)
        .expect("padding")
        .finish()
        .expect("finish")
}

#[test]
fn request_display_renders_every_toc_variant() -> TestResult {
    let mut buf = [0u8; 512];
    let bytes = build_kitchen_sink_request(&mut buf);
    let view = RequestView::parse(bytes)?;
    let rendered = std::format!("{}", view);

    assert!(rendered.contains("Request v1"));
    assert!(rendered.contains("opcode=0x42"));
    assert!(rendered.contains("session_id  = 0xDEAD"));
    assert!(rendered.contains("key_id      = 0xBEEF"));
    assert!(rendered.contains("uint8       = 0x12"));
    assert!(rendered.contains("uint16      = 0x3456"));
    assert!(rendered.contains("uint32      = 0x789ABCDE"));
    assert!(rendered.contains("uint64      = 0x0123456789ABCDEF"));
    // Short buffer (<=16 bytes) is printed inline; no trailing ellipsis.
    assert!(rendered.contains("buffer      [4 bytes] aa aa aa aa\n"));
    // Long buffer (>16 bytes) is truncated with "...".
    assert!(rendered.contains("[32 bytes]"));
    assert!(rendered.contains("..."));
    assert!(rendered.contains("sealed_key  [8 bytes]"));
    assert!(rendered.contains("none"));
    assert!(rendered.contains("padding     [3 bytes]"));
    Ok(())
}

#[test]
fn request_alternate_display_emits_hex_dump() -> TestResult {
    let mut buf = [0u8; 512];
    let bytes = build_kitchen_sink_request(&mut buf);
    let view = RequestView::parse(bytes)?;
    let dump = std::format!("{:#}", view);

    // First line offset header.
    assert!(dump.starts_with("0000  "));
    // The first header byte is the protocol version (0x01).
    assert!(dump.contains("01 "));
    // ASCII sidebar shows the dot replacement for non-printables.
    assert!(dump.contains('·'));
    // Multi-line: more than one 16-byte row.
    assert!(dump.matches('\n').count() > 1);
    Ok(())
}

#[test]
fn response_display_renders_status_and_flags() -> TestResult {
    let mut buf = [0u8; 256];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0xCAFE_F00D, true)
        .uint16(0x1234)?
        .finish()?;
    let view = ResponseView::parse(bytes)?;
    let rendered = std::format!("{}", view);

    assert!(rendered.contains("Response v1"));
    assert!(rendered.contains("status=0xCAFEF00D"));
    assert!(rendered.contains("flags=[FIPS]"));
    assert!(rendered.contains("uint16      = 0x1234"));
    Ok(())
}

#[test]
fn response_display_omits_flags_when_not_fips() -> TestResult {
    let mut buf = [0u8; 256];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, STATUS_OK, false)
        .none()?
        .finish()?;
    let view = ResponseView::parse(bytes)?;
    let rendered = std::format!("{}", view);

    assert!(rendered.contains("Response v1"));
    assert!(rendered.contains("status=0x00000000"));
    assert!(!rendered.contains("flags="));
    Ok(())
}

#[test]
fn response_alternate_display_emits_hex_dump() -> TestResult {
    let mut buf = [0u8; 256];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, STATUS_OK, false)
        .none()?
        .finish()?;
    let view = ResponseView::parse(bytes)?;
    let dump = std::format!("{:#}", view);
    assert!(dump.starts_with("0000  "));
    Ok(())
}

#[test]
fn display_renders_unknown_toc_entry_type() -> TestResult {
    // Encode a normal request, then patch TOC[0] to an unknown 6-bit type
    // (10..=63 are unassigned) so the formatter takes the `Unknown` arm.
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish()?
        .len();
    let word = read_toc_word(&buf, REQ_HEADER_LEN, 0);
    // Replace the 6-bit type field (top bits) with raw type 0x2A (42).
    let patched = (word & 0x03FF_FFFF) | (0x2A << 26);
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, patched);

    let view = RequestView::parse(&buf[..len])?;
    let rendered = std::format!("{}", view);
    assert!(rendered.contains("unknown(42)"));
    Ok(())
}

#[test]
fn view_exposes_data_layout_accessors() -> TestResult {
    let mut buf = [0u8; 256];
    let payload = [0xAB; 5];
    let bytes = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .buffer(&payload)?
        .finish()?;
    let view = RequestView::parse(bytes)?;

    // 4-byte request header + 1 TOC entry * 4 bytes = data section starts at 8.
    assert_eq!(view.data_start(), REQ_HEADER_LEN + TOC_ENTRY_LEN);
    assert_eq!(view.data_size(), payload.len());
    assert_eq!(view.data_section(), &payload[..]);
    assert_eq!(view.as_bytes(), bytes);
    // Buffer is TocType::Buffer = 7.
    assert_eq!(view.toc_entry_type(0), 7);
    Ok(())
}
