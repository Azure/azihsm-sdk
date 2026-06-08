// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encoder/decoder round-trip tests.

use super::common::*;

#[test]
fn request_round_trip_all_entry_types() -> TestResult {
    let mut buf = [0u8; 1024];
    let payload = b"hello world";
    let sealed = [0xABu8; 32];
    let padding_len = 7;

    let bytes = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .session_id(0x1234)?
        .key_id(0x5678)?
        .uint8(0xA5)?
        .uint16(0xBEEF)?
        .uint32(0xDEAD_BEEF)?
        .uint64(0x0123_4567_89AB_CDEF)?
        .buffer(payload)?
        .sealed_key(&sealed)?
        .none()?
        .padding(padding_len)?
        .finish()?;

    let view = RequestView::parse(bytes)?;
    assert_eq!(view.version(), PROTOCOL_VERSION);
    assert_eq!(view.opcode(), OPCODE);
    assert_eq!(view.toc_count(), 10);
    assert_eq!(view.len(), bytes.len());
    assert!(!view.is_empty());

    let entries: Vec<TocEntry<'_>> = view.toc_iter().collect();
    assert!(matches!(entries[0], TocEntry::SessionId(0x1234)));
    assert!(matches!(entries[1], TocEntry::KeyId(0x5678)));
    assert!(matches!(entries[2], TocEntry::Uint8(0xA5)));
    assert!(matches!(entries[3], TocEntry::Uint16(0xBEEF)));
    assert!(matches!(entries[4], TocEntry::Uint32(0xDEAD_BEEF)));
    assert!(matches!(
        entries[5],
        TocEntry::Uint64(0x0123_4567_89AB_CDEF)
    ));
    assert!(matches!(entries[6], TocEntry::Buffer(b) if b == payload));
    assert!(matches!(entries[7], TocEntry::SealedKey(b) if b == sealed));
    assert!(matches!(entries[8], TocEntry::None));
    let TocEntry::Padding(pad) = entries[9] else {
        panic!("expected padding");
    };
    assert_eq!(pad.len(), padding_len);
    assert!(pad.iter().all(|&b| b == 0));
    Ok(())
}

#[test]
fn toc_iter_matches_toc_entry_indexed() -> TestResult {
    let mut buf = [0u8; 256];
    let bytes = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .session_id(1)?
        .uint8(2)?
        .buffer(b"x")?
        .finish()?;

    let view = RequestView::parse(bytes)?;
    let from_iter: Vec<_> = view.toc_iter().collect();
    let from_index: Vec<_> = (0..view.toc_count()).map(|i| view.toc_entry(i)).collect();
    assert_eq!(from_iter, from_index);
    Ok(())
}

#[test]
fn response_round_trip_fips_off() -> TestResult {
    let mut buf = [0u8; 256];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, STATUS_OK, false)
        .uint32(0x1111_2222)?
        .buffer(b"abc")?
        .finish()?;

    let view = ResponseView::parse(bytes)?;
    assert_eq!(view.version(), PROTOCOL_VERSION);
    assert_eq!(view.status(), STATUS_OK);
    assert_eq!(view.flags(), 0);
    assert!(!view.fips_approved());
    assert_eq!(view.toc_count(), 2);
    Ok(())
}

#[test]
fn response_round_trip_fips_on_with_status() -> TestResult {
    let mut buf = [0u8; 256];
    let status = 0xDEAD_BEEF;
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, status, true)
        .uint8(0)?
        .finish()?;

    let view = ResponseView::parse(bytes)?;
    assert_eq!(view.status(), status);
    assert!(view.fips_approved());
    assert_ne!(view.flags() & 0x01, 0);
    Ok(())
}

#[test]
fn encoded_len_matches_finish_length() -> TestResult {
    let mut buf = [0u8; 256];
    let enc = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .session_id(1)?
        .buffer(b"hello")?
        .uint64(0xFF)?;
    let predicted = enc.encoded_len();
    let bytes = enc.finish()?;
    assert_eq!(predicted, bytes.len());
    Ok(())
}

#[test]
fn buffer_reserve_does_not_write() -> TestResult {
    let mut buf = [0u8; 256];
    // Pre-fill so we can detect any unwanted overwrite of reserved bytes.
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    let bytes_len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .buffer_reserve(4)?
        .finish()?
        .len();
    let view = RequestView::parse(&buf[..bytes_len])?;
    let TocEntry::Buffer(b) = view.toc_entry(0) else {
        panic!("expected buffer");
    };
    assert_eq!(b.len(), 4);
    Ok(())
}

#[test]
fn max_toc_entries_round_trip() -> TestResult {
    let mut buf = vec![0u8; REQ_HEADER_LEN + MAX_TOC_ENTRIES * TOC_ENTRY_LEN];
    let mut enc = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE);
    for _ in 0..MAX_TOC_ENTRIES {
        enc = enc.none()?;
    }
    let len = enc.finish()?.len();
    let view = RequestView::parse(&buf[..len])?;
    assert_eq!(view.toc_count(), MAX_TOC_ENTRIES);
    assert!(view.toc_iter().all(|e| matches!(e, TocEntry::None)));
    Ok(())
}
