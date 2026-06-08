// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encoder error-path tests.

use super::common::*;

#[test]
fn encode_rejects_buffer_too_small() -> TestResult {
    let mut buf = [0u8; REQ_HEADER_LEN + TOC_ENTRY_LEN - 1];
    let result = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish();
    assert!(matches!(result, Err(EncodeError::BufferTooSmall)));
    Ok(())
}

#[test]
fn encode_rejects_data_too_large() {
    let big = vec![0u8; MAX_DATA_SIZE + 1];
    let mut out = vec![0u8; MAX_DATA_SIZE + 64];
    let result = RequestEncoder::new(&mut out, PROTOCOL_VERSION, OPCODE).buffer(&big);
    assert!(matches!(result, Err(EncodeError::DataTooLarge)));
}

#[test]
fn encode_rejects_too_many_toc_entries() -> TestResult {
    let mut buf = vec![0u8; REQ_HEADER_LEN + (MAX_TOC_ENTRIES + 1) * TOC_ENTRY_LEN];
    let mut enc = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE);
    for _ in 0..MAX_TOC_ENTRIES {
        enc = enc.none()?;
    }
    let result = enc.none();
    assert!(matches!(result, Err(EncodeError::TooManyTocEntries)));
    Ok(())
}

#[test]
fn encode_rejects_zero_toc_entries_on_finish() {
    let mut buf = [0u8; 256];
    let result = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE).finish();
    assert!(matches!(result, Err(EncodeError::MissingTocEntries)));
}

#[test]
fn encode_rejects_data_offset_overflow() -> TestResult {
    // Push two payloads whose combined size exceeds MAX_DATA_SIZE
    // without either individually exceeding it (which would trigger
    // DataTooLarge first).
    let mut buf = vec![0u8; 9000];
    let half = MAX_DATA_SIZE / 2 + 1;
    let result = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .padding(half)?
        .padding(half);
    assert!(matches!(result, Err(EncodeError::DataOffsetOverflow)));
    Ok(())
}
