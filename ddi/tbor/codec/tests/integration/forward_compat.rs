// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Forward-compatibility and header-constant sanity tests.

use super::common::*;

#[test]
fn unknown_entry_type_decodes_as_unknown() -> TestResult {
    let mut buf = [0u8; 256];
    let len = RequestEncoder::new(&mut buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish()?
        .len();
    // Replace the type field (top 6 bits) with raw type=10 (unassigned),
    // and clear all payload bits so the validator has nothing to flag.
    let new_word = 10u32 << 26;
    write_toc_word(&mut buf, REQ_HEADER_LEN, 0, new_word);
    let view = RequestView::parse(&buf[..len])?;
    let TocEntry::Unknown {
        entry_type,
        raw_bits,
    } = view.toc_entry(0)
    else {
        panic!("expected Unknown entry");
    };
    assert_eq!(entry_type, 10);
    assert_eq!(raw_bits, new_word);
    Ok(())
}

#[test]
fn header_length_constants_are_correct() -> TestResult {
    let mut req_buf = [0u8; 256];
    let req = RequestEncoder::new(&mut req_buf, PROTOCOL_VERSION, OPCODE)
        .none()?
        .finish()?;
    assert_eq!(REQ_HEADER_LEN + TOC_ENTRY_LEN, req.len());

    let mut resp_buf = [0u8; 256];
    let resp = ResponseEncoder::new(&mut resp_buf, PROTOCOL_VERSION, STATUS_OK, false)
        .none()?
        .finish()?;
    assert_eq!(RESP_HEADER_LEN + TOC_ENTRY_LEN, resp.len());
    Ok(())
}
