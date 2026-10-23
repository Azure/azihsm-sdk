// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_codec::DecodeError;
use azihsm_ddi_tbor_codec::RequestEncoder;
use azihsm_ddi_tbor_codec::RequestView;
use common::EncoderTOCBuilders;
use common::FUZZ_REQ_BUF_SIZE;
use common::run_encoder;
use common::validate_toc_entry;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    buf_size: usize,
    version: u8,
    opcode: u8,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut backing = [0u8; FUZZ_REQ_BUF_SIZE];
    let len = input.buf_size % (FUZZ_REQ_BUF_SIZE + 1); // clamp into range
    let buf = &mut backing[..len];
    let encoder = RequestEncoder::new(buf, input.version, input.opcode);
    if let Some(encoded) = run_encoder(encoder, &input.ops) {
        let view = match RequestView::parse(encoded) {
            Ok(view) => view,
            Err(DecodeError::UnsupportedVersion(_)) => return,
            Err(e) => panic!("bytes from a successful RequestEncoder::finish must parse: {e:?}"),
        };
        assert_eq!(view.version(), input.version);
        assert_eq!(view.opcode(), input.opcode);
        assert_eq!(view.toc_count(), input.ops.len());
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();

        for (i, (entry, op)) in view.toc_iter().zip(input.ops).enumerate() {
            assert_eq!(view.toc_entry(i), entry);
            let _ = view.toc_entry_type(i);

            validate_toc_entry(&op, entry);
        }
    }
});
