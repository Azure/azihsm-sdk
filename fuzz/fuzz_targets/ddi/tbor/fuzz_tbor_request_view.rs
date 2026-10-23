// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_codec::RequestView;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(view) = RequestView::parse(data) {
        let _ = view.version();
        let _ = view.opcode();
        let _ = view.toc_count();
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();
        for (i, entry) in view.toc_iter().enumerate() {
            let _ = entry;
            let _ = view.toc_entry_type(i);
            let _ = view.toc_entry(i);
        }
    }
});
