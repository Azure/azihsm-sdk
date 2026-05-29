// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: field group definition and usage.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(fields)]
pub struct CryptoHeader {
    #[tbor(session_id)]
    session: u16,
    #[tbor(key_id)]
    key: u16,
    algorithm: u8,
}

fn main() {
    // Verify the group generates constants and types.
    assert_eq!(CryptoHeader::TOC_COUNT, 3);
    assert_eq!(CryptoHeader::WORST_CASE_DATA_SIZE, 0);
}
