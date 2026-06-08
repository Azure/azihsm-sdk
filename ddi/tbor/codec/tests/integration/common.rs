// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared constants and helpers used across the integration test modules.

pub use azihsm_ddi_tbor_codec::DecodeError;
pub use azihsm_ddi_tbor_codec::EncodeError;
pub use azihsm_ddi_tbor_codec::RequestEncoder;
pub use azihsm_ddi_tbor_codec::RequestView;
pub use azihsm_ddi_tbor_codec::ResponseEncoder;
pub use azihsm_ddi_tbor_codec::ResponseView;
pub use azihsm_ddi_tbor_codec::TocEntry;
pub use azihsm_ddi_tbor_codec::MAX_DATA_SIZE;
pub use azihsm_ddi_tbor_codec::MAX_TOC_ENTRIES;
pub use azihsm_ddi_tbor_codec::PROTOCOL_VERSION;
pub use azihsm_ddi_tbor_codec::REQ_HEADER_LEN;
pub use azihsm_ddi_tbor_codec::RESP_HEADER_LEN;

pub const TOC_ENTRY_LEN: usize = 4;
pub const OPCODE: u8 = 0x42;
pub const STATUS_OK: u32 = 0;

/// Unified test error so `#[test] fn ... -> TestResult` can use `?` on
/// both encoder and decoder calls.
pub enum TestError {
    Encode(EncodeError),
    Decode(DecodeError),
}

impl core::fmt::Debug for TestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "Encode({:?})", e),
            Self::Decode(e) => write!(f, "Decode({:?})", e),
        }
    }
}

impl From<EncodeError> for TestError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl From<DecodeError> for TestError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

pub type TestResult = Result<(), TestError>;

pub fn read_toc_word(buf: &[u8], header_len: usize, idx: usize) -> u32 {
    let base = header_len + idx * TOC_ENTRY_LEN;
    u32::from_be_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]])
}

pub fn write_toc_word(buf: &mut [u8], header_len: usize, idx: usize, word: u32) {
    let base = header_len + idx * TOC_ENTRY_LEN;
    buf[base..base + TOC_ENTRY_LEN].copy_from_slice(&word.to_be_bytes());
}
