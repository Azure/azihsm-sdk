// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

mod decoder;
mod encoder;

pub use decoder::DdiDecoder;
pub use encoder::DdiEncoder;

/// Error wrapper for MBOR encode/decode failures at the DDI layer.
#[derive(Debug)]
pub enum MborError {
    DecodeError,
    EncodeError,
}
