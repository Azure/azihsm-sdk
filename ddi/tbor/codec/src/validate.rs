// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structural validation of TOC entries.
//!
//! Runs once on parse so all later accessors can be infallible.

use crate::error::DecodeError;
use crate::toc::*;

/// Validate every TOC entry in `buf` for structural correctness.
///
/// - Known offset/length types: `offset + length <= data_size`.
/// - Fixed-size types (`Uint32`, `Uint64`): length matches the type's required value.
/// - `None`: all 26 inline payload bits are zero.
/// - Inline types and unknown / forward-compat types are accepted without further checks.
pub(crate) fn validate_toc_entries(
    buf: &[u8],
    header_len: usize,
    toc_count: usize,
    data_size: usize,
) -> Result<(), DecodeError> {
    for entry_index in 0..toc_count {
        let word = read_toc_word(buf, header_len, entry_index);
        let raw = raw_entry_type(word);
        let Some(ty) = TocType::from_raw(raw) else {
            // Unknown / forward-compat: silently accept per spec.
            continue;
        };

        if matches!(ty, TocType::None) {
            if word & INLINE_PAYLOAD_MASK != 0 {
                return Err(DecodeError::InvalidNonePayload);
            }
            continue;
        }

        match ty.shape() {
            TocShape::Inline => { /* inline value already fits the word; nothing to check */ }
            TocShape::OffsetLen { fixed_length } => {
                let offset = raw_offset(word);
                let length = raw_length(word);

                if offset + length > data_size {
                    return Err(DecodeError::OffsetLengthOutOfBounds);
                }

                if let Some(expected) = fixed_length {
                    if length != expected {
                        return Err(DecodeError::InvalidFixedLength);
                    }
                }
            }
        }
    }
    Ok(())
}
