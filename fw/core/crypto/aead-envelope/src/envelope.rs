// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Borrowed view of a parsed envelope.
//!
//! Returned by both [`inspect`](crate::inspect) and
//! [`open`](crate::open). The semantics of
//! [`AeadEnvelope::payload`] depend on which call produced the view:
//!
//! | Producer  | `payload` contents |
//! |-----------|---------------------|
//! | [`inspect`](crate::inspect) | Ciphertext — header is parsed, no decryption. |
//! | [`open`](crate::open)       | Plaintext — PAL has decrypted in place. |

use crate::alg::AeadAlg;
use crate::error::Error;
use crate::error::Result;
use crate::format::Header;
use crate::format::HEADER_LEN;

/// Borrowed view over the regions of an envelope sitting in a
/// caller-owned buffer.
///
/// All fields are sub-slices of the input buffer; constructing an
/// `AeadEnvelope` performs no copies. The `'a` lifetime ties every
/// field back to the source buffer.
#[derive(Clone, Copy, Debug)]
pub struct AeadEnvelope<'a> {
    /// AEAD algorithm read from the envelope header.
    pub alg: AeadAlg,
    /// The 12-byte GCM nonce.
    pub iv: &'a [u8],
    /// Additional authenticated data (may be empty).
    pub aad: &'a [u8],
    /// Ciphertext (after [`inspect`](crate::inspect)) or plaintext
    /// (after [`open`](crate::open)). Length always equals
    /// `envelope_total - header - iv - aad - tag`.
    pub payload: &'a [u8],
    /// The 16-byte GCM authentication tag.
    pub tag: &'a [u8],
}

/// Compute the byte offsets of the IV, AAD, payload, and tag
/// regions given the parsed header and total envelope length.
///
/// Returns `(iv_off, aad_off, payload_off, tag_off)`. Each is the
/// offset of the *start* of the corresponding region; the end of
/// each region is the start of the next.
///
/// # Errors
/// * [`Error::BufferTooSmall`] — `total_len` is shorter than the
///   minimum implied by the header (`HEADER + iv + aad + tag`).
pub(crate) fn region_offsets(
    header: Header,
    total_len: usize,
) -> Result<(usize, usize, usize, usize)> {
    let iv_len = header.alg.iv_len();
    let tag_len = header.alg.tag_len();
    let iv_off = HEADER_LEN;
    let aad_off = iv_off
        .checked_add(iv_len)
        .ok_or(Error::BufferTooSmall { needed: usize::MAX })?;
    let payload_off = aad_off
        .checked_add(header.aad_len)
        .ok_or(Error::BufferTooSmall { needed: usize::MAX })?;
    let min_total = payload_off
        .checked_add(tag_len)
        .ok_or(Error::BufferTooSmall { needed: usize::MAX })?;
    if total_len < min_total {
        return Err(Error::BufferTooSmall { needed: min_total });
    }
    // `total_len - tag_len` cannot underflow because the check above
    // guarantees `total_len >= min_total >= tag_len`.
    let tag_off = total_len - tag_len;
    Ok((iv_off, aad_off, payload_off, tag_off))
}
