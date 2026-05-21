// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! GCM buffer layout helpers for the BCP `pad_aad` convention.
//!
//! The Ocelot BCP hardware accepts AES-GCM input buffers laid out as
//! `[padded_AAD | text]`. The AAD region is padded to a multiple of
//! 32 bytes per the table below. The prepended (or trailing) zero
//! bytes form a GHASH-transparent block, so the real AAD content
//! occupies the same GHASH-block positions as standard GCM.
//!
//! | `aad_len % 32` | Padded layout                              |
//! |----------------|--------------------------------------------|
//! | `0`            | `[AAD]` (no padding)                       |
//! | `1..=16`       | `[zeros(16) ‖ AAD ‖ trail_zeros]` (prefix) |
//! | `17..=31`      | `[AAD ‖ trail_zeros]` (trailing only)      |
//!
//! This crate is pure computation — no PAL traits, no hardware
//! access, no allocations.

// =============================================================================
// Constants
// =============================================================================

/// AAD-padding granularity (bytes). Every BCP GCM submission's AAD
/// region length is a multiple of this value.
const AAD_PAD: usize = 32;

/// Threshold at which the BCP convention switches from the "prefix
/// 16 zeros" layout to the "trailing-only" layout. Inclusive upper
/// bound for the prefix layout.
const PREFIX_LAYOUT_THRESHOLD: usize = 16;

// =============================================================================
// Layout primitives
// =============================================================================

/// Layout selector for [`format_gcm_buf`] — which of the three rules
/// in the table at the top of this module applies.
#[derive(Clone, Copy)]
enum AadLayout {
    /// `aad_len == 0` — the buffer is just the text.
    Empty,
    /// `aad_len % 32 == 0` — AAD is copied verbatim, no padding.
    Aligned,
    /// `aad_len % 32 in 1..=16` — prepend 16 zero bytes, then AAD,
    /// then trailing zeros to the next 32 boundary.
    Prefix16,
    /// `aad_len % 32 in 17..=31` — AAD verbatim, then trailing zeros
    /// to the next 32 boundary.
    Trailing,
}

impl AadLayout {
    /// Pick the right layout for an unpadded AAD length.
    const fn from_len(aad_len: usize) -> Self {
        if aad_len == 0 {
            return Self::Empty;
        }
        match aad_len % AAD_PAD {
            0 => Self::Aligned,
            1..=PREFIX_LAYOUT_THRESHOLD => Self::Prefix16,
            _ => Self::Trailing,
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Compute the padded AAD region size in bytes.
///
/// The result is always a multiple of 32 (or 0 when `aad_len == 0`).
///
/// # Parameters
/// * `aad_len` — unpadded AAD length supplied by the caller.
///
/// # Returns
/// * The padded AAD-region length per the [layout
///   table](self#padded-layout-table).
pub const fn padded_aad_len(aad_len: usize) -> usize {
    match AadLayout::from_len(aad_len) {
        AadLayout::Empty => 0,
        AadLayout::Aligned => aad_len,
        AadLayout::Prefix16 => (16 + aad_len).next_multiple_of(AAD_PAD),
        AadLayout::Trailing => aad_len.next_multiple_of(AAD_PAD),
    }
}

/// Total buffer size needed for one GCM encrypt/decrypt operation
/// (`padded_aad ‖ text`).
///
/// # Parameters
/// * `aad_len` — unpadded AAD length.
/// * `text_len` — plaintext or ciphertext length.
///
/// # Returns
/// * `padded_aad_len(aad_len) + text_len`.
pub const fn gcm_buf_len(aad_len: usize, text_len: usize) -> usize {
    padded_aad_len(aad_len) + text_len
}

/// Format AAD and text into a GCM buffer using the BCP `pad_aad`
/// convention.
///
/// Writes `[padded_aad | text]` into `buf` and returns the unpadded
/// `aad_len` value the caller should pass to `gcm_encrypt` /
/// `gcm_decrypt`.
///
/// # Parameters
/// * `aad` — additional authenticated data (any length, may be
///   empty).
/// * `text` — plaintext or ciphertext.
/// * `buf` — destination; must be at least
///   [`gcm_buf_len(aad.len(), text.len())`](gcm_buf_len) bytes.
///
/// # Returns
/// * `aad.len()` — pass this verbatim to the GCM API.
///
/// # Panics
/// * Panics if `buf` is too small.
pub fn format_gcm_buf(aad: &[u8], text: &[u8], buf: &mut [u8]) -> usize {
    let aad_len = aad.len();
    let padded = padded_aad_len(aad_len);
    let total = padded + text.len();
    assert!(buf.len() >= total, "gcm buf too small");

    match AadLayout::from_len(aad_len) {
        AadLayout::Empty => {
            // No AAD region — `padded` is 0, so `buf[..text.len()]`
            // is the full output.
            buf[..text.len()].copy_from_slice(text);
        }
        AadLayout::Aligned => {
            buf[..aad_len].copy_from_slice(aad);
        }
        AadLayout::Prefix16 => {
            // Prepend 16 zero bytes, then AAD, then trailing zeros
            // up to `padded`.
            buf[..16].fill(0);
            buf[16..16 + aad_len].copy_from_slice(aad);
            buf[16 + aad_len..padded].fill(0);
        }
        AadLayout::Trailing => {
            // AAD left-justified, trailing zeros up to `padded`.
            buf[..aad_len].copy_from_slice(aad);
            buf[aad_len..padded].fill(0);
        }
    }

    // Append text after the padded AAD region.
    buf[padded..total].copy_from_slice(text);

    aad_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_len_zero() {
        assert_eq!(padded_aad_len(0), 0);
    }

    #[test]
    fn padded_len_small() {
        // 13 % 32 = 13 ≤ 16 → prepend 16 + 13 = 29 → round to 32
        assert_eq!(padded_aad_len(13), 32);
    }

    #[test]
    fn padded_len_16() {
        // 16 % 32 = 16 ≤ 16 → prepend 16 + 16 = 32
        assert_eq!(padded_aad_len(16), 32);
    }

    #[test]
    fn padded_len_20() {
        // 20 % 32 = 20 > 16 → trail-pad 20 → 32
        assert_eq!(padded_aad_len(20), 32);
    }

    #[test]
    fn padded_len_32() {
        // 32 % 32 = 0 → no padding
        assert_eq!(padded_aad_len(32), 32);
    }

    #[test]
    fn padded_len_48() {
        // 48 % 32 = 16 ≤ 16 → prepend 16 + 48 = 64
        assert_eq!(padded_aad_len(48), 64);
    }

    #[test]
    fn padded_len_50() {
        // 50 % 32 = 18 > 16 → trail-pad 50 → 64
        assert_eq!(padded_aad_len(50), 64);
    }

    #[test]
    fn padded_len_64() {
        // 64 % 32 = 0 → no padding
        assert_eq!(padded_aad_len(64), 64);
    }

    #[test]
    fn format_no_aad() {
        let text = [0xAA; 16];
        let mut buf = [0u8; 16];
        let aad_len = format_gcm_buf(&[], &text, &mut buf);
        assert_eq!(aad_len, 0);
        assert_eq!(buf, text);
    }

    #[test]
    fn format_aligned_aad() {
        let aad = [0xBB; 32];
        let text = [0xCC; 8];
        let mut buf = [0u8; 40];
        let aad_len = format_gcm_buf(&aad, &text, &mut buf);
        assert_eq!(aad_len, 32);
        assert_eq!(&buf[..32], &aad);
        assert_eq!(&buf[32..40], &text);
    }

    #[test]
    fn format_prepend_zeros() {
        let aad = [0xDD; 13];
        let text = [0xEE; 4];
        let padded = padded_aad_len(13); // 32
        let mut buf = [0xFFu8; 36];
        let aad_len = format_gcm_buf(&aad, &text, &mut buf);
        assert_eq!(aad_len, 13);
        // First 16 bytes are zeros (prepended).
        assert_eq!(&buf[..16], &[0u8; 16]);
        // Then AAD.
        assert_eq!(&buf[16..29], &aad);
        // Trail zeros.
        assert_eq!(&buf[29..padded], &[0u8; 3]);
        // Then text.
        assert_eq!(&buf[padded..padded + 4], &text);
    }
}
