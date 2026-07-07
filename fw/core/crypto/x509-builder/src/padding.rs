// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Subject field padding helpers for CSR / certificate builders.
//!
//! All AZIHSM CSR and certificate templates declare fixed-length
//! subject Common Name and serialNumber slots; these helpers convert
//! caller-supplied variable-length ASCII strings into the exact-byte
//! fixed-width form the template expects.

/// Pad an ASCII Common Name string into `out` to the buffer's full
/// length, padding any unused trailing bytes with ASCII space (0x20).
///
/// # Returns
/// `Some(())` on success, or `None` if `cn` is non-ASCII or longer
/// than `out`.
pub fn pad_cn_to(cn: &str, out: &mut [u8]) -> Option<()> {
    if !cn.is_ascii() || cn.len() > out.len() {
        return None;
    }
    out[..cn.len()].copy_from_slice(cn.as_bytes());
    for b in &mut out[cn.len()..] {
        *b = b' ';
    }
    Some(())
}

/// Pad an ASCII hex serialNumber string into `out` to the buffer's
/// full length, padding any unused trailing bytes with ASCII `'0'`
/// (0x30).
///
/// # Returns
/// `Some(())` on success, or `None` if `sn` is longer than `out` or
/// contains characters that are not ASCII hex digits
/// (`0..=9 | a..=f | A..=F`).
pub fn pad_sn_to(sn: &str, out: &mut [u8]) -> Option<()> {
    if sn.len() > out.len() || !sn.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    out[..sn.len()].copy_from_slice(sn.as_bytes());
    for b in &mut out[sn.len()..] {
        *b = b'0';
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_cn_to_short_string_pads_with_spaces() {
        let mut out = [0u8; 8];
        pad_cn_to("hi", &mut out).unwrap();
        assert_eq!(&out, b"hi      ");
    }

    #[test]
    fn pad_cn_to_exact_length_fills_buffer() {
        let mut out = [0u8; 4];
        pad_cn_to("abcd", &mut out).unwrap();
        assert_eq!(&out, b"abcd");
    }

    #[test]
    fn pad_cn_to_overlong_string_returns_none() {
        let mut out = [0u8; 2];
        assert!(pad_cn_to("abc", &mut out).is_none());
    }

    #[test]
    fn pad_cn_to_non_ascii_returns_none() {
        let mut out = [0u8; 8];
        assert!(pad_cn_to("héllo", &mut out).is_none());
    }

    #[test]
    fn pad_sn_to_short_string_pads_with_zero_char() {
        let mut out = [0u8; 8];
        pad_sn_to("ab", &mut out).unwrap();
        assert_eq!(&out, b"ab000000");
    }

    #[test]
    fn pad_sn_to_exact_length_fills_buffer() {
        let mut out = [0u8; 4];
        pad_sn_to("DEAD", &mut out).unwrap();
        assert_eq!(&out, b"DEAD");
    }

    #[test]
    fn pad_sn_to_overlong_string_returns_none() {
        let mut out = [0u8; 2];
        assert!(pad_sn_to("abcd", &mut out).is_none());
    }

    #[test]
    fn pad_sn_to_non_hex_returns_none() {
        let mut out = [0u8; 8];
        assert!(pad_sn_to("ZZ", &mut out).is_none());
        assert!(pad_sn_to("hello", &mut out).is_none());
        assert!(pad_sn_to("12 34", &mut out).is_none());
    }
}
