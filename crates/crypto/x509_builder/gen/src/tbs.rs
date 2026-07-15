// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBS extraction and needle-matching logic.
//!
//! Given a DER-encoded certificate or CSR, extracts the TBS (To-Be-Signed)
//! portion and locates variable fields by searching for known "needle" byte
//! patterns inserted during template construction.
//!
//! # Workflow
//!
//! 1. [`extract_tbs`] / [`extract_csr_tbs`] — isolate the TBS bytes from a
//!    full DER certificate or CSR.
//! 2. [`find_needle`] / [`find_all_needles`] — locate needle patterns in the
//!    TBS to determine field offsets.
//! 3. [`sanitize_tbs`] — replace needle bytes with [`PLACEHOLDER_BYTE`]
//!    (`0x5F`) to produce the final template.

/// A variable field found in a TBS template.
///
/// Describes where a patchable field lives within the TBS byte array.
#[derive(Debug, Clone)]
pub struct FieldOffset {
    /// Constant name prefix used in generated code (e.g. `"PUBLIC_KEY"`).
    pub name: &'static str,
    /// Byte offset of the field within the TBS template.
    pub offset: usize,
    /// Length of the field in bytes.
    pub len: usize,
}

/// Placeholder byte used to sanitize variable fields in templates.
///
/// Following the Caliptra convention, `0x5F` marks positions in the TBS
/// template that must be patched at runtime.
pub const PLACEHOLDER_BYTE: u8 = 0x5F;

/// Extract the TBS (To-Be-Signed) portion from a DER-encoded X.509 certificate.
///
/// A certificate is `SEQUENCE { TBS, SignatureAlgorithm, Signature }`.
/// This function returns the complete TBS element including its SEQUENCE
/// tag and length bytes.
///
/// # Arguments
/// * `cert_der` — Complete DER-encoded X.509 certificate.
///
/// # Panics
/// Panics if the outer or inner structure does not start with a SEQUENCE tag.
pub fn extract_tbs(cert_der: &[u8]) -> Vec<u8> {
    // Outer SEQUENCE tag at offset 0
    assert_eq!(cert_der[0], 0x30, "Expected SEQUENCE tag");
    let (outer_header_len, _outer_content_len) = parse_der_length(&cert_der[1..]);
    let tbs_start = 1 + outer_header_len;

    // TBS is itself a SEQUENCE
    assert_eq!(cert_der[tbs_start], 0x30, "Expected TBS SEQUENCE tag");
    let (tbs_header_len, tbs_content_len) = parse_der_length(&cert_der[tbs_start + 1..]);
    let tbs_total_len = 1 + tbs_header_len + tbs_content_len;

    cert_der[tbs_start..tbs_start + tbs_total_len].to_vec()
}

/// Extract the TBS (CertificationRequestInfo) portion from a DER-encoded PKCS#10 CSR.
///
/// A CSR has the same outer structure as a certificate:
/// `SEQUENCE { CertificationRequestInfo, SignatureAlgorithm, Signature }`.
///
/// # Arguments
/// * `csr_der` — Complete DER-encoded PKCS#10 CSR.
pub fn extract_csr_tbs(csr_der: &[u8]) -> Vec<u8> {
    // Same structure as a certificate
    extract_tbs(csr_der)
}

/// Find a unique needle byte pattern in the TBS and return its offset.
///
/// # Arguments
/// * `tbs` — The TBS byte array to search.
/// * `needle` — The byte pattern to locate.
/// * `field_name` — Human-readable name for error messages.
///
/// # Panics
/// Panics if the needle is not found exactly once.
pub fn find_needle(tbs: &[u8], needle: &[u8], field_name: &str) -> usize {
    let offsets = find_all_needles(tbs, needle);
    assert!(
        offsets.len() == 1,
        "Field '{field_name}': expected exactly 1 match, found {} at offsets {:?}",
        offsets.len(),
        offsets
    );
    offsets[0]
}

/// Find all occurrences of a needle byte pattern in the TBS.
///
/// Useful for self-signed certificates where the same CN/SN needle
/// appears in both the issuer and subject DNs.
///
/// # Arguments
/// * `tbs` — The TBS byte array to search.
/// * `needle` — The byte pattern to locate.
///
/// # Returns
/// A `Vec<usize>` of byte offsets where the needle was found.
pub fn find_all_needles(tbs: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    for i in 0..tbs.len().saturating_sub(needle.len()) + 1 {
        if tbs[i..].starts_with(needle) {
            found.push(i);
        }
    }
    found
}

/// Sanitize a TBS template by replacing all variable field bytes with [`PLACEHOLDER_BYTE`].
///
/// After calling this, the TBS template is ready for code generation — the
/// placeholder positions will be patched at runtime with actual values.
///
/// # Arguments
/// * `tbs` — Mutable TBS byte slice to sanitize in-place.
/// * `fields` — Variable field descriptors indicating which byte ranges to replace.
pub fn sanitize_tbs(tbs: &mut [u8], fields: &[FieldOffset]) {
    for field in fields {
        for i in 0..field.len {
            tbs[field.offset + i] = PLACEHOLDER_BYTE;
        }
    }
}

/// Parse a DER definite-length field.
///
/// # Arguments
/// * `data` — Byte slice starting at the first length byte (after the tag).
///
/// # Returns
/// `(header_bytes_consumed, content_length)` — how many bytes the length
/// field occupies and the decoded length value.
fn parse_der_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (1, data[0] as usize)
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }
        (1 + num_bytes, length)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_der_length_short() {
        let data = [0x14]; // length 20
        let (consumed, len) = parse_der_length(&data);
        assert_eq!(consumed, 1);
        assert_eq!(len, 20);
    }

    #[test]
    fn test_parse_der_length_long() {
        let data = [0x82, 0x01, 0x20]; // length 288
        let (consumed, len) = parse_der_length(&data);
        assert_eq!(consumed, 3);
        assert_eq!(len, 288);
    }

    #[test]
    fn test_find_needle_unique() {
        let tbs = [0x00, 0x01, 0xAA, 0xBB, 0xCC, 0x02, 0x03];
        let offset = find_needle(&tbs, &[0xAA, 0xBB, 0xCC], "test_field");
        assert_eq!(offset, 2);
    }

    #[test]
    #[should_panic(expected = "expected exactly 1 match")]
    fn test_find_needle_duplicate_panics() {
        let tbs = [0xAA, 0xBB, 0x00, 0xAA, 0xBB];
        find_needle(&tbs, &[0xAA, 0xBB], "dup_field");
    }

    #[test]
    fn test_sanitize_tbs() {
        let mut tbs = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let fields = vec![FieldOffset {
            name: "test",
            offset: 2,
            len: 3,
        }];
        sanitize_tbs(&mut tbs, &fields);
        assert_eq!(tbs, vec![0x00, 0x01, 0x5F, 0x5F, 0x5F, 0x05]);
    }
}
