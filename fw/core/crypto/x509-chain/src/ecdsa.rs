// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDSA DER signature decoding.
//!
//! X.509 certificates encode ECDSA signatures as a DER SEQUENCE of
//! two INTEGERs (r, s). The PAL's [`HsmEcc::ecc_verify`] expects
//! raw `r || s` with each component zero-padded to the curve's
//! scalar length. This module converts between the two formats.

use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use der::asn1::UintRef;
use der::Reader;
use der::SliceReader;

/// Convenience alias for results produced by the internal DER signature
/// decoder. The error type wraps an [`HsmError`] so any [`der::Error`]
/// raised inside `der`'s closure-based readers can be mapped via
/// `?` without losing the canonical HSM error code.
type X509SigDecodeResult<T> = Result<T, X509SigDecodeError>;

/// Internal error type used while decoding ECDSA DER signatures.
///
/// Wraps a single [`HsmError`] so that the `der` crate's error type
/// (which does not implement `From<HsmError>`) can be funnelled
/// through the same `?` operator inside parser closures.
#[derive(Debug, Clone, Copy)]
struct X509SigDecodeError(HsmError);

impl From<der::Error> for X509SigDecodeError {
    /// Convert any DER decoding failure into
    /// [`HsmError::X509ParseError`]. The underlying `der::Error`
    /// detail is intentionally discarded — the public API only
    /// distinguishes "valid" vs. "malformed" DER.
    ///
    /// # Parameters
    /// * `_` — the [`der::Error`] produced by the `der` crate.
    ///
    /// # Returns
    /// An [`X509SigDecodeError`] wrapping [`HsmError::X509ParseError`].
    fn from(_: der::Error) -> Self {
        Self(HsmError::X509ParseError)
    }
}

impl From<HsmError> for X509SigDecodeError {
    /// Wrap an existing [`HsmError`] so it can be returned from a
    /// `der` parser closure without losing its specific variant.
    ///
    /// # Parameters
    /// * `error` — the [`HsmError`] to wrap.
    ///
    /// # Returns
    /// An [`X509SigDecodeError`] preserving `error` verbatim.
    fn from(error: HsmError) -> Self {
        Self(error)
    }
}

impl From<X509SigDecodeError> for HsmError {
    /// Unwrap the internal error back into the public [`HsmError`]
    /// once it leaves the parser.
    ///
    /// # Parameters
    /// * `error` — the [`X509SigDecodeError`] to unwrap.
    ///
    /// # Returns
    /// The wrapped [`HsmError`] value.
    fn from(error: X509SigDecodeError) -> Self {
        error.0
    }
}

/// Decode a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
/// into raw `r || s` bytes zero-padded to `curve.sig_len()`.
///
/// # Parameters
/// * `der_sig` — the DER-encoded signature from the certificate's
///   signatureValue BIT STRING (after stripping the BIT STRING wrapper
///   and unused-bits byte).
/// * `curve` — the signer's curve, used to determine the expected
///   component size.
/// * `out` — output buffer; must be at least `curve.sig_len()` bytes.
///
/// # Returns
/// * `Ok(len)` — number of bytes written to `out` (always `curve.sig_len()`).
/// * `Err(HsmError::X509ParseError)` — malformed DER.
pub fn decode_ecdsa_sig(der_sig: &[u8], curve: HsmEccCurve, out: &mut [u8]) -> HsmResult<usize> {
    let component_len = curve.priv_key_len();
    let sig_len = curve.sig_len();
    if out.len() < sig_len {
        return Err(HsmError::X509ParseError);
    }

    out[..sig_len].fill(0);

    let mut reader = SliceReader::new(der_sig).map_err(X509SigDecodeError::from)?;
    let (r, s) = reader.sequence(|sequence| -> X509SigDecodeResult<_> {
        let r = sequence.decode::<UintRef<'_>>()?;
        let s = sequence.decode::<UintRef<'_>>()?;
        sequence.clone().finish()?;
        Ok((r, s))
    })?;
    reader.finish().map_err(X509SigDecodeError::from)?;

    copy_integer_to_fixed(r.as_bytes(), &mut out[..component_len])?;
    copy_integer_to_fixed(s.as_bytes(), &mut out[component_len..sig_len])?;

    Ok(sig_len)
}

/// Copy a DER INTEGER's big-endian bytes into a fixed-width buffer,
/// right-aligned and zero-padded.
///
/// DER INTEGERs are signed, so positive values whose high bit is set
/// are encoded with a leading `0x00` padding byte. That byte is
/// stripped here before copying so that only the meaningful magnitude
/// bytes remain. The destination buffer is left-padded with zeros
/// so the magnitude is right-aligned to `dst.len()` bytes — exactly
/// what the hardware ECDSA verifier expects per scalar component.
///
/// # Parameters
/// * `src` — DER INTEGER content bytes (big-endian magnitude, with
///   an optional leading sign byte). Caller-allocated.
/// * `dst` — fixed-width destination slice. Its length is the curve
///   scalar size (e.g. 32 for P-256). Must be pre-zeroed by the
///   caller; this function only writes the trailing magnitude bytes.
///
/// # Returns
/// * `Ok(())` — the magnitude bytes were copied right-aligned into
///   `dst`.
/// * `Err(HsmError::X509ParseError)` — the (post-strip) magnitude
///   does not fit in `dst.len()` bytes.
fn copy_integer_to_fixed(src: &[u8], dst: &mut [u8]) -> HsmResult<()> {
    let bytes = match src {
        [0, rest @ ..] if !rest.is_empty() => rest,
        _ => src,
    };
    if bytes.len() > dst.len() {
        return Err(HsmError::X509ParseError);
    }
    let offset = dst.len() - bytes.len();
    dst[offset..].copy_from_slice(bytes);
    Ok(())
}
