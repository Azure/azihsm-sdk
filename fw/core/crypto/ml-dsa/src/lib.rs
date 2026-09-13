// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! ML-DSA-65 (FIPS 204) signing-key import with pre-validation.
//!
//! # Why this crate exists
//!
//! [`ml_dsa::ExpandedSigningKey::from_expanded`] (FIPS 204 Algorithm 25,
//! `skDecode`) **panics** — rather than returning an error — when handed a
//! correctly-sized encoded key whose `s1` or `s2` coefficients fall outside
//! the valid range `[-ETA, ETA]`.  The assertion lives in the crate's
//! `encode` module and fires during coefficient unpacking.
//!
//! The Uno firmware is built with `panic = "abort"`, so such an input would
//! reset the device.  Because the proof-of-concept imports a *host-supplied*
//! signing key, that input is attacker-reachable, making the panic a remote
//! denial-of-service rather than a theoretical concern.  `catch_unwind` is
//! unavailable under `panic = "abort"`, so the only remedy is to reject the
//! malformed key **before** it reaches the decoder.
//!
//! [`validate_encoded_signing_key`] performs that check, and
//! [`import_signing_key`] is the safe entry point that callers should use in
//! place of `from_expanded`.

use ml_dsa::ExpandedSigningKey;
use ml_dsa::ExpandedSigningKeyBytes;
use ml_dsa::MlDsa65;

/// Encoded ML-DSA-65 signing-key length in bytes (FIPS 204 Table 2).
pub const SIGNING_KEY_LEN: usize = 4032;

/// Encoded ML-DSA-65 verifying-key length in bytes.
pub const VERIFYING_KEY_LEN: usize = 1952;

/// ML-DSA-65 signature length in bytes.
pub const SIGNATURE_LEN: usize = 3309;

/// Private-key coefficient bound for ML-DSA-65 (FIPS 204 Table 1: eta = 4).
const ETA: u8 = 4;

/// Length in bytes of the `rho ‖ K ‖ tr` prefix that precedes `s1` in an
/// encoded signing key: 32 + 32 + 64.
const PREFIX_LEN: usize = 128;

/// Number of `s1` polynomials for ML-DSA-65 (dimension `l`).
const L: usize = 5;

/// Number of `s2` polynomials for ML-DSA-65 (dimension `k`).
const K: usize = 6;

/// Coefficients per polynomial.
const N: usize = 256;

/// Packed bits per `s1`/`s2` coefficient when eta = 4.
///
/// FIPS 204 `BitPack` encodes each coefficient of a private-key vector in
/// `bitlen(2 * eta)` bits; for eta = 4 that is 4 bits, so two coefficients
/// occupy one byte.
const ETA_BITS: usize = 4;

/// Packed byte length of one `s1`/`s2` polynomial.
const POLY_LEN: usize = N * ETA_BITS / 8;

/// Reasons an encoded signing key is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaKeyError {
    /// The encoded key is not [`SIGNING_KEY_LEN`] bytes.
    BadLength,

    /// An `s1` or `s2` coefficient lies outside `[-ETA, ETA]`.
    ///
    /// Such a key would panic [`ml_dsa::ExpandedSigningKey::from_expanded`].
    CoefficientOutOfRange,
}

/// Validates an encoded ML-DSA-65 signing key without decoding it.
///
/// Checks the length, then verifies that every packed `s1` and `s2`
/// coefficient decodes to a value within `[-ETA, ETA]`.  FIPS 204 packs each
/// coefficient as `eta - c`, so a valid nibble is in `0..=2 * ETA`; anything
/// larger is out of range.
///
/// # Errors
///
/// - [`MlDsaKeyError::BadLength`] if `enc` is not [`SIGNING_KEY_LEN`] bytes.
/// - [`MlDsaKeyError::CoefficientOutOfRange`] if any coefficient is invalid.
pub fn validate_encoded_signing_key(enc: &[u8]) -> Result<(), MlDsaKeyError> {
    if enc.len() != SIGNING_KEY_LEN {
        return Err(MlDsaKeyError::BadLength);
    }

    let packed_len = (L + K) * POLY_LEN;
    let s = &enc[PREFIX_LEN..PREFIX_LEN + packed_len];

    // Two coefficients per byte; each nibble must satisfy `nibble <= 2 * ETA`.
    for byte in s {
        if (byte & 0x0f) > 2 * ETA || (byte >> 4) > 2 * ETA {
            return Err(MlDsaKeyError::CoefficientOutOfRange);
        }
    }

    Ok(())
}

/// Imports an encoded ML-DSA-65 signing key, rejecting malformed input.
///
/// This is the panic-free replacement for
/// [`ml_dsa::ExpandedSigningKey::from_expanded`]: the encoded key is
/// validated by [`validate_encoded_signing_key`] first, so the decoder is
/// only ever handed input it can decode without asserting.
///
/// # Errors
///
/// Propagates any [`MlDsaKeyError`] from validation.
pub fn import_signing_key(enc: &[u8]) -> Result<ExpandedSigningKey<MlDsa65>, MlDsaKeyError> {
    validate_encoded_signing_key(enc)?;

    let bytes: &ExpandedSigningKeyBytes<MlDsa65> =
        enc.try_into().map_err(|_| MlDsaKeyError::BadLength)?;

    // Safe: `validate_encoded_signing_key` has ruled out the only input class
    // that makes `from_expanded` panic.
    #[allow(deprecated)]
    Ok(ExpandedSigningKey::<MlDsa65>::from_expanded(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A coefficient nibble of `2 * ETA + 1` is the smallest out-of-range value.
    const BAD_NIBBLE: u8 = 2 * ETA + 1;

    fn valid_key() -> [u8; SIGNING_KEY_LEN] {
        // All-zero coefficients encode to nibble 0, which is within range.
        [0u8; SIGNING_KEY_LEN]
    }

    #[test]
    fn accepts_in_range_coefficients() {
        assert_eq!(validate_encoded_signing_key(&valid_key()), Ok(()));
    }

    #[test]
    fn rejects_short_key() {
        let k = [0u8; SIGNING_KEY_LEN - 1];
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::BadLength)
        );
    }

    #[test]
    fn rejects_long_key() {
        let k = [0u8; SIGNING_KEY_LEN + 1];
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::BadLength)
        );
    }

    #[test]
    fn rejects_out_of_range_s1_low_nibble() {
        let mut k = valid_key();
        k[PREFIX_LEN] = BAD_NIBBLE;
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::CoefficientOutOfRange)
        );
    }

    #[test]
    fn rejects_out_of_range_s1_high_nibble() {
        let mut k = valid_key();
        k[PREFIX_LEN] = BAD_NIBBLE << 4;
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::CoefficientOutOfRange)
        );
    }

    #[test]
    fn rejects_out_of_range_s2() {
        let mut k = valid_key();
        // First byte of `s2`, immediately after the `s1` block.
        k[PREFIX_LEN + L * POLY_LEN] = BAD_NIBBLE;
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::CoefficientOutOfRange)
        );
    }

    #[test]
    fn boundary_coefficient_is_accepted() {
        let mut k = valid_key();
        k[PREFIX_LEN] = (2 * ETA) | ((2 * ETA) << 4);
        assert_eq!(validate_encoded_signing_key(&k), Ok(()));
    }
}

// ── On-device self-test (Phase 1) ──────────────────────────────────

/// Outcome of [`selftest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestResult {
    /// Import, sign and verify all succeeded and the signature matched
    /// the pinned FIPS 204 known-answer vector.
    Pass,

    /// The pinned signing key failed validation — should be impossible.
    ImportFailed,

    /// Signing returned an error.
    SignFailed,

    /// The produced signature did not match the known-answer vector.
    SignatureMismatch,

    /// The produced signature failed verification against the pinned
    /// verifying key.
    VerifyFailed,
}

/// Pinned FIPS 204 ML-DSA-65 known-answer vector.
///
/// Source: Wycheproof `mldsa_65_sign_noseed_test.json`, group 0 ("baseline"),
/// tcId 1 — a deterministic signature over an 11-byte message with an empty
/// context.
mod kat {
    /// Encoded signing key (`skDecode` input).
    pub const SK: &[u8] = include_bytes!("../testdata/kat_sk.bin");
    /// Encoded verifying key.
    pub const PK: &[u8] = include_bytes!("../testdata/kat_pk.bin");
    /// Message signed by the vector.
    pub const MSG: &[u8] = include_bytes!("../testdata/kat_msg.bin");
    /// Expected deterministic signature.
    pub const SIG: &[u8] = include_bytes!("../testdata/kat_sig.bin");
}

/// Runs ML-DSA-65 import, sign and verify against a pinned known-answer
/// vector, entirely on-device.
///
/// This is the Phase 1 proof that ML-DSA-65 executes correctly on CP1: it
/// exercises the Milestone 1 code path (import an externally generated key,
/// then sign) without needing any DDI plumbing, and checks the result against
/// a vector rather than against itself.
///
/// Signing is deterministic (empty context), so the output is compared
/// byte-for-byte with the vector; the signature is then verified with the
/// pinned verifying key as an independent check.
///
/// # Returns
///
/// [`SelfTestResult::Pass`] on success, otherwise the stage that failed.
pub fn selftest() -> SelfTestResult {
    use ml_dsa::signature::Verifier;
    use ml_dsa::EncodedSignature;
    use ml_dsa::EncodedVerifyingKey;
    use ml_dsa::Signature;
    use ml_dsa::VerifyingKey;

    let Ok(sk) = import_signing_key(kat::SK) else {
        return SelfTestResult::ImportFailed;
    };

    let Ok(sig) = sk.sign_deterministic(kat::MSG, &[]) else {
        return SelfTestResult::SignFailed;
    };

    let produced = sig.encode();
    if produced.as_slice() != kat::SIG {
        return SelfTestResult::SignatureMismatch;
    }

    let Ok(pk_enc): Result<&EncodedVerifyingKey<MlDsa65>, _> = kat::PK.try_into() else {
        return SelfTestResult::VerifyFailed;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(pk_enc);

    let Ok(sig_enc): Result<&EncodedSignature<MlDsa65>, _> = kat::SIG.try_into() else {
        return SelfTestResult::VerifyFailed;
    };
    let Some(decoded) = Signature::<MlDsa65>::decode(sig_enc) else {
        return SelfTestResult::VerifyFailed;
    };

    if vk.verify(kat::MSG, &decoded).is_err() {
        return SelfTestResult::VerifyFailed;
    }

    SelfTestResult::Pass
}

#[cfg(test)]
mod selftest_tests {
    use super::*;

    #[test]
    fn selftest_passes_against_pinned_vector() {
        assert_eq!(selftest(), SelfTestResult::Pass);
    }
}
