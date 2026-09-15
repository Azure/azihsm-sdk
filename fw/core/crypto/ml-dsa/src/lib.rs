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

use ml_dsa::EncodedSignature;
use ml_dsa::EncodedVerifyingKey;
use ml_dsa::ExpandedSigningKey;
use ml_dsa::ExpandedSigningKeyBytes;
#[cfg(feature = "param-mldsa44")]
use ml_dsa::MlDsa44;
#[cfg(param65)]
use ml_dsa::MlDsa65;
#[cfg(feature = "param-mldsa87")]
use ml_dsa::MlDsa87;
use ml_dsa::Signature;
use ml_dsa::SigningKey;
use ml_dsa::VerifyingKey;

/// Parameter set under test.
///
/// ML-DSA-65 is the default. `param-mldsa44` and `param-mldsa87` select the
/// other two FIPS 204 sets; a firmware image links exactly one, because
/// carrying more than one is not affordable in FLASH.
#[cfg(param65)]
pub type Param = MlDsa65;
/// See [`Param`].
#[cfg(feature = "param-mldsa44")]
pub type Param = MlDsa44;
/// See [`Param`].
#[cfg(feature = "param-mldsa87")]
pub type Param = MlDsa87;

/// Encoded signing-key length in bytes (FIPS 204 Table 2).
#[cfg(param65)]
pub const SIGNING_KEY_LEN: usize = 4032;
/// See [`SIGNING_KEY_LEN`].
#[cfg(feature = "param-mldsa44")]
pub const SIGNING_KEY_LEN: usize = 2560;
/// See [`SIGNING_KEY_LEN`].
#[cfg(feature = "param-mldsa87")]
pub const SIGNING_KEY_LEN: usize = 4896;

/// Encoded verifying-key length in bytes (FIPS 204 Table 2).
#[cfg(param65)]
pub const VERIFYING_KEY_LEN: usize = 1952;
/// See [`VERIFYING_KEY_LEN`].
#[cfg(feature = "param-mldsa44")]
pub const VERIFYING_KEY_LEN: usize = 1312;
/// See [`VERIFYING_KEY_LEN`].
#[cfg(feature = "param-mldsa87")]
pub const VERIFYING_KEY_LEN: usize = 2592;

/// Signature length in bytes (FIPS 204 Table 2).
#[cfg(param65)]
pub const SIGNATURE_LEN: usize = 3309;
/// See [`SIGNATURE_LEN`].
#[cfg(feature = "param-mldsa44")]
pub const SIGNATURE_LEN: usize = 2420;
/// See [`SIGNATURE_LEN`].
#[cfg(feature = "param-mldsa87")]
pub const SIGNATURE_LEN: usize = 4627;

/// Private-key coefficient bound (FIPS 204 Table 1): eta = 4 for ML-DSA-65,
/// eta = 2 for ML-DSA-44 and ML-DSA-87.
#[cfg(param65)]
const ETA: u8 = 4;
/// See [`ETA`].
#[cfg(any(feature = "param-mldsa44", feature = "param-mldsa87"))]
const ETA: u8 = 2;

/// Length in bytes of the `rho ‖ K ‖ tr` prefix that precedes `s1` in an
/// encoded signing key: 32 + 32 + 64.
const PREFIX_LEN: usize = 128;

/// Number of `s1` polynomials (dimension `l`).
#[cfg(param65)]
const L: usize = 5;
/// See [`L`].
#[cfg(feature = "param-mldsa44")]
const L: usize = 4;
/// See [`L`].
#[cfg(feature = "param-mldsa87")]
const L: usize = 7;

/// Number of `s2` polynomials (dimension `k`).
#[cfg(param65)]
const K: usize = 6;
/// See [`K`].
#[cfg(feature = "param-mldsa44")]
const K: usize = 4;
/// See [`K`].
#[cfg(feature = "param-mldsa87")]
const K: usize = 8;

/// Coefficients per polynomial.
const N: usize = 256;

/// Packed bits per `s1`/`s2` coefficient.
///
/// FIPS 204 `BitPack` encodes each coefficient of a private-key vector in
/// `bitlen(2 * eta)` bits: 4 bits for eta = 4 (ML-DSA-65), 3 bits for
/// eta = 2 (ML-DSA-44 and ML-DSA-87).
#[cfg(param65)]
const ETA_BITS: usize = 4;
/// See [`ETA_BITS`].
#[cfg(any(feature = "param-mldsa44", feature = "param-mldsa87"))]
const ETA_BITS: usize = 3;

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

/// Validates an encoded ML-DSA signing key without decoding it.
///
/// Checks the length, then verifies that every packed `s1` and `s2`
/// coefficient is a value the decoder will accept.  FIPS 204 `BitUnPack`
/// reads each coefficient as an `ETA_BITS`-bit field and asserts that it is
/// at most `2 * ETA` before mapping it to `eta - z`; a larger field value
/// trips that assertion and **panics**
/// [`ml_dsa::ExpandedSigningKey::from_expanded`].
///
/// Both parameter sets need this check, because neither packing is
/// saturated: eta = 2 is carried in 3 bits (0..=7, of which only 0..=4 are
/// legal) and eta = 4 in 4 bits (0..=15, of which only 0..=8 are legal).
///
/// The `t0` region needs no such check and is deliberately not examined:
/// it is range-encoded over `(-2^12, 2^12]` in exactly 13 bits, so every
/// 13-bit value is a legal encoding and the decoder's assertion there can
/// never fire.
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

    // Walk the packed region as a little-endian bit stream. Each polynomial
    // occupies a whole number of bytes (256 * ETA_BITS / 8), so polynomial
    // boundaries fall on byte boundaries and the whole region can be decoded
    // as one continuous stream even when a coefficient straddles a byte, as
    // it does for the 3-bit eta = 2 packing.
    let max = u32::from(2 * ETA);
    let mask = (1u32 << ETA_BITS) - 1;
    let mut acc: u32 = 0;
    let mut acc_bits = 0usize;
    for &byte in s {
        acc |= u32::from(byte) << acc_bits;
        acc_bits += 8;
        while acc_bits >= ETA_BITS {
            if (acc & mask) > max {
                return Err(MlDsaKeyError::CoefficientOutOfRange);
            }
            acc >>= ETA_BITS;
            acc_bits -= ETA_BITS;
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
pub fn import_signing_key(enc: &[u8]) -> Result<ExpandedSigningKey<Param>, MlDsaKeyError> {
    validate_encoded_signing_key(enc)?;

    let bytes: &ExpandedSigningKeyBytes<Param> =
        enc.try_into().map_err(|_| MlDsaKeyError::BadLength)?;

    // Safe: `validate_encoded_signing_key` has ruled out the only input class
    // that makes `from_expanded` panic.
    #[allow(deprecated)]
    Ok(ExpandedSigningKey::<Param>::from_expanded(bytes))
}

/// Reasons a signing or verification request is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaOpError {
    /// The supplied signing key was rejected — see [`MlDsaKeyError`].
    Key(MlDsaKeyError),

    /// A supplied buffer was not the length this parameter set requires.
    BadLength,

    /// Signing failed.
    SignFailed,

    /// The signature did not verify under the supplied verifying key.
    VerifyFailed,
}

impl From<MlDsaKeyError> for MlDsaOpError {
    fn from(e: MlDsaKeyError) -> Self {
        Self::Key(e)
    }
}

/// Derives the encoded verifying key for `seed`, writing it into `out_pk`.
///
/// The signing key is not produced: the DDI returns the seed itself, which
/// is the private key in FIPS 204's seed form, so the expanded key is never
/// needed on-device at generation time.
///
/// # Stack
///
/// `#[inline(never)]`. Uses the crate's combined entry point, which returns
/// the encoded verifying key that key generation already computed as the
/// input to the `tr` hash. Recovering it afterwards via `verifying_key()`
/// instead repeats the whole `A * s1 + s2` product in a 54 KiB frame on top
/// of this one — measured, that is the difference between a 137.1 KiB and a
/// 235.5 KiB chain at ML-DSA-65, against a 212.9 KiB stack.
///
/// # Errors
///
/// - [`MlDsaOpError::BadLength`] if `out_pk` is the wrong length.
#[inline(never)]
pub fn keygen_into(seed: &[u8; 32], out_pk: &mut [u8]) -> Result<(), MlDsaOpError> {
    if out_pk.len() != VERIFYING_KEY_LEN {
        return Err(MlDsaOpError::BadLength);
    }

    let mut sk_enc = ExpandedSigningKeyBytes::<Param>::default();
    let pk_enc = SigningKey::<Param>::keygen_encoded_into(seed.into(), &mut sk_enc);
    out_pk.copy_from_slice(pk_enc.as_slice());
    Ok(())
}

/// Signs `msg` with the encoded signing key `enc_sk`, writing the encoded
/// signature into `out`.
///
/// Uses the FIPS 204 **deterministic** variant, so no entropy source is
/// required and the signature is a pure function of key and message — which
/// is also what makes the on-device result checkable against a pinned
/// known-answer vector.
///
/// `out` must be exactly [`SIGNATURE_LEN`] bytes; the signature is written
/// into it in place rather than returned, so the caller's buffer (a DMA
/// response slot) is the only copy.
///
/// # Stack
///
/// This is `#[inline(never)]` on purpose, and deliberately does **not**
/// split expansion from the signing rounds. LLVM merges inlined callees
/// into a single frame and does not reuse slots across scopes, so letting
/// this inline into a command handler would add its whole working set to
/// the caller's frame. Splitting it further is worse, not better: measured
/// on ARM, importing and signing in one frame costs 108 KiB, whereas
/// handing the expanded key to a separate `#[inline(never)]` signer costs
/// 163 + 14 KiB, because the key is then materialised on both sides of the
/// call. The 163.4 KiB stack region admits the former and not the latter.
///
/// # Errors
///
/// - [`MlDsaOpError::Key`] if the signing key is malformed.
/// - [`MlDsaOpError::BadLength`] if `out` is not [`SIGNATURE_LEN`] bytes.
/// - [`MlDsaOpError::SignFailed`] if signing fails.
#[inline(never)]
pub fn sign_into(enc_sk: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), MlDsaOpError> {
    if out.len() != SIGNATURE_LEN {
        return Err(MlDsaOpError::BadLength);
    }

    // Construct the expanded key directly rather than calling
    // `import_signing_key`: returning it through a `Result` across a call
    // boundary makes the compiler materialise the ~57 KiB key twice, once
    // as the callee's return temporary and once as the local. Measured on
    // ARM that is the difference between a 163 KiB and a 108 KiB frame.
    validate_encoded_signing_key(enc_sk)?;
    let bytes: &ExpandedSigningKeyBytes<Param> = enc_sk
        .try_into()
        .map_err(|_| MlDsaOpError::Key(MlDsaKeyError::BadLength))?;

    // Safe: `validate_encoded_signing_key` has ruled out the only input
    // class that makes `from_expanded` panic.
    #[allow(deprecated)]
    let sk = ExpandedSigningKey::<Param>::from_expanded(bytes);

    let sig = sk
        .sign_deterministic(msg, &[])
        .map_err(|_| MlDsaOpError::SignFailed)?;
    out.copy_from_slice(sig.encode().as_slice());
    Ok(())
}

/// Verifies `sig` over `msg` under the encoded verifying key `enc_pk`.
///
/// # Stack
///
/// `#[inline(never)]` for the same reason as [`sign_into`]; this path peaks
/// at 92.5 KiB at ML-DSA-44 and 146 KiB at ML-DSA-65, measured on ARM.
///
/// # Errors
///
/// - [`MlDsaOpError::BadLength`] if either buffer is the wrong length.
/// - [`MlDsaOpError::VerifyFailed`] if the signature does not verify.
#[inline(never)]
pub fn verify(enc_pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), MlDsaOpError> {
    use ml_dsa::signature::Verifier;

    let pk_enc: &EncodedVerifyingKey<Param> =
        enc_pk.try_into().map_err(|_| MlDsaOpError::BadLength)?;
    let sig_enc: &EncodedSignature<Param> = sig.try_into().map_err(|_| MlDsaOpError::BadLength)?;

    // A signature that is the right length but not a well-formed encoding is
    // a failed verification, not a malformed request: the encoding is
    // attacker-supplied and carries no separate integrity guarantee.
    let decoded = Signature::<Param>::decode(sig_enc).ok_or(MlDsaOpError::VerifyFailed)?;

    VerifyingKey::<Param>::decode(pk_enc)
        .verify(msg, &decoded)
        .map_err(|_| MlDsaOpError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A coefficient nibble of `2 * ETA + 1` is the smallest out-of-range value.
    #[cfg(param65)]
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
    #[cfg(param65)]
    fn rejects_out_of_range_s1_low_nibble() {
        let mut k = valid_key();
        k[PREFIX_LEN] = BAD_NIBBLE;
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::CoefficientOutOfRange)
        );
    }

    #[test]
    #[cfg(param65)]
    fn rejects_out_of_range_s1_high_nibble() {
        let mut k = valid_key();
        k[PREFIX_LEN] = BAD_NIBBLE << 4;
        assert_eq!(
            validate_encoded_signing_key(&k),
            Err(MlDsaKeyError::CoefficientOutOfRange)
        );
    }

    #[test]
    #[cfg(param65)]
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
    #[cfg(param65)]
    fn boundary_coefficient_is_accepted() {
        let mut k = valid_key();
        k[PREFIX_LEN] = (2 * ETA) | ((2 * ETA) << 4);
        assert_eq!(validate_encoded_signing_key(&k), Ok(()));
    }
}

// ── On-device self-test (Phase 1) ──────────────────────────────────

#[cfg(not(feature = "param-mldsa87"))]
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

#[cfg(not(feature = "param-mldsa87"))]
/// Pinned FIPS 204 ML-DSA-65 known-answer vector.
///
/// Source: Wycheproof `mldsa_65_sign_noseed_test.json`, group 0 ("baseline"),
/// tcId 1 — a deterministic signature over an 11-byte message with an empty
/// context.
mod kat {
    /// Encoded signing key (`skDecode` input).
    #[cfg(param65)]
    pub const SK: &[u8] = include_bytes!("../testdata/kat_sk.bin");
    /// Encoded verifying key.
    #[cfg(param65)]
    pub const PK: &[u8] = include_bytes!("../testdata/kat_pk.bin");
    /// Message signed by the vector.
    #[cfg(param65)]
    pub const MSG: &[u8] = include_bytes!("../testdata/kat_msg.bin");
    /// Expected deterministic signature.
    #[cfg(param65)]
    pub const SIG: &[u8] = include_bytes!("../testdata/kat_sig.bin");

    /// See [`SK`].
    #[cfg(feature = "param-mldsa44")]
    pub const SK: &[u8] = include_bytes!("../testdata/kat44_sk.bin");
    /// See [`PK`].
    #[cfg(feature = "param-mldsa44")]
    pub const PK: &[u8] = include_bytes!("../testdata/kat44_pk.bin");
    /// See [`MSG`].
    #[cfg(feature = "param-mldsa44")]
    pub const MSG: &[u8] = include_bytes!("../testdata/kat44_msg.bin");
    /// See [`SIG`].
    #[cfg(feature = "param-mldsa44")]
    pub const SIG: &[u8] = include_bytes!("../testdata/kat44_sig.bin");
}

#[cfg(not(feature = "param-mldsa87"))]
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
/// Stage identifiers reported by [`selftest_staged`].
pub mod stage {
    /// `skDecode` + matrix expansion finished.
    pub const IMPORT_DONE: u32 = 1;
    /// Deterministic signing finished.
    pub const SIGN_DONE: u32 = 2;
    /// Signature matched the pinned vector.
    pub const KAT_MATCH: u32 = 3;
    /// Verification finished.
    pub const VERIFY_DONE: u32 = 4;
}

#[cfg(not(feature = "param-mldsa87"))]
/// Same as [`selftest`], but invokes `mark` after each stage so a caller can
/// report progress. Used to localise a hang or fault on hardware, where a
/// single pass/fail result cannot say which stage failed to return.
/// Imports the pinned key and signs, returning the encoded signature.
///
/// `#[inline(never)]` is load-bearing: the signing key is ~64 KiB and the
/// verifying key ~43 KiB for ML-DSA-65. If these stages are inlined into one
/// function the compiler allocates both, plus temporaries, in a single stack
/// frame at entry, which overflows the stack on this target before a single
/// instruction runs. Keeping them in separate frames makes the peak the
/// larger of the two rather than their sum.
#[cfg(not(feature = "verify-only"))]
#[inline(never)]
fn kat_sign(mark: &mut dyn FnMut(u32)) -> Result<EncodedSignature<Param>, SelfTestResult> {
    // Import and sign share one frame deliberately. Splitting them so the key
    // is returned across a call boundary makes the compiler materialise it
    // twice - once in the callee, once in the caller - which measured worse
    // on this target than the single larger frame.
    let sk = import_signing_key(kat::SK).map_err(|_| SelfTestResult::ImportFailed)?;
    mark(stage::IMPORT_DONE);

    let sig = sk
        .sign_deterministic(kat::MSG, &[])
        .map_err(|_| SelfTestResult::SignFailed)?;
    mark(stage::SIGN_DONE);

    Ok(sig.encode())
}

#[cfg(not(feature = "param-mldsa87"))]
/// Verifies the pinned signature with the pinned verifying key.
///
/// Separate frame from [`kat_sign`] so the signing key and verifying key are
/// never live at once; kept as a single frame internally for the reason noted
/// in [`kat_sign`].
#[inline(never)]
fn kat_verify() -> bool {
    use ml_dsa::signature::Verifier;

    let Ok(pk_enc): Result<&EncodedVerifyingKey<Param>, _> = kat::PK.try_into() else {
        return false;
    };
    let Ok(sig_enc): Result<&EncodedSignature<Param>, _> = kat::SIG.try_into() else {
        return false;
    };
    let Some(decoded) = Signature::<Param>::decode(sig_enc) else {
        return false;
    };
    VerifyingKey::<Param>::decode(pk_enc)
        .verify(kat::MSG, &decoded)
        .is_ok()
}

#[cfg(not(feature = "param-mldsa87"))]
/// Runs the self-test.
///
/// With the `verify-only` feature the signing half is skipped: ML-DSA-65's
/// signing path needs a ~322 KiB stack frame on this target (measured), which
/// does not fit the 163.4 KiB stack region, while verification needs 150 KiB
/// and does fit. Verify-only therefore exercises the "host signs, firmware
/// verifies" direction at the full ML-DSA-65 parameter set.
pub fn selftest_staged(mark: &mut dyn FnMut(u32)) -> SelfTestResult {
    #[cfg(not(feature = "verify-only"))]
    {
        let sig = match kat_sign(mark) {
            Ok(sig) => sig,
            Err(e) => return e,
        };
        if sig.as_slice() != kat::SIG {
            return SelfTestResult::SignatureMismatch;
        }
        mark(stage::KAT_MATCH);
    }

    if !kat_verify() {
        return SelfTestResult::VerifyFailed;
    }
    mark(stage::VERIFY_DONE);

    SelfTestResult::Pass
}

#[cfg(not(feature = "param-mldsa87"))]
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

    let Ok(pk_enc): Result<&EncodedVerifyingKey<Param>, _> = kat::PK.try_into() else {
        return SelfTestResult::VerifyFailed;
    };
    let vk = VerifyingKey::<Param>::decode(pk_enc);

    let Ok(sig_enc): Result<&EncodedSignature<Param>, _> = kat::SIG.try_into() else {
        return SelfTestResult::VerifyFailed;
    };
    let Some(decoded) = Signature::<Param>::decode(sig_enc) else {
        return SelfTestResult::VerifyFailed;
    };

    if vk.verify(kat::MSG, &decoded).is_err() {
        return SelfTestResult::VerifyFailed;
    }

    SelfTestResult::Pass
}

#[cfg(not(feature = "param-mldsa87"))]
#[cfg(test)]
mod selftest_tests {
    use super::*;

    #[test]
    fn selftest_passes_against_pinned_vector() {
        assert_eq!(selftest(), SelfTestResult::Pass);
    }
}
