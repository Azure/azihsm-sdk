// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate-local error type. Mapped into
//! [`HsmError`](azihsm_fw_hsm_pal_traits::HsmError) at the public
//! boundary so callers see a uniform PAL error surface.

use azihsm_fw_hsm_pal_traits::HsmError;

/// Errors produced by [`seal`](crate::seal) and [`open`](crate::open).
///
/// `Error` exists so the per-call validation logic can be unit-tested
/// without dragging in the full [`HsmError`] surface. It is converted
/// into `HsmError` via [`From`] when bubbled out of the public API.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The output buffer (for [`seal`](crate::seal)) or input buffer
    /// (for [`open`](crate::open)) is
    /// shorter than the envelope length implied by the inputs /
    /// header.
    BufferTooSmall {
        /// Minimum required length in bytes.
        needed: usize,
    },
    /// The envelope's magic bytes do not match [`FORMAT_TAG`](crate::FORMAT_TAG),
    /// or the reserved header byte is non-zero.
    InvalidFormat,
    /// The envelope's `alg` byte is not the discriminant of any
    /// [`AeadAlg`](crate::AeadAlg) variant supported by this crate
    /// version (v1: only `0x03` for AES-256-GCM).
    UnsupportedAlg(u8),
    /// The supplied key length does not match
    /// [`AeadAlg::key_len`](crate::AeadAlg::key_len) for the selected
    /// algorithm.
    InvalidKeyLength,
    /// The supplied IV length does not match
    /// [`AeadAlg::iv_len`](crate::AeadAlg::iv_len) for the selected
    /// algorithm.
    InvalidIvLength,
    /// `aad_len` is not `0` or a multiple of `32`, or exceeds
    /// [`MAX_AAD_LEN`](crate::MAX_AAD_LEN).
    InvalidAadLength,
    /// On [`open`](crate::open): the GCM authentication tag does not
    /// match. Always returned in preference to more specific format
    /// errors after a successful header parse, to avoid leaking
    /// information about why decryption failed.
    AuthFailed,
    /// The PAL reported an error during the underlying crypto call.
    Backend(HsmError),
}

impl From<Error> for HsmError {
    fn from(e: Error) -> Self {
        match e {
            Error::BufferTooSmall { .. } => HsmError::InvalidArg,
            Error::InvalidFormat => HsmError::InvalidArg,
            Error::UnsupportedAlg(_) => HsmError::InvalidArg,
            Error::InvalidKeyLength => HsmError::InvalidArg,
            Error::InvalidIvLength => HsmError::InvalidArg,
            Error::InvalidAadLength => HsmError::InvalidArg,
            Error::AuthFailed => HsmError::AesGcmDecryptTagDoesNotMatch,
            Error::Backend(e) => e,
        }
    }
}

/// Crate-local result alias.
pub type Result<T> = core::result::Result<T, Error>;
