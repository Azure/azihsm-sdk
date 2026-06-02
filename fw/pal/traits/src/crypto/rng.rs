// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographically secure random number generation trait.
//!
//! Defines the [`HsmRng`] trait used by every PAL sub-component that
//! needs random bytes — IV/nonce generation, ephemeral keys, PSS salts,
//! masking blobs, etc.
//!
//! Implementations are backed by a hardware TRNG on the Cortex-M7
//! target and OpenSSL `RAND_bytes` on the standard PAL.

use super::super::*;

/// Synchronous random-byte source.
///
/// Unlike [`super::HsmHash`] / [`super::HsmEcc`], this trait is
/// **synchronous**: an RNG fill is fast enough (well below the
/// scheduler tick) that there is no benefit to yielding.  Callers can
/// use it from `async` and non-`async` contexts alike.
pub trait HsmRng {
    /// Fills `buf` with cryptographically secure random bytes.
    ///
    /// Every byte of `buf` is overwritten on success; on error the
    /// contents of `buf` are unspecified and must not be used.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `buf` — output buffer; entire length is filled with random
    ///   data.  Zero-length is a no-op success.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `buf` populated with `buf.len()` random bytes.
    /// - `Err(HsmError)` — propagated from the CSPRNG (TRNG hardware
    ///   error, entropy starvation, OpenSSL `RAND_bytes` failure).
    fn rng_fill_bytes(&self, io: &impl HsmIo, buf: &mut [u8]) -> HsmResult<()>;
}
