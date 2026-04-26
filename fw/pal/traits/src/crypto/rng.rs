// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographically secure random number generation trait for the HSM PAL.
//!
//! Defines the [`HsmRng`] trait that PAL implementations use to expose
//! hardware or software CSPRNG. On Cortex-M7 hardware this would be
//! backed by a TRNG peripheral; on the standard PAL it uses OpenSSL's
//! `RAND_bytes`.

use super::super::*;

/// Synchronous random number generation interface.
///
/// Unlike [`HsmHash`] and [`HsmEcc`], this is a synchronous trait — RNG
/// fill is fast enough that yielding to the executor is unnecessary.
pub trait HsmRng {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// # Parameters
    /// - `buf` — Output buffer to fill. All `buf.len()` bytes will be
    ///   overwritten with random data on success.
    ///
    /// # Errors
    /// Returns [`HsmError`] if the CSPRNG fails (e.g., insufficient
    /// entropy, hardware TRNG error).
    fn rng_fill_bytes(&mut self, buf: &mut [u8]) -> HsmResult<()>;
}
