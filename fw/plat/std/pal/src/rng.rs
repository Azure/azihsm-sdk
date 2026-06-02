// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Random number generation for the standard (host-native) PAL.
//!
//! Implements the [`HsmRng`] trait from `azihsm_fw_hsm_pal_traits` for
//! [`StdHsmPal`], delegating to the OpenSSL-backed `azihsm_crypto::Rng`
//! for cryptographically secure random byte generation.
//!
//! On the real Cortex-M7 hardware this would be backed by a hardware TRNG
//! peripheral; here we use the host OS CSPRNG via OpenSSL as a stand-in
//! for simulation and testing.

use super::*;

impl HsmRng for StdHsmPal {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// Delegates to [`azihsm_crypto::Rng::rand_bytes`], which calls
    /// OpenSSL's `RAND_bytes`. Returns [`HsmError::InternalError`] if
    /// the underlying CSPRNG fails (e.g., insufficient entropy).
    fn rng_fill_bytes(&self, _io: &impl HsmIo, buf: &mut [u8]) -> HsmResult<()> {
        azihsm_crypto::Rng::rand_bytes(buf).map_err(|_| HsmError::InternalError)
    }
}
