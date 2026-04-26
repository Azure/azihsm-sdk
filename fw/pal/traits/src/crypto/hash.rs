// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash (digest) trait for the HSM PAL.
//!
//! Defines [`HashAlgo`] and the [`HsmHash`] trait that PAL implementations
//! use to expose hardware-accelerated or software-backed hash computation.
//!
//! On Cortex-M7 hardware this would typically delegate to a SHA engine
//! peripheral. On the standard (host-native) PAL it would use OpenSSL.
//!
//! **Status**: The trait is defined but not yet included in the [`HsmCrypto`]
//! supertrait bound — no PAL implements it yet. It will be wired in when
//! DDI commands that require hashing (e.g., `EccSign`, `HkdfDerive`) are
//! implemented in `fw/core`.

use super::*;

/// Supported hash algorithms.
///
/// Discriminant values are `u32` for direct mapping to hardware register
/// selectors on Cortex-M7.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmHashAlgo {
    /// SHA-1 (160-bit digest). **Not FIPS-approved for signing.**
    Sha1,

    /// SHA-256 (256-bit / 32-byte digest).
    Sha256,

    /// SHA-384 (384-bit / 48-byte digest).
    Sha384,

    /// SHA-512 (512-bit / 64-byte digest).
    Sha512,
}

impl HsmHashAlgo {
    /// Returns the output digest length in bytes for the given algorithm.
    pub fn digest_len(&self) -> usize {
        match self {
            HsmHashAlgo::Sha1 => 20,
            HsmHashAlgo::Sha256 => 32,
            HsmHashAlgo::Sha384 => 48,
            HsmHashAlgo::Sha512 => 64,
        }
    }
}

/// Asynchronous hash computation trait.
///
/// PAL implementations provide this to the core for computing message
/// digests. The async signature allows hardware-backed implementations
/// to yield while a SHA engine processes data.
pub trait HsmHash {
    /// Compute a cryptographic hash of `data` using `algo`.
    ///
    /// # Parameters
    ///
    /// - `algo` — The hash algorithm to use.
    /// - `data` — Input message bytes to hash.
    /// - `digest` — Output buffer for the resulting digest. Must be at
    ///   least [`HsmHashAlgo::digest_len`] bytes for the selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the hash computation fails (e.g., hardware
    /// engine error).
    async fn hash(&self, algo: HsmHashAlgo, data: &[u8], digest: &mut [u8]) -> HsmResult<()>;
}
