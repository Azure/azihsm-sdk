// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHash`] implementation for the standard (host-native) PAL.
//!
//! Bridges the PAL-level [`HsmHashAlgo`] enum to the crypto library's
//! [`azihsm_crypto::HashAlgo`] and delegates computation to the
//! [`StdHash`](crate::drivers::hash::StdHash) driver.
//!
//! ## Data flow
//!
//! ```text
//! Core calls pal.hash(algo, data, digest)
//!   → to_hash_algo() maps HsmHashAlgo → azihsm_crypto::HashAlgo
//!   → StdHash::hash() copies data to owned buffer
//!     → WorkerPool::submit_with_result() spawns on tokio
//!       → azihsm_crypto::HashOp::hash() (OpenSSL SHA)
//!     → result copied back into caller's `digest` buffer
//! ```
//!
//! On real Cortex-M7 hardware, hash computation would be offloaded to a
//! SHA engine peripheral via DMA with zero-copy into the response buffer.
//! Here we simulate the async pattern using the tokio worker pool.

use azihsm_crypto::HashAlgo;

use super::*;

/// Map the PAL-level [`HsmHashAlgo`] to the crypto library's
/// [`azihsm_crypto::HashAlgo`].
///
/// Each variant constructs the corresponding OpenSSL message digest
/// context (e.g., `EVP_sha256`).
fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
    match algo {
        HsmHashAlgo::Sha1 => HashAlgo::sha1(),
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
    }
}

impl HsmHash for StdHsmPal {
    /// Compute a cryptographic hash by delegating to the [`StdHash`]
    /// driver.
    ///
    /// The driver copies `data` to an owned buffer, offloads the OpenSSL
    /// SHA computation to the tokio worker pool, and writes the result
    /// into `digest`. The caller must ensure `digest` is at least
    /// [`HsmHashAlgo::digest_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::ShaError`] if the OpenSSL hash operation fails.
    async fn hash(&self, algo: HsmHashAlgo, data: &[u8], digest: &mut [u8]) -> HsmResult<()> {
        self.hash.hash(to_hash_algo(algo), data, digest).await
    }
}
