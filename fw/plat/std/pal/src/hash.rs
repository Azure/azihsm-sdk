// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHash`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] enum
//! to [`azihsm_crypto::HashAlgo`] and forwards the call to the
//! [`StdHash`](crate::drivers::hash::StdHash) driver.
//!
//! ## Data flow
//!
//! ```text
//! Core calls pal.hash(HsmHashAlgo::Sha256, data, digest)
//!   → to_hash_algo() maps to azihsm_crypto::HashAlgo::sha256()
//!   → self.hash.hash(algo, data, digest)
//!     → StdHash copies data, dispatches to WorkerPool
//!       → OpenSSL EVP_Digest (SHA-256)
//!     → digest written into caller's buffer
//! ```

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
    /// Compute a cryptographic hash by delegating to the [`StdHash`] driver.
    ///
    /// # Parameters
    /// - `algo` — The hash algorithm (SHA-1/256/384/512).
    /// - `data` — Input message bytes.
    /// - `digest` — Output buffer (must be ≥ [`HsmHashAlgo::digest_len`] bytes).
    ///
    /// # Errors
    /// Returns [`HsmError::ShaError`] if the underlying OpenSSL operation fails.
    async fn hash(&self, algo: HsmHashAlgo, data: &[u8], digest: &mut [u8]) -> HsmResult<()> {
        self.hash.hash(to_hash_algo(algo), data, digest).await
    }
}
