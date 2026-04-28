// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdHmac`](crate::drivers::hmac::StdHmac)
//! driver. The PAL impl maps key length to the underlying hash algorithm
//! and delegates all crypto work to the driver (which offloads to the
//! worker pool).
//!
//! ## Key-length → hash-algorithm mapping
//!
//! | Key length | Hash algorithm |
//! |------------|----------------|
//! | 32 bytes   | SHA-256        |
//! | 48 bytes   | SHA-384        |
//! | 64 bytes   | SHA-512        |
//! | other      | SHA-256        |
//!
//! ## Data flow (sign example)
//!
//! ```text
//! Core calls pal.hmac_sign(key, data, sig)
//!   → hash_algo_for_key_len(key.len())   // 32 → SHA-256
//!   → self.hmac.sign(hash_algo, key, data, sig)
//!     → WorkerPool → OpenSSL HMAC
//!   → sig written into caller's buffer
//! ```

use azihsm_crypto::HashAlgo;

use super::*;

/// Map HMAC key length to the corresponding [`HashAlgo`].
///
/// Uses the key length as an implicit indicator of the intended hash
/// algorithm. Falls back to SHA-256 for unrecognized sizes.
fn hash_algo_for_key_len(len: usize) -> HashAlgo {
    match len {
        32 => HashAlgo::sha256(),
        48 => HashAlgo::sha384(),
        64 => HashAlgo::sha512(),
        _ => HashAlgo::sha256(),
    }
}

impl HsmHmac for StdHsmPal {
    /// Generate a random HMAC key by delegating to the driver.
    async fn hmac_gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        self.hmac.gen_key(key).await
    }

    /// Compute an HMAC tag by mapping key length to hash algo and
    /// delegating to the driver.
    async fn hmac_sign(&self, key: &[u8], data: &[u8], sig: &mut [u8]) -> HsmResult<()> {
        let hash_algo = hash_algo_for_key_len(key.len());
        self.hmac.sign(hash_algo, key, data, sig).await
    }

    /// Verify an HMAC tag by mapping key length to hash algo and
    /// delegating to the driver.
    async fn hmac_verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> HsmResult<bool> {
        let hash_algo = hash_algo_for_key_len(key.len());
        self.hmac.verify(hash_algo, key, data, sig).await
    }
}
