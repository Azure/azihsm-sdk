// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmKdf`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] and
//! [`HkdfMode`] enums to their [`azihsm_crypto`] counterparts and
//! forwards calls to the [`StdKdf`](crate::drivers::kdf::StdKdf) driver.
//!
//! ## Data flow (HKDF example)
//!
//! ```text
//! Core calls pal.hkdf(key, HsmHashAlgo::Sha256, mode, salt, info, output)
//!   → to_hash_algo() maps to azihsm_crypto::HashAlgo::sha256()
//!   → to_hkdf_mode() maps to azihsm_crypto::HkdfMode
//!   → self.kdf.hkdf(key, hash_algo, mode, salt, info, output)
//!     → WorkerPool → OpenSSL HKDF
//!   → output written into caller's buffer
//! ```

use azihsm_crypto::HashAlgo;

use super::*;

/// Map the PAL-level [`HsmHashAlgo`] to the crypto library's
/// [`azihsm_crypto::HashAlgo`].
fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
    match algo {
        HsmHashAlgo::Sha1 => HashAlgo::sha1(),
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
    }
}

/// Map the PAL-level [`HkdfMode`] to the crypto library's
/// [`azihsm_crypto::HkdfMode`].
fn to_hkdf_mode(mode: HkdfMode) -> azihsm_crypto::HkdfMode {
    match mode {
        HkdfMode::Extract => azihsm_crypto::HkdfMode::Extract,
        HkdfMode::Expand => azihsm_crypto::HkdfMode::Expand,
        HkdfMode::ExtractAndExpand => azihsm_crypto::HkdfMode::ExtractAndExpand,
    }
}

impl HsmKdf for StdHsmPal {
    /// Derive key material using HKDF by delegating to the [`StdKdf`] driver.
    async fn hkdf(
        &self,
        key: &[u8],
        algo: HsmHashAlgo,
        mode: HkdfMode,
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        self.kdf
            .hkdf(
                key,
                to_hash_algo(algo),
                to_hkdf_mode(mode),
                salt,
                info,
                output,
            )
            .await
    }

    /// Derive key material using KBKDF by delegating to the [`StdKdf`] driver.
    async fn kbkdf(
        &self,
        key: &[u8],
        algo: HsmHashAlgo,
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        self.kdf
            .kbkdf(key, to_hash_algo(algo), label, context, output)
            .await
    }
}
