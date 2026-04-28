// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC (Hash-based Message Authentication Code) trait for the HSM PAL.
//!
//! Defines the [`HsmHmac`] trait that PAL implementations use to expose
//! HMAC key generation, signing (MAC computation), and verification.
//!
//! On Cortex-M7 hardware this would delegate to a dedicated HMAC engine
//! or use the SHA engine in HMAC mode. On the standard (host-native) PAL
//! it uses OpenSSL's HMAC implementation.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! HMAC key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Output buffer convention
//!
//! All methods take mandatory `&mut [u8]` output buffers. The caller is
//! responsible for providing buffers of the correct size (the MAC tag
//! length matches [`HsmHashAlgo::digest_len`] for the underlying hash).

use super::*;

/// Asynchronous HMAC operations trait.
///
/// PAL implementations provide this to the core for HMAC key generation,
/// MAC computation, and MAC verification. The async signatures allow
/// hardware-backed implementations to yield while the HMAC engine
/// processes data.
pub trait HsmHmac {
    /// Generate a random HMAC key.
    ///
    /// # Parameters
    /// - `key` — Output buffer filled with random key material. The
    ///   buffer length determines the key size (e.g., 32 bytes for
    ///   HMAC-SHA256, 48 for HMAC-SHA384, 64 for HMAC-SHA512).
    ///
    /// # Errors
    /// - [`HsmError`] if RNG fails or the PCT verification fails.
    async fn hmac_gen_key(&self, key: &mut [u8]) -> HsmResult<()>;

    /// Compute an HMAC tag (sign).
    ///
    /// # Parameters
    /// - `key` — The HMAC key to use.
    /// - `data` — Input message to authenticate.
    /// - `sig` — Output buffer for the MAC tag. Must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes for the key's underlying
    ///   hash algorithm.
    ///
    /// # Errors
    /// - [`HsmError`] if the HMAC computation fails.
    async fn hmac_sign(&self, key: &[u8], data: &[u8], sig: &mut [u8]) -> HsmResult<()>;

    /// Verify an HMAC tag.
    ///
    /// Computes the MAC over `data` using `key` and compares it to
    /// `sig` in constant time.
    ///
    /// # Parameters
    /// - `key` — The HMAC key to use.
    /// - `data` — The message that was authenticated.
    /// - `sig` — The MAC tag to verify against.
    ///
    /// # Returns
    /// `true` if the tag is valid, `false` if it does not match.
    ///
    /// # Errors
    /// - [`HsmError`] if the HMAC computation itself fails (distinct
    ///   from a tag mismatch, which returns `Ok(false)`).
    async fn hmac_verify(&self, key: &[u8], data: &[u8], sig: &[u8]) -> HsmResult<bool>;
}
