// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC (Hash-based Message Authentication Code) trait for the HSM PAL.
//!
//! Defines the [`HsmHmac`] trait that PAL implementations use to expose
//! HMAC key generation, signing (MAC computation), and verification.
//!
//! On Cortex-M7 hardware this delegates to the SHA engine with software
//! HMAC key scheduling (RFC 2104 ipad/opad). On the standard
//! (host-native) PAL it uses OpenSSL's HMAC implementation.
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
//!
//! ## Multi-step API
//!
//! For messages that arrive in pieces, callers use
//! [`hmac_begin`](HsmHmac::hmac_begin) /
//! [`hmac_continue`](HsmHmac::hmac_continue) /
//! [`hmac_finish`](HsmHmac::hmac_finish) (or
//! [`hmac_finish_verify`](HsmHmac::hmac_finish_verify)). The caller
//! provides an [`HsmHashState`] buffer of at least
//! [`HsmHashAlgo::hmac_state_len`] bytes which the PAL uses to persist
//! intermediate state between calls.

use super::*;

/// Asynchronous HMAC operations trait.
///
/// PAL implementations provide this to the core for HMAC key generation,
/// MAC computation, and MAC verification. The async signatures allow
/// hardware-backed implementations to yield while the HMAC engine
/// processes data.
///
/// Both one-shot ([`hmac_sign`](Self::hmac_sign),
/// [`hmac_verify`](Self::hmac_verify)) and multi-step
/// ([`hmac_begin`](Self::hmac_begin) / [`hmac_continue`](Self::hmac_continue)
/// / [`hmac_finish`](Self::hmac_finish)) forms are provided.
pub trait HsmHmac {
    /// Platform-specific multi-step HMAC context.
    ///
    /// Created by [`hmac_begin`](Self::hmac_begin) and consumed by
    /// [`hmac_finish`](Self::hmac_finish) or
    /// [`hmac_finish_verify`](Self::hmac_finish_verify). Holds the
    /// intermediate SHA state, pending partial block, and the outer key
    /// (opad) needed for finalization.
    type HmacCtx<'a>
    where
        Self: 'a;

    /// Generate a random HMAC key.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm that determines the recommended key
    ///   size, though the actual key length is controlled by `key.len()`.
    /// - `key` — output buffer filled with random key material. The
    ///   buffer length determines the key size (e.g., 32 bytes for
    ///   HMAC-SHA256, 48 for HMAC-SHA384, 64 for HMAC-SHA512).
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if RNG fails or the PCT verification fails.
    async fn hmac_gen_key(&self, algo: HsmHashAlgo, key: &mut [u8]) -> HsmResult<()>;

    /// Compute an HMAC tag (sign) in a single call.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256, SHA-512).
    /// - `key` — the HMAC key to use.
    /// - `data` — input message to authenticate.
    /// - `tag` — output buffer for the MAC tag. Must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes for the chosen algorithm.
    /// - `state` — caller-owned buffer of at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes for intermediate state.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the HMAC computation fails or `tag` is
    /// too short.
    async fn hmac_sign<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        data: &[u8],
        tag: &mut [u8],
        state: HsmHashState<'a>,
    ) -> HsmResult<()>
    where
        Self: 'a;

    /// Verify an HMAC tag in a single call.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256, SHA-512).
    /// - `key` — the HMAC key to use.
    /// - `data` — the message that was authenticated.
    /// - `tag` — the MAC tag to verify against.
    /// - `state` — caller-owned buffer of at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes for intermediate state.
    ///
    /// # Returns
    ///
    /// `true` if the tag is valid, `false` if it does not match.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the HMAC computation itself fails (distinct
    /// from a tag mismatch, which returns `Ok(false)`).
    async fn hmac_verify<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        data: &[u8],
        tag: &[u8],
        state: HsmHashState<'a>,
    ) -> HsmResult<bool>
    where
        Self: 'a;

    /// Begin a multi-step HMAC computation.
    ///
    /// Derives the inner (ipad) and outer (opad) keys from `key` per
    /// RFC 2104 and submits the ipad block as the first SHA input.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm.
    /// - `key` — the HMAC key. Keys longer than `algo.block_len()` are
    ///   first hashed to `algo.digest_len()` bytes.
    /// - `state` — caller-owned buffer that must wrap at least
    ///   [`HsmHashAlgo::hmac_state_len`] bytes. Layout:
    ///   `[digest(state_len) | pending_block(block_len) | opad(block_len)]`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if `state` is too small.
    async fn hmac_begin<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        state: HsmHashState<'a>,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a;

    /// Feed arbitrary-length data into the running HMAC computation.
    ///
    /// May be called zero or more times between [`hmac_begin`](Self::hmac_begin)
    /// and [`hmac_finish`](Self::hmac_finish). Internally buffers a partial
    /// block and submits full blocks to the SHA engine.
    ///
    /// # Parameters
    ///
    /// - `ctx` — the HMAC context returned by [`hmac_begin`](Self::hmac_begin).
    /// - `data` — message bytes to append.
    async fn hmac_continue(&self, ctx: &mut Self::HmacCtx<'_>, data: &[u8]) -> HsmResult<()>;

    /// Finalize the inner hash and compute the outer hash to produce the
    /// HMAC tag. Consumes the context.
    ///
    /// # Returns
    ///
    /// An [`HsmHashState`] whose [`digest()`](HsmHashState::digest) slice
    /// contains the final MAC tag.
    async fn hmac_finish<'a>(&self, ctx: Self::HmacCtx<'a>) -> HsmResult<HsmHashState<'a>>;

    /// Finalize the HMAC and write the tag directly to `dest`.
    ///
    /// Like [`hmac_finish`](Self::hmac_finish), but the SHA hardware DMA
    /// writes the outer hash digest straight into `dest` instead of the
    /// context's state buffer. This avoids a `copy_from_slice` when the
    /// caller needs the tag in a separate output buffer (e.g. KDF
    /// iterations).
    ///
    /// # Parameters
    ///
    /// - `ctx` — the HMAC context to finalize (consumed).
    /// - `dest` — output buffer of at least
    ///   [`HsmHashAlgo::digest_len`] bytes.
    async fn hmac_finish_into(&self, ctx: Self::HmacCtx<'_>, dest: &mut [u8]) -> HsmResult<()>;

    /// Finalize and verify the MAC tag against `tag` using hardware
    /// constant-time comparison. Consumes the context.
    ///
    /// # Parameters
    ///
    /// - `ctx` — the HMAC context to finalize.
    /// - `tag` — the expected MAC tag to compare against.
    ///
    /// # Returns
    ///
    /// `true` if the computed tag matches, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError`] if the HMAC computation itself fails (distinct
    /// from a tag mismatch, which returns `Ok(false)`).
    async fn hmac_finish_verify(&self, ctx: Self::HmacCtx<'_>, tag: &[u8]) -> HsmResult<bool>;
}
