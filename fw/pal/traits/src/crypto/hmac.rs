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
//! [`hmac_finish_verify`](HsmHmac::hmac_finish_verify)). The PAL allocates
//! the intermediate HMAC state from an [`HsmScopedAlloc`], matching the
//! scoped-allocation pattern used by the hash API.

use super::HsmScopedAlloc;
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
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm; informational, used by
    ///   PAL implementations that record key metadata.  The actual
    ///   key length is determined by `key.len()`.
    /// - `key` — output buffer; entire length is filled with random
    ///   bytes.  Typical sizes are `algo.digest_len()`
    ///   (32 / 48 / 64 bytes for SHA-256 / 384 / 512).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `key` populated with `key.len()` random bytes.
    /// - `Err(HsmError)` — propagated from the CSPRNG.
    async fn hmac_gen_key(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// Compute an HMAC tag (sign) in a single call.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key bytes; longer than `algo.block_len()`
    ///   triggers an internal pre-hash to `algo.digest_len()`.
    /// - `data` — message to authenticate.  Any length, including
    ///   zero.
    /// - `tag` — output buffer; must be at least
    ///   `algo.digest_len()` bytes.  Only the leading `digest_len`
    ///   bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `tag[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `tag` shorter than
    ///   `algo.digest_len()`.
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation
    ///   cannot fit the HMAC state buffer.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_sign(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// Verify an HMAC tag in a single call using constant-time
    /// comparison.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key (same key that produced the tag).
    /// - `data` — message that was authenticated.
    /// - `tag` — MAC tag to verify against.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — tag is valid.
    /// - `Ok(false)` — tag does not match (not an error).
    /// - `Err(HsmError::NotEnoughSpace)` — internal scoped allocation
    ///   cannot fit the HMAC state buffer.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_verify(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &DmaBuf,
    ) -> HsmResult<bool>;

    /// Begin a multi-step HMAC computation.
    ///
    /// Derives the inner (ipad) and outer (opad) keys from `key` per
    /// RFC 2104, submits the ipad block as the first SHA input, and
    /// stores the opad-keyed prefix in the returned context for use
    /// at finalisation.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `algo` — underlying hash algorithm.
    /// - `key` — HMAC key bytes; keys longer than
    ///   `algo.block_len()` are first hashed.
    /// - `alloc` — scoped allocator backing
    ///   [`Self::HmacCtx`]; the context borrows from this scope.
    ///
    /// # Returns
    ///
    /// - `Ok(ctx)` — fresh HMAC context.
    /// - `Err(HsmError::NotEnoughSpace)` — `alloc` cannot satisfy
    ///   `algo.hmac_state_len()` bytes.
    /// - `Err(HsmError)` — SHA driver failure during the ipad
    ///   prelude.
    async fn hmac_begin<'a>(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a;

    /// Feed arbitrary-length data into a running HMAC.
    ///
    /// May be called any number of times (including zero) between
    /// [`hmac_begin`](Self::hmac_begin) and the chosen finaliser.
    /// Implementations buffer a partial trailing block and submit
    /// full blocks to the SHA engine as soon as they accumulate.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context returned by
    ///   [`hmac_begin`](Self::hmac_begin).
    /// - `data` — message bytes to append.
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_continue(
        &self,
        io: &impl HsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()>;

    /// Finalise the inner hash, compute the outer hash, and write
    /// the resulting tag into `tag`.  Consumes `ctx`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context to finalise (consumed).
    /// - `tag` — output buffer; must be at least
    ///   `algo.digest_len()` bytes.  Only the leading `digest_len`
    ///   bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `tag[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `tag` too short.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish(
        &self,
        io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        tag: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// Finalise the HMAC and write the tag directly to `dest`.
    ///
    /// Identical to [`hmac_finish`](Self::hmac_finish) except the
    /// SHA hardware DMA writes the outer-hash digest straight into
    /// `dest` rather than into the context's state buffer.  This
    /// elides a `copy_from_slice` when the caller already has a
    /// destination in mind (e.g. KDF iterations).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context to finalise (consumed).
    /// - `dest` — destination buffer; must be at least
    ///   `algo.digest_len()` bytes.  Only the leading `digest_len`
    ///   bytes are written.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `dest[..digest_len]` populated.
    /// - `Err(HsmError::InvalidArg)` — `dest` too short.
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish_into(
        &self,
        io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        dest: &mut DmaBuf,
    ) -> HsmResult<()>;

    /// Finalise and verify the running HMAC against an expected
    /// `tag` using hardware constant-time comparison.  Consumes
    /// `ctx`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `ctx` — context to finalise (consumed).
    /// - `tag` — expected MAC tag.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — tag matches.
    /// - `Ok(false)` — tag does not match (not an error).
    /// - `Err(HsmError)` — SHA driver failure.
    async fn hmac_finish_verify(
        &self,
        io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        tag: &DmaBuf,
    ) -> HsmResult<bool>;
}
