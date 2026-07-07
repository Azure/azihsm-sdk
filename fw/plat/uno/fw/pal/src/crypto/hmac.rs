// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the Uno PAL.
//!
//! Implements RFC 2104 HMAC over the on-chip SHA accelerator. Both
//! one-shot and multi-step APIs are supported; multi-step state is
//! allocated from an [`HsmScopedAlloc`].
//!
//! ## Scoped state buffer
//!
//! Every multi-step call allocates a buffer of at least
//! [`HsmHashAlgo::hmac_state_len`] bytes, partitioned as
//! `[state(state_len) | pending(block_len) | opad(block_len)]`:
//!
//! * **state** — intermediate SHA working variables; ultimately holds
//!   the inner-hash digest, then the final HMAC tag.
//! * **pending** — accumulates a partial block between
//!   [`hmac_continue`](HsmHmac::hmac_continue) calls.
//! * **opad** — pre-computed `SHA(opad_block)` working state, kept
//!   unchanged from [`hmac_begin`](HsmHmac::hmac_begin) until the outer
//!   hash in [`hmac_finish`](HsmHmac::hmac_finish).
//!
//! ## Algorithm overview
//!
//! [`hmac_begin`](HsmHmac::hmac_begin) derives the effective key
//! (hashing it down if it exceeds the block length), pre-computes the
//! opad working state, then primes the inner hash with the ipad block.
//! [`hmac_continue`](HsmHmac::hmac_continue) shovels message bytes into
//! the SHA engine using the same fill-flush-buffer pattern as
//! [`super::hash`]. [`hmac_finish`](HsmHmac::hmac_finish) flushes the
//! pending bytes with auto-pad enabled, then runs the outer hash by
//! loading the cached opad state and feeding it the inner digest.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmHmac;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRng;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_sha::ShaRequest;

use super::hash::ShaDigestContext;
use crate::UnoHsmPal;

// =============================================================================
// Constants
// =============================================================================

/// Maximum block length across all supported hash algorithms (SHA-512 = 128).
const MAX_BLOCK_LEN: usize = HsmHashAlgo::Sha512.block_len();

/// RFC 2104 inner padding byte (0x36).
const HMAC_IPAD: u8 = 0x36;

/// RFC 2104 outer padding byte (0x5C).
const HMAC_OPAD: u8 = 0x5C;

// =============================================================================
// HmacContext
// =============================================================================

/// Multi-step HMAC context.
///
/// Created by [`hmac_begin`](HsmHmac::hmac_begin) and consumed by
/// [`hmac_finish`](HsmHmac::hmac_finish),
/// [`hmac_finish_into`](HsmHmac::hmac_finish_into), or
/// [`hmac_finish_verify`](HsmHmac::hmac_finish_verify). Carries the
/// algorithm selection, running inner-hash byte count, and the
/// alloc-allocated `[state | pending | opad]` buffer (see [module-level
/// docs](self#scoped-state-buffer)).
#[derive(Debug)]
pub struct HmacContext<'a> {
    /// Hash algorithm selected at [`hmac_begin`](HsmHmac::hmac_begin).
    algo: HsmHashAlgo,

    /// Total inner-hash message bytes submitted to hardware so far.
    ///
    /// Passed to the SHA engine on every submission. On the final block
    /// the engine uses this value (plus the pending length) to construct
    /// the length field in the SHA padding.
    byte_count: u32,

    /// Scope-allocated `[state | pending | opad]` buffer.
    buf: &'a mut DmaBuf,

    /// Number of valid bytes currently in the pending region.
    pending_len: u8,
}

impl<'a> HmacContext<'a> {
    /// Copies bytes from `data` into the pending region until it is
    /// full or `data` is exhausted.
    ///
    /// # Parameters
    /// * `data` — source bytes to append to the pending buffer.
    ///
    /// # Returns
    /// * The unconsumed tail of `data` (empty if all bytes fit).
    fn fill_pending<'d>(&mut self, data: &'d DmaBuf) -> &'d DmaBuf {
        let pending_start = self.algo.state_len();
        let start = self.pending_len as usize;
        let n = (self.algo.block_len() - start).min(data.len());
        self.buf[pending_start + start..pending_start + start + n].copy_from_slice(&data[..n]);
        self.pending_len += n as u8;
        &data[n..]
    }
    /// `true` when the pending region holds exactly one full block and
    /// must be flushed before more data can be buffered.
    fn pending_full(&self) -> bool {
        self.pending_len as usize == self.algo.block_len()
    }

    /// Borrow the three regions of [`buf`](Self::buf) as disjoint
    /// mutable slices via chained `split_at_mut`.
    ///
    /// # Returns
    /// * `(state, pending, opad)` — non-overlapping mutable borrows
    ///   covering bytes `0..state_len`, `state_len..state_len+block_len`,
    ///   and `state_len+block_len..state_len+2*block_len` respectively.
    fn split_regions(&mut self) -> (&mut DmaBuf, &mut DmaBuf, &mut DmaBuf) {
        let state_len = self.algo.state_len();
        let block_len = self.algo.block_len();
        let (state, rest) = self.buf.split_at_mut(state_len);
        let (pending, opad) = rest.split_at_mut(block_len);
        (state, pending, opad)
    }
}

impl ShaDigestContext for HmacContext<'_> {
    fn algo(&self) -> HsmHashAlgo {
        self.algo
    }

    fn byte_count(&self) -> u32 {
        self.byte_count
    }

    fn set_byte_count(&mut self, byte_count: u32) {
        self.byte_count = byte_count;
    }

    fn buf(&mut self) -> &mut DmaBuf {
        self.buf
    }
}

// =============================================================================
// HsmHmac trait impl
// =============================================================================
//
// The primary contract for each method (intended semantics, parameter
// shapes, error model) lives on the [`HsmHmac`] trait itself. The notes
// below describe the Uno-specific behaviour and the buffer surgery
// each method performs.

impl HsmHmac for UnoHsmPal {
    type HmacCtx<'a> = HmacContext<'a>;

    /// Generate a random HMAC key.
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `_algo` — hash algorithm the key will be used with (ignored;
    ///   key length is determined by `key.len()`).
    /// * `key` — destination buffer; every byte is overwritten with
    ///   hardware-generated random bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the RNG driver.
    async fn hmac_gen_key(
        &self,
        io: &impl HsmIo,
        _algo: HsmHashAlgo,
        key: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.rng_fill_bytes(io, key)
    }

    /// One-shot HMAC sign: compute `HMAC(key, data)` and write the tag.
    ///
    /// Internally allocates a scoped HMAC state buffer, then calls
    /// [`hmac_begin_in_buf`](Self::hmac_begin_in_buf) /
    /// [`hmac_continue`](Self::hmac_continue) /
    /// [`hmac_finish`](Self::hmac_finish).
    ///
    /// # Parameters
    /// * `algo` — hash algorithm (selects digest/block lengths).
    /// * `key` — HMAC key bytes (any length).
    /// * `data` — message to authenticate (any length).
    /// * `tag` — destination buffer for the tag. Must be at least
    ///   `algo.digest_len()` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `tag` is shorter than the
    ///   algorithm's digest length.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_sign(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            if tag.len() < algo.digest_len() {
                return Err(HsmError::InvalidArg);
            }

            let hmac_buf = scope.dma_alloc(algo.hmac_state_len())?;
            let mut ctx = self.hmac_begin_in_buf(io, algo, key, hmac_buf).await?;
            self.hmac_continue(io, &mut ctx, data).await?;
            self.hmac_finish(io, ctx, tag).await?;
            Ok::<(), HsmError>(())
        })
        .await
    }

    /// One-shot HMAC verify: compute `HMAC(key, data)` and compare to `tag`.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `key` — HMAC key bytes (any length).
    /// * `data` — message to authenticate.
    /// * `tag` — expected tag. Must be exactly `algo.digest_len()` bytes.
    ///
    /// # Returns
    /// * `Ok(true)` if the computed tag matches `tag`.
    /// * `Ok(false)` if it does not.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `tag.len() != algo.digest_len()`.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_verify(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &DmaBuf,
    ) -> HsmResult<bool> {
        self.alloc_scoped_async(io, async |scope| {
            if tag.len() != algo.digest_len() {
                return Err(HsmError::InvalidArg);
            }

            let hmac_buf = scope.dma_alloc(algo.hmac_state_len())?;
            let mut ctx = self.hmac_begin_in_buf(io, algo, key, hmac_buf).await?;
            self.hmac_continue(io, &mut ctx, data).await?;
            self.hmac_finish_verify(io, ctx, tag).await
        })
        .await
    }

    /// Begin a multi-step HMAC computation.
    ///
    /// Performs RFC 2104 key conditioning, pre-computes the opad SHA
    /// working state into the opad region of `state`, then primes the
    /// inner hash with the ipad block.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `key` — HMAC key bytes (any length). Hashed down to
    ///   `digest_len()` bytes if longer than `block_len()`.
    /// * `alloc` — scoped allocator used for the internal HMAC state.
    ///
    /// # Returns
    /// * `Ok(HmacContext)` ready to accept message bytes.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if `alloc` cannot allocate the
    ///   internal HMAC state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver during key
    ///   conditioning or opad pre-hashing.
    async fn hmac_begin<'a>(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a,
    {
        // Generic multi-step HMAC callers may already retain substantial
        // Local (DTCM) scratch in the same scoped allocation (for example,
        // HPKE KEM/KDF intermediates). Put the larger HMAC state in Global
        // SRAM so CBC-HMAC does not exhaust the 2 KiB Local heap.
        let buf = alloc.dma_alloc(algo.hmac_state_len())?;
        self.hmac_begin_in_buf(_io, algo, key, buf).await
    }

    /// Feed arbitrary-length data into the inner hash.
    ///
    /// Operates in the same fill-flush-buffer pattern as
    /// [`super::hash::HsmHashContext`].
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `ctx` — active HMAC context.
    /// * `data` — message bytes (any length, including zero).
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_continue(
        &self,
        io: &impl HsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        let _ = io;
        self.hmac_continue_bytes(ctx, data).await
    }

    /// Finalize the HMAC and copy the tag into `tag`. Consumes `ctx`.
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `ctx` — context to finalize.
    /// * `tag` — destination buffer for the final tag. Must be at least
    ///   `algo.digest_len()` bytes.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `tag` is shorter than the digest.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_finish(
        &self,
        io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        let _ = io;
        let digest_len = ctx.algo.digest_len();
        if tag.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }

        self.hmac_outer_compute(&mut ctx, OuterMode::IntoState)
            .await?;
        tag[..digest_len].copy_from_slice(&ctx.buf[..digest_len]);
        Ok(())
    }

    /// Finalize the HMAC and write the tag directly into `dest`.
    /// Consumes `ctx`.
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `ctx` — context to finalize.
    /// * `dest` — destination buffer. Must be non-empty; if shorter
    ///   than `algo.digest_len()` the tag is truncated.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_finish_into(
        &self,
        io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        dest: &mut DmaBuf,
    ) -> HsmResult<()> {
        let _ = io;
        let digest_len = ctx.algo.digest_len();

        if dest.len() >= digest_len {
            // Direct DMA: SHA writes the outer hash straight into `dest`.
            self.hmac_outer_compute(&mut ctx, OuterMode::IntoDest(&mut dest[..digest_len]))
                .await?;
            Ok(())
        } else {
            // Truncated: SHA writes to the state region, copy a prefix.
            self.hmac_outer_compute(&mut ctx, OuterMode::IntoState)
                .await?;
            let dest_len = dest.len();
            dest.copy_from_slice(&ctx.buf[..dest_len]);
            Ok(())
        }
    }

    /// Finalize the HMAC and verify the tag against the expected value.
    /// Consumes `ctx`.
    ///
    /// # Parameters
    /// * `io` — PAL I/O handle for platform-mediated operations.
    /// * `ctx` — context to finalize.
    /// * `tag` — expected tag. Must be exactly `algo.digest_len()`
    ///   bytes.
    ///
    /// # Returns
    /// * `Ok(true)` if the computed tag matches `tag`.
    /// * `Ok(false)` if it does not.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `tag.len() != algo.digest_len()`.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_finish_verify(
        &self,
        io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        tag: &DmaBuf,
    ) -> HsmResult<bool> {
        let _ = io;
        if tag.len() != ctx.algo.digest_len() {
            return Err(HsmError::InvalidArg);
        }

        self.hmac_outer_compute(&mut ctx, OuterMode::Verify(tag))
            .await
    }
}

// =============================================================================
// Private helpers
// =============================================================================

/// Selects how [`UnoHsmPal::hmac_outer_compute`] terminates.
enum OuterMode<'a> {
    /// Write the final tag into the state region of `ctx.buf`.
    IntoState,
    /// Write the final tag into a caller-supplied slice.
    IntoDest(&'a mut DmaBuf),
    /// Compare the final tag against a reference and report the result.
    Verify(&'a DmaBuf),
}

impl UnoHsmPal {
    pub(crate) async fn hmac_continue_bytes(
        &self,
        ctx: &mut HmacContext<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        let block_len = ctx.algo.block_len();

        let remaining = if ctx.pending_len > 0 {
            let tail = ctx.fill_pending(data);
            if ctx.pending_full() {
                self.hmac_flush_pending(ctx, false).await?;
            }
            tail
        } else {
            data
        };

        let full_len = remaining.len() / block_len * block_len;
        let (full_blocks, tail) = remaining.split_at(full_len);
        if !full_blocks.is_empty() {
            self.hmac_submit_blocks(ctx, full_blocks).await?;
        }
        if !tail.is_empty() {
            ctx.fill_pending(tail);
        }

        Ok(())
    }

    pub(crate) async fn hmac_begin_in_buf<'a>(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        buf: &'a mut DmaBuf,
    ) -> HsmResult<HmacContext<'a>> {
        let block_len = algo.block_len();
        let state_len = algo.state_len();
        buf.fill(0);

        // `effective_key` must be DMA-accessible (SHA writes to it when
        // key > block_len). Scoped alloc frees it after pad computation.
        self.alloc_scoped_async(io, async |scope| {
            let effective_key = scope.dma_alloc(MAX_BLOCK_LEN)?;
            effective_key.fill(0);
            if key.len() > block_len {
                self.sha_oneshot(algo, key, &mut effective_key[..algo.digest_len()], false)
                    .await?;
            } else {
                effective_key[..key.len()].copy_from_slice(key);
            }

            // Split `buf` into `[state | pending | opad]`.
            let (_, rest) = buf.split_at_mut(state_len);
            let (pending, opad) = rest.split_at_mut(block_len);

            // OPAD: write key ⊕ OPAD into `pending`, then hash it into `opad`.
            for i in 0..block_len {
                pending[i] = effective_key[i] ^ HMAC_OPAD;
            }
            let req = ShaRequest::new(algo.into(), pending, &mut opad[..state_len])
                .with_full_state()
                .with_byte_swap();
            self.sha.digest(req).await?;

            // IPAD: overwrite `pending` with key ⊕ IPAD for the first inner block.
            for i in 0..block_len {
                pending[i] = effective_key[i] ^ HMAC_IPAD;
            }

            Ok::<(), HsmError>(())
        })
        .await?;

        let mut ctx = HmacContext {
            algo,
            byte_count: 0,
            buf,
            pending_len: block_len as u8,
        };
        self.hmac_flush_pending(&mut ctx, false).await?;
        Ok(ctx)
    }

    /// Flush whatever bytes are in the pending region to the SHA engine
    /// and reset `pending_len` to zero.
    ///
    /// # Parameters
    /// * `ctx` — active HMAC context. On success, `ctx.pending_len` is
    ///   `0` and `ctx.byte_count` has been advanced.
    /// * `finalize` — when `true`, SHA auto-padding is applied so the
    ///   engine writes the final inner-hash digest. When `false`, the
    ///   full working state is emitted for chaining into the next
    ///   submission.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_flush_pending(&self, ctx: &mut HmacContext<'_>, finalize: bool) -> HsmResult<()> {
        let len = ctx.pending_len as usize;
        self.sha_digest_block(ctx, None, len, finalize, false)
            .await?;
        ctx.pending_len = 0;
        Ok(())
    }

    /// Submit one or more full blocks straight from `blocks` to the
    /// SHA engine (zero-copy path).
    ///
    /// # Parameters
    /// * `ctx` — active HMAC context. On success, `ctx.byte_count` has
    ///   been advanced by `blocks.len()`.
    /// * `blocks` — message bytes whose length must be a non-zero
    ///   multiple of `algo.block_len()`.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_submit_blocks(
        &self,
        ctx: &mut HmacContext<'_>,
        blocks: &DmaBuf,
    ) -> HsmResult<()> {
        self.sha_digest_block(ctx, Some(blocks), blocks.len(), false, false)
            .await
    }

    /// Run the HMAC outer hash and dispatch on the selected
    /// [`OuterMode`].
    ///
    /// Steps:
    /// 1. Flush any remaining inner-hash bytes with auto-pad enabled.
    ///    After this the inner digest sits at `ctx.buf[..digest_len]`.
    /// 2. Copy that inner digest into the pending region so it can be
    ///    used as the SHA message while the state region is freed for
    ///    the outer-hash output.
    /// 3. Submit one final SHA request that loads the cached opad
    ///    state, hashes the inner digest with auto-pad enabled, and
    ///    writes the tag (or compares it) per `mode`.
    ///
    /// # Parameters
    /// * `ctx` — active HMAC context (consumed conceptually — caller
    ///   must drop afterwards).
    /// * `mode` — destination/verification selector.
    ///
    /// # Returns
    /// * `OuterMode::IntoState` / `OuterMode::IntoDest` — `Ok(true)` on
    ///   success (the boolean is unused by sign callers but allows a
    ///   single return type).
    /// * `OuterMode::Verify` — `Ok(true)` on tag match, `Ok(false)`
    ///   otherwise.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn hmac_outer_compute(
        &self,
        ctx: &mut HmacContext<'_>,
        mode: OuterMode<'_>,
    ) -> HsmResult<bool> {
        // Step 1: flush remaining bytes through the inner hash with
        // padding enabled. The inner digest now lives in `ctx.buf[..]`.
        self.hmac_flush_pending(ctx, true).await?;

        let algo = ctx.algo;
        let mode_sha = algo.into();
        let state_len = algo.state_len();
        let digest_len = algo.digest_len();
        let block_len = algo.block_len();
        // Outer-hash total message length: opad block (block_len) + inner
        // digest (digest_len). Used to construct the SHA padding length.
        let outer_total = block_len as u32 + digest_len as u32;

        // Step 2: copy the inner digest from the state region into the
        // pending region. This frees `state` for use as the outer-hash
        // output buffer and lets us hand `pending`/`opad` to the SHA
        // request as disjoint borrows produced by `split_regions`.
        let (state, pending, opad) = ctx.split_regions();
        pending[..digest_len].copy_from_slice(&state[..digest_len]);

        let inner = &pending[..digest_len];
        let opad_state = &opad[..state_len];

        // Step 3: build the request once and dispatch on verify-vs-write.
        let (dest, verify_tag) = match mode {
            OuterMode::IntoState => (&mut state[..state_len], None),
            OuterMode::IntoDest(d) => (d, None),
            OuterMode::Verify(t) => (&mut state[..state_len], Some(t)),
        };
        let req = ShaRequest::new(mode_sha, inner, dest)
            .with_auto_pad(outer_total)
            .with_initial_digest(opad_state);
        match verify_tag {
            Some(tag) => self.sha.digest_verify(req.with_check_digest(tag)).await,
            None => {
                self.sha.digest(req).await?;
                Ok(true)
            }
        }
    }
}
