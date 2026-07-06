// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHash`] implementation for the Uno PAL.
//!
//! Delegates all hashing to the SHA hardware accelerator via [`ShaRequest`].
//! Two paths are supported:
//!
//! - **One-shot** ([`hash`](HsmHash::hash)) — the entire message is submitted
//!   in a single hardware request with automatic padding.
//!
//! - **Multi-step** ([`hash_begin`](HsmHash::hash_begin) /
//!   [`hash_continue`](HsmHash::hash_continue) /
//!   [`hash_finish`](HsmHash::hash_finish)) — data arrives incrementally and
//!   is buffered in alloc-allocated scratch memory until full blocks can be
//!   flushed to hardware.
//!
//! ## Multi-step algorithm
//!
//! [`HsmHashContext`] holds a single alloc-allocated buffer with layout
//! `[state | pending]`, where the state region stores the intermediate SHA
//! working variables and the pending region accumulates a partial block.
//!
//! Each [`hash_continue`](HsmHash::hash_continue) call proceeds in three
//! phases:
//!
//! 1. **Fill** — bytes are copied into `pending` until it reaches the
//!    algorithm's block size.
//! 2. **Flush** — full blocks (both from `pending` and any remaining
//!    block-aligned data in the caller's buffer) are submitted to the SHA
//!    engine.  Intermediate requests use `full_state` + `byte_swap` so the
//!    engine emits the complete working state in little-endian order, which
//!    is reloaded via `load_digest` on the next submission.
//! 3. **Buffer** — any trailing sub-block bytes are saved in `pending` for
//!    the next call.
//!
//! [`hash_finish`](HsmHash::hash_finish) flushes whatever remains in
//! `pending` with `auto_pad` enabled so the hardware appends standard SHA
//! padding and writes the final truncated NIST digest.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_sha::ShaRequest;

use crate::UnoHsmPal;

/// Multi-step hash context for the Uno SHA hardware accelerator.
///
/// Carries the algorithm selection, running byte count, and a alloc-allocated
/// buffer that persists across [`hash_continue`](HsmHash::hash_continue)
/// calls. Created by [`hash_begin`](HsmHash::hash_begin) and consumed by
/// [`hash_finish`](HsmHash::hash_finish).
#[derive(Debug)]
pub struct HsmHashContext<'a> {
    /// Hash algorithm selected at creation time.
    algo: HsmHashAlgo,

    /// Total number of message bytes submitted to hardware so far.
    ///
    /// Passed to the SHA engine on every submission.  On the final block the
    /// engine uses this value (plus the current message length) to construct
    /// the 64-bit or 128-bit length field in the SHA padding.
    byte_count: u32,

    /// Scope-allocated state buffer with layout `[digest(state_len) |
    /// pending(block_len)]`.
    ///
    /// The state region holds the intermediate SHA working variables between
    /// hardware submissions and ultimately receives the final digest. The
    /// pending region accumulates a partial block between
    /// [`hash_continue`](HsmHash::hash_continue) calls.
    buf: &'a mut DmaBuf,

    /// Number of valid bytes currently stored in the pending region of
    /// [`buf`](Self::buf).
    pending_len: u8,
}

pub(crate) trait ShaDigestContext {
    fn algo(&self) -> HsmHashAlgo;

    fn byte_count(&self) -> u32;

    fn set_byte_count(&mut self, byte_count: u32);

    fn buf(&mut self) -> &mut DmaBuf;
}

impl ShaDigestContext for HsmHashContext<'_> {
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

impl<'a> HsmHashContext<'a> {
    /// Creates a new context with zero bytes processed and an empty pending
    /// buffer.
    ///
    /// # Parameters
    ///
    /// - `algo` — hash algorithm (e.g. SHA-256, SHA-512).
    /// - `buf` — alloc-allocated state storage for intermediate state, final
    ///   digest, and pending block storage. Must be at least
    ///   [`HsmHashAlgo::hash_state_len`] bytes.
    ///
    /// # Returns
    ///
    /// A freshly initialized [`HsmHashContext`] with `byte_count` and
    /// `pending_len` both set to zero.
    pub(crate) fn new(algo: HsmHashAlgo, buf: &'a mut DmaBuf) -> Self {
        Self {
            algo,
            byte_count: 0,
            buf,
            pending_len: 0,
        }
    }

    /// Copies bytes from `data` into the pending region of [`buf`](Self::buf)
    /// until it is full or `data` is exhausted.
    ///
    /// # Parameters
    ///
    /// - `data` — source bytes to append to the pending buffer.
    ///
    /// # Returns
    ///
    /// The unconsumed tail of `data` (empty if all bytes fit).
    fn fill_pending<'d>(&mut self, data: &'d [u8]) -> &'d [u8] {
        let start = self.pending_len as usize;
        let n = (self.algo.block_len() - start).min(data.len());
        let (_, pending) = self.buf.split_at_mut(self.algo.state_len());
        pending[start..start + n].copy_from_slice(&data[..n]);
        self.pending_len += n as u8;
        &data[n..]
    }

    /// Returns `true` when the pending region of [`buf`](Self::buf) holds
    /// exactly one full block and must be flushed before more data can be
    /// buffered.
    ///
    /// # Returns
    ///
    /// `true` if `pending_len` equals the algorithm's block size.
    fn pending_full(&self) -> bool {
        self.pending_len as usize == self.algo.block_len()
    }
}

// ---------------------------------------------------------------------------
// HsmHash trait implementation
// ---------------------------------------------------------------------------

impl HsmHash for UnoHsmPal {
    type HashCtx<'a> = HsmHashContext<'a>;

    /// Computes a one-shot hash of the entire message.
    ///
    /// Delegates to [`sha_oneshot`](Self::sha_oneshot) with the hardware mode
    /// derived from `algo`.
    ///
    /// # Parameters
    ///
    /// - `io` — I/O context for the current operation.
    /// - `algo` — hash algorithm to use.
    /// - `data` — complete input message.
    /// - `digest` — output buffer (must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes).
    /// - `big_endian` — if `true`, the digest is written in big-endian (NIST
    ///   standard) byte order.  If `false`, the output is byte-swapped to
    ///   little-endian.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`HsmError`] if the message length exceeds
    /// `u32::MAX` or the hardware submission fails.
    async fn hash(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        data: &DmaBuf,
        digest: &mut DmaBuf,
        big_endian: bool,
    ) -> HsmResult<()> {
        let _ = io;
        self.sha_oneshot(algo, data, digest, !big_endian).await
    }

    /// Begins a multi-step hash computation.
    ///
    /// Allocates the combined `[state | block]` buffer from `alloc`, then
    /// returns a fresh [`HsmHashContext`].
    ///
    /// # Parameters
    ///
    /// - `io` — I/O context for the current operation.
    /// - `alloc` — scoped allocator used for the internal hash state buffer.
    /// - `algo` — hash algorithm to use.
    ///
    /// # Returns
    ///
    /// `Ok(HsmHashContext)` ready to accept data via
    /// [`hash_continue`](HsmHash::hash_continue), or
    /// [`HsmError::NotEnoughSpace`] if the alloc cannot satisfy the
    /// allocation.
    fn hash_begin<'a>(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        let buf = alloc.dma_alloc(algo.hash_state_len())?;
        Ok(HsmHashContext::new(algo, buf))
    }

    /// Feeds arbitrary-length data into a multi-step hash.
    ///
    /// Operates in three phases (see [module-level docs](self)):
    ///
    /// 1. Fills the pending buffer and flushes it if full.
    /// 2. Submits remaining full blocks directly from `data` (zero-copy).
    /// 3. Buffers any trailing sub-block bytes in `pending`.
    ///
    /// # Parameters
    ///
    /// - `io` — I/O context for the current operation.
    /// - `ctx` — mutable reference to the active [`HsmHashContext`].
    /// - `data` — input bytes to hash.  May be any length, including zero.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`HsmError`] if the cumulative message
    /// length overflows `u32` or the hardware submission fails.
    async fn hash_continue(
        &self,
        io: &impl HsmIo,
        ctx: &mut Self::HashCtx<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        let _ = io;
        self.hash_continue_bytes(ctx, data).await
    }

    /// Finalizes the multi-step hash and writes the digest to `digest`.
    ///
    /// Flushes any remaining bytes in the pending buffer with SHA auto-padding
    /// enabled. Consumes the context so it cannot be reused.
    ///
    /// # Parameters
    ///
    /// - `io` — I/O context for the current operation.
    /// - `ctx` — the [`HsmHashContext`] to finalize (consumed).
    /// - `digest` — output buffer for the final digest. Must be at least
    ///   [`HsmHashAlgo::digest_len`] bytes.
    /// - `big_endian` — if `true`, the digest is written in big-endian (NIST
    ///   standard) byte order. If `false`, the output is byte-swapped to
    ///   little-endian.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`HsmError`] if `digest` is too short or the
    /// hardware submission fails.
    async fn hash_finish(
        &self,
        io: &impl HsmIo,
        mut ctx: Self::HashCtx<'_>,
        digest: &mut DmaBuf,
        big_endian: bool,
    ) -> HsmResult<()> {
        let _ = io;
        let algo = ctx.algo;
        let digest_len = algo.digest_len();
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }

        let len = ctx.pending_len as usize;
        self.sha_digest_block(&mut ctx, None, len, true, !big_endian)
            .await?;
        digest[..digest_len].copy_from_slice(&ctx.buf[..digest_len]);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private SHA helpers
// ---------------------------------------------------------------------------

impl UnoHsmPal {
    pub(crate) async fn hash_continue_bytes(
        &self,
        ctx: &mut HsmHashContext<'_>,
        data: &[u8],
    ) -> HsmResult<()> {
        let block_len = ctx.algo.block_len();

        let remaining = if ctx.pending_len > 0 {
            let tail = ctx.fill_pending(data);
            if ctx.pending_full() {
                self.sha_flush_pending(ctx, false).await?;
            }
            tail
        } else {
            data
        };

        let full_len = remaining.len() / block_len * block_len;
        let (full_blocks, tail) = remaining.split_at(full_len);
        if !full_blocks.is_empty() {
            self.sha_submit_blocks(ctx, full_blocks).await?;
        }
        if !tail.is_empty() {
            ctx.fill_pending(tail);
        }

        Ok(())
    }

    /// Submits a one-shot SHA request with automatic padding.
    ///
    /// Used by [`hash`](HsmHash::hash) when the entire message is available
    /// up front.  No prior state is loaded; the engine starts from the FIPS
    /// initial constants.
    ///
    /// # Parameters
    ///
    /// - `mode` — SHA hardware algorithm selector.
    /// - `message` — complete input message.
    /// - `digest` — output buffer for the final hash.
    /// - `byte_swap` — if `true`, the digest is byte-swapped
    ///   (little-endian output).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or [`HsmError::InvalidArg`] if `message.len()`
    /// exceeds `u32::MAX`, or an [`HsmError`] propagated from the SHA
    /// driver.
    pub(crate) async fn sha_oneshot(
        &self,
        algo: HsmHashAlgo,
        message: &DmaBuf,
        digest: &mut DmaBuf,
        byte_swap: bool,
    ) -> HsmResult<()> {
        let byte_count = u32::try_from(message.len()).map_err(|_| HsmError::InvalidArg)?;
        let mut req = ShaRequest::new(algo.into(), message, digest).with_auto_pad(byte_count);
        if byte_swap {
            req = req.with_byte_swap();
        }
        self.sha.digest(req).await
    }

    /// Flushes the pending buffer to the SHA engine and resets `pending_len`
    /// to zero.
    ///
    /// # Parameters
    ///
    /// - `ctx` — mutable reference to the active [`HsmHashContext`].  On
    ///   return, `ctx.pending_len` is reset to `0` and `ctx.byte_count` is
    ///   advanced.
    /// - `finalize` — if `true`, SHA auto-padding is applied and the engine
    ///   writes the final digest.  If `false`, the full working state is
    ///   emitted for chaining.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`HsmError`] propagated from the SHA
    /// driver.
    async fn sha_flush_pending(
        &self,
        ctx: &mut HsmHashContext<'_>,
        finalize: bool,
    ) -> HsmResult<()> {
        let len = ctx.pending_len as usize;
        self.sha_digest_block(ctx, None, len, finalize, false)
            .await?;
        ctx.pending_len = 0;
        Ok(())
    }

    /// Submits one or more full blocks from the caller's buffer directly to
    /// hardware (zero-copy path).
    ///
    /// # Parameters
    ///
    /// - `ctx` — mutable reference to the active [`HsmHashContext`].  On
    ///   return, `ctx.byte_count` is advanced by `blocks.len()`.
    /// - `blocks` — message data whose length must be a non-zero multiple of
    ///   the algorithm's block size.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an [`HsmError`] propagated from the SHA
    /// driver.
    async fn sha_submit_blocks(
        &self,
        ctx: &mut HsmHashContext<'_>,
        blocks: &[u8],
    ) -> HsmResult<()> {
        // SAFETY: sha_submit_blocks is only called from hash_continue_bytes
        // with data that originated from hash_continue(data: &DmaBuf) or
        // hmac_continue, so `blocks` is always a sub-slice of a
        // DMA-accessible caller buffer.
        let blocks = unsafe { DmaBuf::from_raw(blocks) };
        self.sha_digest_block(ctx, Some(blocks), blocks.len(), false, false)
            .await
    }

    /// Core multi-step SHA submission shared by all intermediate and final
    /// block paths.
    ///
    /// Constructs a [`ShaRequest`] with the appropriate flags and submits it
    /// to the hardware SHA engine.  On success, advances `ctx.byte_count` by
    /// `msg_len`.
    ///
    /// # Parameters
    ///
    /// - `ctx` — mutable reference to the active [`HsmHashContext`].  On
    ///   return, `ctx.byte_count` is advanced by `msg_len`, and the digest
    ///   region of `ctx.buf` may have been overwritten with intermediate state
    ///   or the final digest.
    /// - `external_msg` — if `Some`, the message bytes to hash.  If `None`,
    ///   the first `msg_len` bytes of the pending region in `ctx.buf` are used
    ///   instead.
    /// - `msg_len` — number of message bytes to process.
    /// - `finalize` — if `true`, automatic SHA padding is applied and the
    ///   engine writes the truncated NIST digest.  If `false`, the engine
    ///   writes the full working-variable state for chaining.
    /// - `byte_swap` — if `true`, the digest output is byte-swapped
    ///   (little-endian).  Only meaningful when `finalize` is `true`;
    ///   intermediate blocks always use byte-swap for state continuity.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or [`HsmError::InvalidArg`] if `msg_len` exceeds
    /// `u32::MAX` or the cumulative byte count overflows, or an [`HsmError`]
    /// propagated from the SHA driver.
    pub(crate) async fn sha_digest_block<C>(
        &self,
        ctx: &mut C,
        external_msg: Option<&DmaBuf>,
        msg_len: usize,
        finalize: bool,
        byte_swap: bool,
    ) -> HsmResult<()>
    where
        C: ShaDigestContext,
    {
        let msg_len_u32 = u32::try_from(msg_len).map_err(|_| HsmError::InvalidArg)?;
        let algo = ctx.algo();
        let byte_count = ctx.byte_count();
        let total = byte_count
            .checked_add(msg_len_u32)
            .ok_or(HsmError::InvalidArg)?;
        let state_len = algo.state_len();
        let (digest, pending) = ctx.buf().split_at_mut(state_len);
        let message: &DmaBuf = match external_msg {
            Some(ext) => ext,
            None => &pending[..msg_len],
        };

        let mut req = ShaRequest::new(algo.into(), message, digest);
        if finalize {
            req = req.with_auto_pad(total);
            if byte_swap {
                req = req.with_byte_swap();
            }
        } else {
            req.byte_count = total;
            req = req.with_full_state().with_byte_swap();
        }
        if byte_count != 0 {
            req = req.with_load_digest();
        }
        self.sha.digest(req).await?;

        ctx.set_byte_count(total);
        Ok(())
    }
}
