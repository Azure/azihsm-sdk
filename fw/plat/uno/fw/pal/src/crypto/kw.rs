// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES Key Wrap (RFC 3394) and Key Wrap with Padding (RFC 5649) for the
//! Uno PAL.
//!
//! ## Algorithm overview
//!
//! Both KW and KWP iterate the same `(A, R[1..n])` register pair through
//! six j-rounds. Each j-round performs `n` AES-ECB operations: encrypt
//! for wrap, decrypt for unwrap.
//!
//! | Quantity | Wrap (RFC 3394 §2.2.1) | Unwrap (RFC 3394 §2.2.2) |
//! |----------|------------------------|--------------------------|
//! | `B`      | `AES-ECB(K, A ‖ R[i])` | —                        |
//! | `A'`     | `MSB(64, B) ⊕ t`       | `MSB(64, B)`             |
//! | `R'[i]`  | `LSB(64, B)`           | `LSB(64, B)`             |
//! | `t`      | `n*j + i`              | `n*j + i`                |
//!
//! ## Async batching strategy
//!
//! The PAL acquires the AES core via [`AesDriver::with_exclusive`] for
//! batches of up to [`BATCH_SIZE`] semiblocks at a time, runs the
//! batch's ECB operations as fast as the hardware can poll, then
//! releases the lock and yields. This keeps long KWP wraps from
//! starving other tasks on the cooperative executor.
//!
//! ## KWP delegation
//!
//! KWP (RFC 5649) is implemented in terms of KW for `r ≥ 2`
//! semiblocks, with a single AES-ECB block as the special case for
//! `r = 1`. The Alternative Initial Value (AIV) is built from the
//! constant prefix [`AIV_PREFIX`] and the message length indicator.
//!
//! [`AesDriver::with_exclusive`]:
//!     azihsm_fw_uno_drivers_aes::AesDriver::with_exclusive

use core::ops::RangeInclusive;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_aes::AesExclusive;
use azihsm_fw_uno_drivers_aes::AesMode;
use azihsm_fw_uno_drivers_aes::AesOp;
use azihsm_fw_uno_drivers_aes::AesRequest;

use crate::UnoHsmPal;

// =============================================================================
// Constants
// =============================================================================

/// Semiblock size in bytes (64 bits — half of an AES block).
const SEMI: usize = 8;

/// AES block size in bytes (128 bits — two semiblocks).
const BLOCK: usize = 16;

/// Default IV for AES-KW (RFC 3394 §2.2.3.1): eight 0xA6 bytes.
const DEFAULT_IV: [u8; SEMI] = [0xA6; SEMI];

/// AIV constant prefix for AES-KWP (RFC 5649 §3): four bytes
/// `0xA6 0x59 0x59 0xA6`. Followed by a 32-bit big-endian message
/// length indicator.
const AIV_PREFIX: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

/// Maximum input data size accepted by [`UnoHsmPal::kw_wrap_impl`]
/// and [`UnoHsmPal::kwp_wrap_impl`] (3 KiB, sized for HSM session
/// state buffers).
const MAX_DATA: usize = 3072;

/// Maximum number of AES-ECB blocks processed per `with_exclusive`
/// session before yielding. Tunes KW throughput against task-scheduler
/// fairness.
const BATCH_SIZE: u64 = 64;

// =============================================================================
// Per-batch state
// =============================================================================

/// Mutable state shared across the wrap j-loop: the running register
/// `[A | R[1..n]]` plus the semiblock count.
struct WrapState<'o> {
    /// `A` lives at bytes `0..SEMI`, `R[i]` at `i*SEMI..(i+1)*SEMI`.
    output: &'o mut DmaBuf,
    /// Number of `R` semiblocks (always `output.len() / SEMI - 1`).
    n: u64,
}

/// Mutable state shared across the unwrap j-loop: a separate `A`
/// register, the running `R[1..n]` buffer, and the semiblock count.
struct UnwrapState<'a, 'o> {
    /// 64-bit register that holds the candidate AIV at the end.
    a: &'a mut [u8; SEMI],
    /// `R[i]` at bytes `(i-1)*SEMI..i*SEMI` (1-based; total `n*SEMI`).
    output: &'o mut DmaBuf,
    /// Number of `R` semiblocks (always `output.len() / SEMI`).
    n: u64,
}

// =============================================================================
// AES-KW core (RFC 3394) — per-batch primitives
// =============================================================================

/// RFC 3394 §2.2.1 wrap — run a contiguous batch of ECB encrypts within
/// one j-round.
///
/// Processes semiblock indices `i_range` (1-based, inclusive) for
/// j-round `j`. Updates `state.output[..SEMI]` (`A`) and
/// `state.output[i*SEMI..(i+1)*SEMI]` (`R[i]`) for every `i` in range.
///
/// # Type parameters
/// * `DEPTH` — AES driver queue depth from the held [`AesExclusive`].
///
/// # Parameters
/// * `ecb` — exclusively-held AES engine handle.
/// * `key` — AES key (16, 24, or 32 bytes).
/// * `state` — mutable `[A | R[1..n]]` register.
/// * `j` — j-round index (`0..6`).
/// * `i_range` — 1-based inclusive batch range within `1..=state.n`.
///
/// # Returns
/// * `Ok(())` on success.
///
/// # Errors
/// * Any [`HsmError`] surfaced by the AES driver.
fn kw_wrap_batch<const DEPTH: usize>(
    ecb: &AesExclusive<'_, DEPTH>,
    key: &DmaBuf,
    state: &mut WrapState<'_>,
    j: u64,
    i_range: RangeInclusive<u64>,
    pt: &mut DmaBuf,
    ct: &mut DmaBuf,
) -> HsmResult<()> {
    for i in i_range {
        let idx = i as usize * SEMI;

        // B = AES-ECB(K, A ‖ R[i])
        pt[..SEMI].copy_from_slice(&state.output[..SEMI]);
        pt[SEMI..].copy_from_slice(&state.output[idx..idx + SEMI]);
        ecb.encrypt_decrypt(&AesRequest {
            mode: AesMode::Ecb,
            op: AesOp::Encrypt,
            key,
            iv: None,
            update_iv: false,
            message: pt,
            result: ct,
        })?;

        // A = MSB(64, B) ⊕ t   where t = n*j + i
        let t_bytes = (state.n * j + i).to_be_bytes();
        state.output[..SEMI].copy_from_slice(&ct[..SEMI]);
        for (a, t) in state.output[..SEMI].iter_mut().zip(&t_bytes) {
            *a ^= *t;
        }

        // R[i] = LSB(64, B)
        state.output[idx..idx + SEMI].copy_from_slice(&ct[SEMI..BLOCK]);
    }
    Ok(())
}

/// RFC 3394 §2.2.2 unwrap — run a contiguous batch of ECB decrypts
/// within one j-round.
///
/// Processes semiblock indices `i_range` in reverse (1-based,
/// inclusive) for j-round `j`. Updates `state.a` and
/// `state.output[(i-1)*SEMI..i*SEMI]` (`R[i]`) for every `i` in range.
///
/// # Type parameters
/// * `DEPTH` — AES driver queue depth from the held [`AesExclusive`].
///
/// # Parameters
/// * `ecb` — exclusively-held AES engine handle.
/// * `key` — AES key (16, 24, or 32 bytes).
/// * `state` — mutable `(A, R[1..n])` registers.
/// * `j` — j-round index (`0..6`).
/// * `i_range` — 1-based inclusive batch range; iterated in reverse.
///
/// # Returns
/// * `Ok(())` on success.
///
/// # Errors
/// * Any [`HsmError`] surfaced by the AES driver.
fn kw_unwrap_batch<const DEPTH: usize>(
    ecb: &AesExclusive<'_, DEPTH>,
    key: &DmaBuf,
    state: &mut UnwrapState<'_, '_>,
    j: u64,
    i_range: RangeInclusive<u64>,
    ct: &mut DmaBuf,
    pt: &mut DmaBuf,
) -> HsmResult<()> {
    for i in i_range.rev() {
        let idx = (i as usize - 1) * SEMI;

        // A = A ⊕ t   where t = n*j + i
        let t_bytes = (state.n * j + i).to_be_bytes();
        for (a, t) in state.a.iter_mut().zip(&t_bytes) {
            *a ^= *t;
        }

        // B = AES-ECB-1(K, A ‖ R[i])
        ct[..SEMI].copy_from_slice(state.a);
        ct[SEMI..].copy_from_slice(&state.output[idx..idx + SEMI]);
        ecb.encrypt_decrypt(&AesRequest {
            mode: AesMode::Ecb,
            op: AesOp::Decrypt,
            key,
            iv: None,
            update_iv: false,
            message: ct,
            result: pt,
        })?;

        // A = MSB(64, B);  R[i] = LSB(64, B)
        state.a.copy_from_slice(&pt[..SEMI]);
        state.output[idx..idx + SEMI].copy_from_slice(&pt[SEMI..BLOCK]);
    }
    Ok(())
}

/// AES-ECB encrypt/decrypt one 16-byte block in place.
///
/// Used for the KWP `r = 1` semiblock special case where the entire
/// `(AIV, padded_plaintext)` pair fits in a single AES block.
///
/// # Type parameters
/// * `DEPTH` — AES driver queue depth from the held [`AesExclusive`].
///
/// # Parameters
/// * `ecb` — exclusively-held AES engine handle.
/// * `key` — AES key (16, 24, or 32 bytes).
/// * `op` — [`AesOp::Encrypt`] for KWP wrap, [`AesOp::Decrypt`] for
///   KWP unwrap.
/// * `block` — 16-byte buffer transformed in place.
///
/// # Returns
/// * `Ok(())` on success. `block` now contains the transformed bytes.
///
/// # Errors
/// * Any [`HsmError`] surfaced by the AES driver.
fn ecb_block_in_place<const DEPTH: usize>(
    ecb: &AesExclusive<'_, DEPTH>,
    key: &DmaBuf,
    op: AesOp,
    block: &mut DmaBuf,
    out: &mut DmaBuf,
) -> HsmResult<()> {
    ecb.encrypt_decrypt(&AesRequest {
        mode: AesMode::Ecb,
        op,
        key,
        iv: None,
        update_iv: false,
        message: block,
        result: out,
    })?;
    block[..BLOCK].copy_from_slice(&out[..BLOCK]);
    Ok(())
}

/// Verify the Alternative Initial Value (AIV) of a KWP unwrap and
/// return the message length indicator (MLI).
///
/// Per RFC 5649 §3 the AIV must:
///
/// 1. Start with the constant prefix [`AIV_PREFIX`].
/// 2. Encode an MLI in the inclusive range `(8*(n-1), 8*n]`.
/// 3. Be followed by zero-valued padding bytes only.
///
/// # Parameters
/// * `aiv` — first 8 bytes of the unwrapped buffer (`[A6 59 59 A6 |
///   MLI_be32]`).
/// * `padded` — the unwrapped plaintext including any zero padding
///   (length is a multiple of [`SEMI`]).
///
/// # Returns
/// * `Ok(mli)` — the message length indicator in bytes.
///
/// # Errors
/// * [`HsmError::AesUnwrapFailed`] if any of the three checks above
///   fail.
fn verify_aiv(aiv: &[u8], padded: &[u8]) -> HsmResult<usize> {
    if aiv[..4] != AIV_PREFIX {
        return Err(HsmError::AesUnwrapFailed);
    }

    let mli = u32::from_be_bytes(aiv[4..8].try_into().unwrap()) as usize;
    let n = padded.len() / SEMI;

    if n == 0 || mli > SEMI * n || mli <= SEMI * (n - 1) {
        return Err(HsmError::AesUnwrapFailed);
    }

    if padded[mli..].iter().any(|&b| b != 0) {
        return Err(HsmError::AesUnwrapFailed);
    }

    Ok(mli)
}

// =============================================================================
// AES-KW/KWP methods — called from the HsmAes impl in aes.rs
// =============================================================================

impl UnoHsmPal {
    /// Run the six wrap j-rounds, chunking each j-round into batches
    /// of up to [`BATCH_SIZE`] semiblocks per `with_exclusive`
    /// acquisition.
    ///
    /// Caller must initialise `output` to `[A | R[1..n]]` before
    /// calling. On return, `output` holds the wrapped ciphertext.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `state` — pre-initialised wrap state.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn run_kw_wrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        mut state: WrapState<'_>,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            let pt_buf = scope.dma_alloc(BLOCK)?;
            let ct_buf = scope.dma_alloc(BLOCK)?;
            for j in 0..6u64 {
                let mut i = 1u64;
                while i <= state.n {
                    let i_end = (i + BATCH_SIZE - 1).min(state.n);
                    self.aes
                        .with_exclusive(|ecb| {
                            kw_wrap_batch(
                                ecb,
                                key,
                                &mut state,
                                j,
                                i..=i_end,
                                &mut pt_buf[..],
                                &mut ct_buf[..],
                            )
                        })
                        .await?;
                    i = i_end + 1;
                }
            }
            Ok::<(), HsmError>(())
        })
        .await
    }

    /// Run the six unwrap j-rounds (in reverse j order), chunking
    /// each j-round into reverse batches of up to [`BATCH_SIZE`]
    /// semiblocks per `with_exclusive` acquisition.
    ///
    /// Caller must initialise `state.a` and `state.output` to the
    /// first semiblock and the remaining `R[1..n]` semiblocks of the
    /// ciphertext before calling. On return, `state.a` holds the
    /// candidate AIV and `state.output` holds the (possibly padded)
    /// plaintext.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `state` — pre-initialised unwrap state.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the AES driver.
    async fn run_kw_unwrap(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        mut state: UnwrapState<'_, '_>,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            let ct_buf = scope.dma_alloc(BLOCK)?;
            let pt_buf = scope.dma_alloc(BLOCK)?;
            for j in (0..6u64).rev() {
                let mut i = state.n;
                while i >= 1 {
                    let i_start = if i > BATCH_SIZE {
                        i - BATCH_SIZE + 1
                    } else {
                        1
                    };
                    self.aes
                        .with_exclusive(|ecb| {
                            kw_unwrap_batch(
                                ecb,
                                key,
                                &mut state,
                                j,
                                i_start..=i,
                                &mut ct_buf[..],
                                &mut pt_buf[..],
                            )
                        })
                        .await?;
                    if i_start == 1 {
                        break;
                    }
                    i = i_start - 1;
                }
            }
            Ok::<(), HsmError>(())
        })
        .await
    }

    /// AES-KW wrap (RFC 3394 §2.2.1).
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — plaintext to wrap. Must be at least 16 bytes, a
    ///   whole multiple of [`SEMI`], and at most [`MAX_DATA`] bytes.
    /// * `output` — destination buffer for the ciphertext. Must be at
    ///   least `input.len() + SEMI` bytes; the wrap appends an extra
    ///   8-byte authenticated value at the front.
    ///
    /// # Returns
    /// * `Ok(())` on success. `output[..input.len() + SEMI]` contains
    ///   the wrapped key.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `input` or `output` violates the
    ///   length constraints above.
    /// * Any [`HsmError`] surfaced by the AES driver.
    pub(super) async fn kw_wrap_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        let m = input.len();
        if m < 16 || !m.is_multiple_of(SEMI) || m > MAX_DATA {
            return Err(HsmError::InvalidArg);
        }
        let out_len = m + SEMI;
        if output.len() < out_len {
            return Err(HsmError::InvalidArg);
        }

        // Initialise: A = IV, R[1..n] = P[1..n]
        output[..SEMI].copy_from_slice(&DEFAULT_IV);
        output[SEMI..out_len].copy_from_slice(input);

        let n = (m / SEMI) as u64;
        self.run_kw_wrap(
            io,
            key,
            WrapState {
                output: &mut output[..out_len],
                n,
            },
        )
        .await
    }

    /// AES-KW unwrap (RFC 3394 §2.2.2).
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — ciphertext to unwrap. Must be at least 24 bytes, a
    ///   whole multiple of [`SEMI`], and at most `MAX_DATA + SEMI`
    ///   bytes.
    /// * `output` — destination buffer for the plaintext. Must be at
    ///   least `input.len() - SEMI` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success. `output[..input.len() - SEMI]` contains
    ///   the unwrapped key.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `input` or `output` violates the
    ///   length constraints above.
    /// * [`HsmError::AesUnwrapFailed`] if the recovered IV does not
    ///   match [`DEFAULT_IV`] (authentication failure).
    /// * Any [`HsmError`] surfaced by the AES driver.
    pub(super) async fn kw_unwrap_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        let c_len = input.len();
        if c_len < 24 || !c_len.is_multiple_of(SEMI) || c_len > MAX_DATA + SEMI {
            return Err(HsmError::InvalidArg);
        }
        let p_len = c_len - SEMI;
        if output.len() < p_len {
            return Err(HsmError::InvalidArg);
        }

        // Initialise: A = C[0], R[1..n] = C[1..n+1]
        let mut a = [0u8; SEMI];
        a.copy_from_slice(&input[..SEMI]);
        output[..p_len].copy_from_slice(&input[SEMI..]);

        let n = (p_len / SEMI) as u64;
        self.run_kw_unwrap(
            io,
            key,
            UnwrapState {
                a: &mut a,
                output: &mut output[..p_len],
                n,
            },
        )
        .await?;

        if a != DEFAULT_IV {
            return Err(HsmError::AesUnwrapFailed);
        }
        Ok(())
    }

    /// AES-KWP wrap (RFC 5649 §4.1).
    ///
    /// Pads `input` to a multiple of [`SEMI`] with zeroes, prefixes
    /// the AIV (`AIV_PREFIX ‖ MLI_be32`), and either runs a single
    /// AES-ECB encrypt (1-semiblock special case) or KW-wraps the
    /// padded data.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — plaintext to wrap. Must be in `1..=MAX_DATA` bytes.
    /// * `output` — destination buffer. Must be at least
    ///   `next_multiple_of(input.len(), SEMI) + SEMI` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `input` is empty, exceeds
    ///   [`MAX_DATA`], or `output` is too small.
    /// * Any [`HsmError`] surfaced by the AES driver.
    pub(super) async fn kwp_wrap_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        let m = input.len();
        if m == 0 || m > MAX_DATA {
            return Err(HsmError::InvalidArg);
        }

        let r = m.next_multiple_of(SEMI);
        let out_len = r + SEMI;
        if output.len() < out_len {
            return Err(HsmError::InvalidArg);
        }

        // Build AIV: [AIV_PREFIX | MLI_be32]
        let mut aiv = [0u8; SEMI];
        aiv[..4].copy_from_slice(&AIV_PREFIX);
        aiv[4..].copy_from_slice(&(m as u32).to_be_bytes());

        if r == SEMI {
            // 1-semiblock special case: a single AES-ECB encrypt.
            return self
                .alloc_scoped_async(io, async |scope| {
                    let block = scope.dma_alloc_zeroed(BLOCK)?;
                    let out = scope.dma_alloc(BLOCK)?;
                    block[..SEMI].copy_from_slice(&aiv);
                    block[SEMI..SEMI + m].copy_from_slice(input);

                    self.aes
                        .with_exclusive(|ecb| {
                            ecb_block_in_place(
                                ecb,
                                key,
                                AesOp::Encrypt,
                                &mut block[..],
                                &mut out[..],
                            )
                        })
                        .await?;

                    output[..BLOCK].copy_from_slice(&block[..BLOCK]);
                    Ok::<(), HsmError>(())
                })
                .await;
        }

        // r ≥ 2 semiblocks: zero-pad input, prefix AIV, KW-wrap.
        output[..SEMI].copy_from_slice(&aiv);
        output[SEMI..SEMI + m].copy_from_slice(input);
        output[SEMI + m..out_len].fill(0);

        let n = (r / SEMI) as u64;
        self.run_kw_wrap(
            io,
            key,
            WrapState {
                output: &mut output[..out_len],
                n,
            },
        )
        .await
    }

    /// AES-KWP unwrap (RFC 5649 §4.2).
    ///
    /// Either runs a single AES-ECB decrypt (1-block special case) or
    /// KW-unwraps the ciphertext, then verifies the AIV via
    /// [`verify_aiv`] and reports the recovered message length.
    ///
    /// # Parameters
    /// * `key` — AES key (16, 24, or 32 bytes).
    /// * `input` — ciphertext to unwrap. Must be at least [`BLOCK`]
    ///   bytes, a whole multiple of [`SEMI`], and at most
    ///   `MAX_DATA + SEMI` bytes.
    /// * `output` — destination buffer for the unwrapped plaintext.
    ///   Must be at least `mli` bytes (the special case requires at
    ///   least `mli` bytes; the multi-block case requires at least
    ///   `input.len() - SEMI` bytes).
    ///
    /// # Returns
    /// * `Ok(mli)` — the recovered message length.
    ///   `output[..mli]` contains the unwrapped plaintext.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] for length-constraint violations.
    /// * [`HsmError::AesUnwrapFailed`] if the AIV does not validate.
    /// * Any [`HsmError`] surfaced by the AES driver.
    pub(super) async fn kwp_unwrap_impl(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        input: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<usize> {
        let c_len = input.len();
        if c_len < BLOCK || !c_len.is_multiple_of(SEMI) || c_len > MAX_DATA + SEMI {
            return Err(HsmError::InvalidArg);
        }

        if c_len == BLOCK {
            // 1-block special case: single AES-ECB decrypt + AIV check.
            return self
                .alloc_scoped_async(io, async |scope| {
                    let block = scope.dma_alloc(BLOCK)?;
                    let out = scope.dma_alloc(BLOCK)?;
                    block[..BLOCK].copy_from_slice(input);

                    self.aes
                        .with_exclusive(|ecb| {
                            ecb_block_in_place(
                                ecb,
                                key,
                                AesOp::Decrypt,
                                &mut block[..],
                                &mut out[..],
                            )
                        })
                        .await?;

                    let mli = verify_aiv(&block[..SEMI], &block[SEMI..BLOCK])?;
                    if output.len() < mli {
                        return Err(HsmError::InvalidArg);
                    }
                    output[..mli].copy_from_slice(&block[SEMI..SEMI + mli]);
                    Ok::<usize, HsmError>(mli)
                })
                .await;
        }

        let p_len = c_len - SEMI;
        if output.len() < p_len {
            return Err(HsmError::InvalidArg);
        }

        // Initialise: A = C[0], R[1..n] = C[1..n+1]
        let mut a = [0u8; SEMI];
        a.copy_from_slice(&input[..SEMI]);
        output[..p_len].copy_from_slice(&input[SEMI..]);

        let n = (p_len / SEMI) as u64;
        self.run_kw_unwrap(
            io,
            key,
            UnwrapState {
                a: &mut a,
                output: &mut output[..p_len],
                n,
            },
        )
        .await?;

        verify_aiv(&a, &output[..p_len])
    }
}
