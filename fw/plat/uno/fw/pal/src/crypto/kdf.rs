// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmKdf`] implementation for the Uno PAL.
//!
//! ## HMAC-based KDFs (HKDF, SP 800-108)
//!
//! [`hkdf_extract`](HsmKdf::hkdf_extract),
//! [`hkdf_expand`](HsmKdf::hkdf_expand), and
//! [`sp800_108_kdf`](HsmKdf::sp800_108_kdf) delegate to the HMAC
//! multi-step API ([`HsmHmac`]), which in turn uses the SHA hardware
//! accelerator asynchronously.
//!
//! ## Hash-based concatenation KDFs (MGF1, X9.63, SP 800-56A)
//!
//! [`mgf1`](HsmKdf::mgf1), [`x963_kdf`](HsmKdf::x963_kdf), and
//! [`sp800_56a_kdf`](HsmKdf::sp800_56a_kdf) all use
//! [`ShaDriver::with_exclusive`] to acquire the SHA engine once (async),
//! then run the hash loop synchronously via busy-polled
//! [`ShaExclusive::digest`] calls — one async boundary, N sync hashes,
//! one wake on release. The three variants share the same internal
//! concatenation-KDF hashing loop and differ only in how each variant
//! lays out and encodes its input material.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmHmac;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKdf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_sha::ShaExclusive;
use azihsm_fw_uno_drivers_sha::ShaMode;
use azihsm_fw_uno_drivers_sha::ShaRequest;

use crate::UnoHsmPal;

impl HsmKdf for UnoHsmPal {
    /// HKDF-Extract: `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// Per RFC 5869 §2.2, an empty `salt` is treated as a string of
    /// `algo.digest_len()` zero bytes.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm (selects digest/block lengths and the
    ///   underlying HMAC variant).
    /// * `salt` — HKDF salt (any length, may be empty).
    /// * `ikm` — input keying material (any length).
    /// * `prk` — destination buffer for the pseudo-random key. Must be
    ///   at least `algo.digest_len()` bytes; only the first
    ///   `algo.digest_len()` bytes are written.
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `prk` is shorter than
    ///   `algo.digest_len()`.
    /// * Any [`HsmError`] surfaced by the HMAC trait calls.
    async fn hkdf_extract(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        salt: Option<&DmaBuf>,
        ikm: &DmaBuf,
        prk: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            if prk.len() < algo.digest_len() {
                return Err(HsmError::InvalidArg);
            }

            // RFC 5869: if salt is empty, use a zero-filled salt of digest_len
            // bytes in DMA-accessible memory.
            let zero_salt;
            let salt: &DmaBuf = match salt {
                Some(salt) if !salt.is_empty() => salt,
                _ => {
                    zero_salt = scope.dma_alloc_zeroed(algo.digest_len())?;
                    &*zero_salt
                }
            };

            let hmac_buf = scope.dma_alloc(algo.hmac_state_len())?;

            // PRK = HMAC(salt, IKM)  — salt is the HMAC key, IKM is the message
            let mut ctx = self.hmac_begin_in_buf(io, algo, salt, hmac_buf).await?;
            self.hmac_continue(io, &mut ctx, ikm).await?;
            self.hmac_finish_into(io, ctx, &mut prk[..algo.digest_len()])
                .await
        })
        .await
    }

    /// HKDF-Expand: derive output keying material from a pseudo-random
    /// key.
    ///
    /// ```text
    /// T(0) = empty
    /// T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    /// OKM  = first L bytes of T(1) || T(2) || …
    /// ```
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `prk` — pseudo-random key from [`Self::hkdf_extract`].
    /// * `info` — optional context/application-specific bytes.
    /// * `output` — destination buffer for the derived key (any length
    ///   up to `255 * algo.digest_len()`).
    ///
    /// # Errors
    /// * [`HsmError::InvalidArg`] if `output.len() > 255 * digest_len`.
    /// * Any [`HsmError`] surfaced by the HMAC trait calls.
    async fn hkdf_expand(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        prk: &DmaBuf,
        info: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            let hlen = algo.digest_len();

            // RFC 5869: output length must not exceed 255 * HashLen.
            if output.len() > 255 * hlen {
                return Err(HsmError::InvalidArg);
            }

            if output.is_empty() {
                return Ok::<(), HsmError>(());
            }

            let n = output.len().div_ceil(hlen);
            let hmac_buf = scope.dma_alloc(algo.hmac_state_len())?;
            // 1-byte DMA scratch for the HKDF counter byte.
            let ctr = scope.dma_alloc(1)?;

            // T(i-1) is read back from the previous iteration's slot in `output`.
            // Iterations 1..n-1 always wrote a full hlen-sized T, so reading
            // hlen bytes back is safe.  The first iteration has no T(0).
            for i in 1..=n {
                let mut ctx = self
                    .hmac_begin_in_buf(io, algo, prk, &mut *hmac_buf)
                    .await?;

                if i > 1 {
                    let prev_start = (i - 2) * hlen;
                    self.hmac_continue(io, &mut ctx, &output[prev_start..prev_start + hlen])
                        .await?;
                }
                if let Some(info) = info.filter(|info| !info.is_empty()) {
                    self.hmac_continue(io, &mut ctx, info).await?;
                }
                ctr[0] = i as u8;
                self.hmac_continue(io, &mut ctx, ctr).await?;

                let start = (i - 1) * hlen;
                let len = hlen.min(output.len() - start);
                self.hmac_finish_into(io, ctx, &mut output[start..start + len])
                    .await?;
            }

            Ok::<(), HsmError>(())
        })
        .await
    }

    /// SP 800-108 Counter Mode KDF with HMAC-PRF.
    ///
    /// Each output block is
    /// `K(i) = HMAC(key, i || label || 0x00 || context || L)` where
    /// `i` is a 32-bit big-endian counter starting at 1 and `L` is the
    /// total output length in bits (also 32-bit big-endian).
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `key` — HMAC key bytes (any length).
    /// * `label` — application-specific label (may be empty).
    /// * `context` — application-specific context (may be empty).
    /// * `output` — destination buffer for the derived key (any length).
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the HMAC trait calls.
    async fn sp800_108_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        label: Option<&DmaBuf>,
        context: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            let hlen = algo.digest_len();

            if output.is_empty() {
                return Ok::<(), HsmError>(());
            }

            let l_bits = ((output.len() * 8) as u32).to_be_bytes();
            let hmac_buf = scope.dma_alloc(algo.hmac_state_len())?;
            // DMA scratch layout: [counter(0..4) | 0x00(4..5) | l_bits(5..9)]
            let scratch = scope.dma_alloc(9)?;
            scratch[4] = 0x00;
            scratch[5..9].copy_from_slice(&l_bits);

            for idx in 0..output.len().div_ceil(hlen) {
                let counter = ((idx + 1) as u32).to_be_bytes();
                scratch[..4].copy_from_slice(&counter);
                let mut ctx = self
                    .hmac_begin_in_buf(io, algo, key, &mut *hmac_buf)
                    .await?;

                // counter || label || 0x00 || context || L
                self.hmac_continue(io, &mut ctx, &scratch[..4]).await?;
                if let Some(label) = label.filter(|label| !label.is_empty()) {
                    self.hmac_continue(io, &mut ctx, label).await?;
                }
                self.hmac_continue(io, &mut ctx, &scratch[4..5]).await?;
                if let Some(context) = context.filter(|context| !context.is_empty()) {
                    self.hmac_continue(io, &mut ctx, context).await?;
                }
                self.hmac_continue(io, &mut ctx, &scratch[5..]).await?;

                let start = idx * hlen;
                let len = hlen.min(output.len() - start);
                self.hmac_finish_into(io, ctx, &mut output[start..start + len])
                    .await?;
            }

            Ok::<(), HsmError>(())
        })
        .await
    }

    /// MGF1 (RFC 8017 §B.2.1): `Hash(seed || counter)` with the counter
    /// starting at 0.
    ///
    /// State layout: `[hash(digest_len) | input(seed_len + 4)]`.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `seed` — MGF1 seed (any length).
    /// * `mask` — destination buffer; every byte is overwritten with
    ///   the generated mask.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if the internal scoped allocation cannot fit the
    ///   MGF1 state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn mgf1(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        seed: &DmaBuf,
        mask: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.run_concat_kdf(io, algo, ConcatKdf::Mgf1, seed, &seed[..0], mask)
            .await
    }

    /// MGF1 with the result XOR-ed into `mask` instead of overwriting
    /// it. Used by RSA-OAEP / RSA-PSS where the MGF output is combined
    /// with an existing buffer in place.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `seed` — MGF1 seed (any length).
    /// * `mask` — buffer XOR-ed in place with the generated mask.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if the internal scoped allocation cannot fit the
    ///   MGF1 state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn mgf1_xor(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        seed: &DmaBuf,
        mask: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            if mask.is_empty() {
                return Ok::<(), HsmError>(());
            }

            let state = scope.dma_alloc(algo.mgf1_state_len(seed.len()))?;

            self.sha
                .with_exclusive(|sha| ConcatKdf::Mgf1.run_xor(sha, algo, seed, mask, state))
                .await
        })
        .await
    }

    /// X9.63 KDF (SEC 1 §3.6.1): `Hash(Z || counter || SharedInfo)` with
    /// the counter starting at 1.
    ///
    /// State layout: `[hash(digest_len) | input(z_len + 4 + info_len)]`.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `z` — input keying material.
    /// * `shared_info` — application-specific info (may be empty).
    /// * `key` — destination buffer for the derived key.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if the internal scoped allocation cannot fit the
    ///   KDF state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn x963_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        z: &DmaBuf,
        shared_info: &DmaBuf,
        key: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.run_concat_kdf(io, algo, ConcatKdf::X963, z, shared_info, key)
            .await
    }

    /// SP 800-56A one-step KDF: `Hash(counter || Z || OtherInfo)` with
    /// the counter starting at 1.
    ///
    /// State layout: `[hash(digest_len) | input(4 + z_len + info_len)]`.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `z` — input keying material.
    /// * `other_info` — application-specific info (may be empty).
    /// * `key` — destination buffer for the derived key.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if the internal scoped allocation cannot fit the
    ///   KDF state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    async fn sp800_56a_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        z: &DmaBuf,
        other_info: &DmaBuf,
        key: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.run_concat_kdf(io, algo, ConcatKdf::Sp80056a, z, other_info, key)
            .await
    }
}

impl UnoHsmPal {
    /// Shared boilerplate for [`HsmKdf::mgf1`], [`HsmKdf::x963_kdf`],
    /// and [`HsmKdf::sp800_56a_kdf`].
    ///
    /// Allocates the variant-specific working buffer from an internal
    /// scoped allocator, then runs [`ConcatKdf::run`] under a single
    /// async SHA-engine acquisition.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `kdf` — input-field ordering selector.
    /// * `z` — input keying material.
    /// * `info` — application-specific info (may be empty).
    /// * `output` — destination buffer (any length).
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * [`HsmError::NotEnoughSpace`] if the internal scoped allocation
    ///   cannot fit the KDF state buffer.
    /// * Any [`HsmError`] surfaced by the SHA driver.
    #[allow(clippy::too_many_arguments)]
    async fn run_concat_kdf(
        &self,
        io: &impl HsmIo,
        algo: HsmHashAlgo,
        kdf: ConcatKdf,
        z: &DmaBuf,
        info: &DmaBuf,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.alloc_scoped_async(io, async |scope| {
            if output.is_empty() {
                return Ok::<(), HsmError>(());
            }

            let state = scope.dma_alloc(kdf.required_state_len(algo, z.len(), info.len()))?;

            self.run_concat_kdf_in_buf(algo, kdf, z, info, output, state)
                .await
        })
        .await
    }

    /// Buffer-backed concatenation-KDF helper reused by callers that already
    /// manage their own scratch space.
    async fn run_concat_kdf_in_buf(
        &self,
        algo: HsmHashAlgo,
        kdf: ConcatKdf,
        z: &DmaBuf,
        info: &DmaBuf,
        output: &mut DmaBuf,
        state: &mut DmaBuf,
    ) -> HsmResult<()> {
        let required = kdf.required_state_len(algo, z.len(), info.len());
        if state.len() < required {
            return Err(HsmError::InvalidArg);
        }
        if output.is_empty() {
            return Ok(());
        }

        let state = &mut state[..required];

        self.sha
            .with_exclusive(|sha| kdf.run(sha, algo, z, info, output, state))
            .await
    }
}

/// Hash input field ordering for the concatenation KDF family.
enum ConcatKdf {
    /// MGF1: `seed || counter` (counter starts at 0).
    Mgf1,

    /// X9.63: `Z || counter || SharedInfo` (counter starts at 1).
    X963,

    /// SP 800-56A: `counter || Z || OtherInfo` (counter starts at 1).
    Sp80056a,
}

impl ConcatKdf {
    /// Initial counter value: 0 for MGF1, 1 for X9.63 and SP 800-56A.
    ///
    /// # Returns
    /// * `0` for [`Self::Mgf1`].
    /// * `1` for [`Self::X963`] and [`Self::Sp80056a`].
    fn counter_start(&self) -> u32 {
        match self {
            ConcatKdf::Mgf1 => 0,
            ConcatKdf::X963 | ConcatKdf::Sp80056a => 1,
        }
    }

    /// Returns the byte offset of the 4-byte counter within the input buffer.
    fn counter_offset(&self, z_len: usize) -> usize {
        match self {
            ConcatKdf::Mgf1 | ConcatKdf::X963 => z_len,
            ConcatKdf::Sp80056a => 0,
        }
    }

    /// Copy the static parts (`z`, `info`) into `buf` once.
    ///
    /// The 4-byte counter slot is left for per-iteration updates by
    /// [`Self::write_counter`].
    ///
    /// # Parameters
    /// * `buf` — destination input buffer (large enough to hold `z`,
    ///   `info`, and the counter slot per the variant's layout).
    /// * `z` — keying material / seed.
    /// * `info` — optional auxiliary bytes (ignored for [`Self::Mgf1`]).
    ///
    /// # Returns
    /// * Total length in bytes of the populated input region.
    fn init_input(&self, buf: &mut DmaBuf, z: &DmaBuf, info: &DmaBuf) -> usize {
        match self {
            ConcatKdf::Mgf1 => {
                buf[..z.len()].copy_from_slice(z);
                z.len() + 4
            }
            ConcatKdf::X963 => {
                buf[..z.len()].copy_from_slice(z);
                let info_start = z.len() + 4;
                buf[info_start..info_start + info.len()].copy_from_slice(info);
                info_start + info.len()
            }
            ConcatKdf::Sp80056a => {
                buf[4..4 + z.len()].copy_from_slice(z);
                let info_start = 4 + z.len();
                buf[info_start..info_start + info.len()].copy_from_slice(info);
                info_start + info.len()
            }
        }
    }

    /// Write the big-endian counter value into its slot in `buf`.
    ///
    /// # Parameters
    /// * `buf` — input buffer initialised by [`Self::init_input`].
    /// * `z_len` — length of the `Z`/seed field (used to locate the
    ///   counter slot).
    /// * `counter` — value to write.
    fn write_counter(&self, buf: &mut DmaBuf, z_len: usize, counter: u32) {
        let off = self.counter_offset(z_len);
        buf[off..off + 4].copy_from_slice(&counter.to_be_bytes());
    }

    /// Minimum state buffer size required for this layout.
    ///
    /// # Parameters
    /// * `algo` — hash algorithm.
    /// * `z_len` — length of the `Z`/seed field.
    /// * `info_len` — length of the auxiliary `info` field (ignored
    ///   for [`Self::Mgf1`]).
    ///
    /// # Returns
    /// * Minimum `state.len()` accepted by [`Self::run`] /
    ///   [`Self::run_xor`].
    fn required_state_len(&self, algo: HsmHashAlgo, z_len: usize, info_len: usize) -> usize {
        match self {
            ConcatKdf::Mgf1 => algo.mgf1_state_len(z_len),
            ConcatKdf::X963 | ConcatKdf::Sp80056a => algo.concat_kdf_state_len(z_len, info_len),
        }
    }

    /// Run this layout's hash-and-counter loop on a held SHA engine.
    ///
    /// All three concatenation KDFs are "hash N blocks with a counter"
    /// — they differ only in the order of fields within each hash
    /// input. The static fields (`z`, `info`) are written into `state`
    /// once; only the counter slot changes per iteration.
    ///
    /// # Type parameters
    /// * `DEPTH` — SHA driver queue depth (carried through from the
    ///   acquired [`ShaExclusive`]).
    ///
    /// # Parameters
    /// * `sha` — exclusively-held SHA engine handle.
    /// * `algo` — hash algorithm.
    /// * `z` — input keying material.
    /// * `info` — auxiliary bytes (ignored for [`Self::Mgf1`]).
    /// * `output` — destination buffer (any length).
    /// * `state` — caller-owned working buffer, exactly
    ///   `digest_len + input_size` bytes; split internally into
    ///   `[hash(digest_len) | input(...)]`.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    fn run<const DEPTH: usize>(
        &self,
        sha: &ShaExclusive<'_, DEPTH>,
        algo: HsmHashAlgo,
        z: &DmaBuf,
        info: &DmaBuf,
        output: &mut DmaBuf,
        state: &mut DmaBuf,
    ) -> HsmResult<()> {
        let mode: ShaMode = algo.into();
        let hlen = algo.digest_len();
        let (hash, input) = state.split_at_mut(hlen);
        let counter_start = self.counter_start();

        // Copy z and info once; only the 4-byte counter changes per iteration.
        let input_len = self.init_input(input, z, info);

        let n = output.len().div_ceil(hlen);
        for i in 0..n {
            let counter = counter_start + i as u32;
            self.write_counter(input, z.len(), counter);

            let start = i * hlen;
            let len = hlen.min(output.len() - start);
            if len == hlen {
                // Full chunk: SHA writes directly to output — zero copy.
                sha.digest(
                    ShaRequest::new(mode, &input[..input_len], &mut output[start..start + len])
                        .with_auto_pad(input_len as u32),
                )?;
            } else {
                // Truncated last chunk: SHA writes to scratch, copy prefix.
                sha.digest(
                    ShaRequest::new(mode, &input[..input_len], hash)
                        .with_auto_pad(input_len as u32),
                )?;
                output[start..start + len].copy_from_slice(&hash[..len]);
            }
        }

        Ok(())
    }

    /// Like [`Self::run`] but XORs each hash output into `mask`
    /// instead of overwriting. Only valid for [`Self::Mgf1`] (no info
    /// field).
    ///
    /// # Type parameters
    /// * `DEPTH` — SHA driver queue depth.
    ///
    /// # Parameters
    /// * `sha` — exclusively-held SHA engine handle.
    /// * `algo` — hash algorithm.
    /// * `seed` — MGF1 seed.
    /// * `mask` — buffer XOR-ed in place with the generated mask.
    /// * `state` — caller-owned working buffer of exactly
    ///   `digest_len + seed_len + 4` bytes.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    ///
    /// # Errors
    /// * Any [`HsmError`] surfaced by the SHA driver.
    fn run_xor<const DEPTH: usize>(
        &self,
        sha: &ShaExclusive<'_, DEPTH>,
        algo: HsmHashAlgo,
        seed: &DmaBuf,
        mask: &mut DmaBuf,
        state: &mut DmaBuf,
    ) -> HsmResult<()> {
        let mode: ShaMode = algo.into();
        let hlen = algo.digest_len();
        let (hash, input) = state.split_at_mut(hlen);

        let input_len = self.init_input(input, seed, &seed[..0]);

        let n = mask.len().div_ceil(hlen);
        for i in 0..n {
            let counter = i as u32;
            self.write_counter(input, seed.len(), counter);

            sha.digest(
                ShaRequest::new(mode, &input[..input_len], hash).with_auto_pad(input_len as u32),
            )?;

            let start = i * hlen;
            let len = hlen.min(mask.len() - start);
            let chunk = &mut mask[start..start + len];

            for (m, h) in chunk.iter_mut().zip(hash.iter()) {
                *m ^= *h;
            }
        }

        Ok(())
    }
}
