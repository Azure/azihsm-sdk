// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdHmac`](crate::drivers::hmac::StdHmac)
//! driver. One-shot operations are backed by [`azihsm_crypto`]'s
//! platform-abstracted HMAC (OpenSSL on Linux, CNG on Windows).
//!
//! Multi-step HMAC is implemented as a true streaming pipeline: the
//! caller-provided key bytes are imported into an [`HmacKey`] handle
//! at [`hmac_begin`] time and the resulting streaming context
//! ([`HmacAlgoSignContext`]) is held inside [`StdHmacCtx`].  Each
//! [`hmac_continue`] call feeds its `DmaBuf` slice straight into the
//! HMAC state machine via [`SignStreamingOpContext::update`]; the
//! std PAL never accumulates message bytes in a heap buffer.  This
//! preserves the "must not panic on any input" trust-boundary
//! contract by removing the unbounded `Vec::extend_from_slice` path
//! that could OOM-abort on attacker-sized streams.
//!
//! ## Sensitive-byte handling
//!
//! - The caller's [`DmaBuf`] key bytes are not copied into a PAL-
//!   side scratch buffer.  [`HmacKey::from_bytes`] reads the slice
//!   and copies into its own backend-owned storage; the caller's
//!   `DmaBuf` remains under the IO scope's zero-on-free allocator
//!   contract and is wiped on release.
//! - The streaming HMAC state owned by [`HmacAlgoSignContext`] is a
//!   thin wrapper around an OpenSSL `EVP_MD_CTX` (Linux) or a CNG
//!   `BCRYPT_HASH_HANDLE` (Windows); both backends zeroize their
//!   internal HMAC key material on free.  No raw key bytes are
//!   retained inside [`StdHmacCtx`] itself.
//! - The driver-level one-shot sign / verify paths still own a
//!   short-lived `Vec` for cross-thread submission to the worker
//!   pool; that buffer is bounded by the single-call DmaBuf size and
//!   freed before the next operation can be dispatched.

use core::marker::PhantomData;

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HmacAlgo;
use azihsm_crypto::HmacAlgoSignContext;
use azihsm_crypto::HmacKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::SignStreamingOpContext;
use azihsm_crypto::Signer;

use super::*;

/// Largest HMAC tag we may need to materialise locally for verify
/// (== SHA-512 digest length).
const MAX_HMAC_TAG_LEN: usize = 64;

fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
    match algo {
        HsmHashAlgo::Sha1 => HashAlgo::sha1(),
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
    }
}

/// Constant-time byte slice comparison.
///
/// Returns `true` iff `a` and `b` have the same length and contents.
/// The execution path depends only on `a.len()`, not on the byte
/// values, to keep verify decisions immune to timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Std-PAL streaming HMAC context.
///
/// Holds the live [`HmacAlgoSignContext`] for an in-progress
/// multi-step HMAC.  No raw key or message bytes are buffered: each
/// [`hmac_continue`] call feeds its slice directly into the HMAC
/// state machine, and the key material is owned by the platform
/// crypto backend (which clears it on free via the context's own
/// `Drop` impl: OpenSSL `EVP_MD_CTX_free` / CNG `BCryptDestroyHash`).
///
/// The `'a` lifetime parameter is required to match the
/// [`HsmHmac::HmacCtx`] associated type but is unused here — the
/// streaming context is self-contained (`'static`) on both backends.
pub struct StdHmacCtx<'a> {
    algo: HsmHashAlgo,
    sign_ctx: HmacAlgoSignContext<'static>,
    _marker: PhantomData<&'a ()>,
}

impl HsmHmac for StdHsmPal {
    type HmacCtx<'a>
        = StdHmacCtx<'a>
    where
        Self: 'a;

    async fn hmac_gen_key(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        key: &mut [u8],
    ) -> HsmResult<()> {
        self.hmac.gen_key(key).await
    }

    async fn hmac_sign(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.hmac.sign(to_hash_algo(algo), key, data, tag).await
    }

    async fn hmac_verify(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        data: &DmaBuf,
        tag: &DmaBuf,
    ) -> HsmResult<bool> {
        self.hmac.verify(to_hash_algo(algo), key, data, tag).await
    }

    async fn hmac_begin<'a>(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a,
    {
        // `HmacKey::from_bytes` copies the bytes into its own
        // backend-owned storage; the caller's `DmaBuf` keeps owning
        // the original buffer and is wiped on release by the IO
        // scope's zero-on-free allocator contract.
        let hmac_key = HmacKey::from_bytes(key).map_err(|_| HsmError::HmacError)?;

        let hmac_algo = HmacAlgo::new(to_hash_algo(algo));
        let sign_ctx: HmacAlgoSignContext<'static> =
            Signer::sign_init::<'static, HmacAlgo>(hmac_algo, hmac_key)
                .map_err(|_| HsmError::HmacError)?;

        Ok(StdHmacCtx {
            algo,
            sign_ctx,
            _marker: PhantomData,
        })
    }

    async fn hmac_continue(
        &self,
        _io: &impl HsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        ctx.sign_ctx.update(data).map_err(|_| HsmError::HmacError)
    }

    async fn hmac_finish(
        &self,
        _io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        finish_into_tag(&mut ctx, tag)
    }

    async fn hmac_finish_into(
        &self,
        _io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        dest: &mut DmaBuf,
    ) -> HsmResult<()> {
        finish_into_tag(&mut ctx, dest)
    }

    async fn hmac_finish_verify(
        &self,
        _io: &impl HsmIo,
        mut ctx: Self::HmacCtx<'_>,
        tag: &DmaBuf,
    ) -> HsmResult<bool> {
        let mut computed = [0u8; MAX_HMAC_TAG_LEN];
        let digest_len = to_hash_algo(ctx.algo).size();
        if digest_len > computed.len() {
            return Err(HsmError::HmacError);
        }
        ctx.sign_ctx
            .finish(Some(&mut computed[..digest_len]))
            .map_err(|_| HsmError::HmacError)?;

        // Constant-time compare against the caller-supplied tag.  We
        // accept any tag length the caller submitted; the comparator
        // returns false immediately on a length mismatch, which is
        // safe to leak (the tag length is not secret).
        let ok = constant_time_eq(&computed[..digest_len], tag);
        // Wipe the on-stack computed tag now that the decision is made.
        computed.fill(0);
        Ok(ok)
    }
}

/// Shared helper for the two non-verify finishers.  Writes the HMAC
/// tag into `out[..digest_len]`.
fn finish_into_tag(ctx: &mut StdHmacCtx<'_>, out: &mut DmaBuf) -> HsmResult<()> {
    let digest_len = to_hash_algo(ctx.algo).size();
    if out.len() < digest_len {
        return Err(HsmError::HmacError);
    }
    ctx.sign_ctx
        .finish(Some(&mut out[..digest_len]))
        .map_err(|_| HsmError::HmacError)?;
    Ok(())
}
