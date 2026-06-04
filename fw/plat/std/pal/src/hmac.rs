// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdHmac`](crate::drivers::hmac::StdHmac)
//! driver. One-shot operations are backed by OpenSSL. Multi-step HMAC
//! is implemented by buffering all `hmac_continue` data into the
//! context and running a single one-shot `sign`/`verify` at finalisation
//! time — std PAL has no streaming hardware to drive, so this matches
//! the trait contract without paying for incremental OpenSSL state.

use std::vec::Vec;

use azihsm_crypto::HashAlgo;

use super::*;

fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
    match algo {
        HsmHashAlgo::Sha1 => HashAlgo::sha1(),
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
    }
}

/// Std-PAL streaming HMAC context.
///
/// Buffers the key and all `hmac_continue` data, then runs a single
/// one-shot HMAC via [`StdHmac`](crate::drivers::hmac::StdHmac) at
/// finalisation. Lifetime `'a` is unused — std env can own the
/// buffers — but is retained to match the [`HsmHmac::HmacCtx`]
/// associated-type signature.
pub struct StdHmacCtx<'a> {
    algo: HsmHashAlgo,
    key: Vec<u8>,
    data: Vec<u8>,
    _marker: core::marker::PhantomData<&'a ()>,
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
        Ok(StdHmacCtx {
            algo,
            key: key.to_vec(),
            data: Vec::new(),
            _marker: core::marker::PhantomData,
        })
    }

    async fn hmac_continue(
        &self,
        _io: &impl HsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        data: &DmaBuf,
    ) -> HsmResult<()> {
        ctx.data.extend_from_slice(data);
        Ok(())
    }

    async fn hmac_finish(
        &self,
        _io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.hmac
            .sign(to_hash_algo(ctx.algo), &ctx.key, &ctx.data, tag)
            .await
    }

    async fn hmac_finish_into(
        &self,
        _io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        dest: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.hmac
            .sign(to_hash_algo(ctx.algo), &ctx.key, &ctx.data, dest)
            .await
    }

    async fn hmac_finish_verify(
        &self,
        _io: &impl HsmIo,
        ctx: Self::HmacCtx<'_>,
        tag: &DmaBuf,
    ) -> HsmResult<bool> {
        self.hmac
            .verify(to_hash_algo(ctx.algo), &ctx.key, &ctx.data, tag)
            .await
    }
}
