// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdHmac`](crate::drivers::hmac::StdHmac)
//! driver. One-shot operations are backed by OpenSSL. Multi-step HMAC APIs
//! are not currently used by the standard PAL and are left as `todo!()`.

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

#[allow(dead_code)]
pub struct StdHmacCtx<'a> {
    algo: HsmHashAlgo,
    state: &'a mut [u8],
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
        _algo: HsmHashAlgo,
        _key: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn hmac_continue(
        &self,
        _io: &impl HsmIo,
        _ctx: &mut Self::HmacCtx<'_>,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn hmac_finish(
        &self,
        _io: &impl HsmIo,
        _ctx: Self::HmacCtx<'_>,
        _tag: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn hmac_finish_into(
        &self,
        _io: &impl HsmIo,
        _ctx: Self::HmacCtx<'_>,
        _dest: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn hmac_finish_verify(
        &self,
        _io: &impl HsmIo,
        _ctx: Self::HmacCtx<'_>,
        _tag: &DmaBuf,
    ) -> HsmResult<bool> {
        todo!()
    }
}
