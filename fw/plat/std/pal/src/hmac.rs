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

impl HsmHmac for StdHsmPal {
    type HmacCtx<'a>
        = HsmHashState<'a>
    where
        Self: 'a;

    async fn hmac_gen_key(&self, _algo: HsmHashAlgo, key: &mut [u8]) -> HsmResult<()> {
        self.hmac.gen_key(key).await
    }

    async fn hmac_sign<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        data: &[u8],
        tag: &mut [u8],
        _state: HsmHashState<'a>,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        self.hmac.sign(to_hash_algo(algo), key, data, tag).await
    }

    async fn hmac_verify<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        data: &[u8],
        tag: &[u8],
        _state: HsmHashState<'a>,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        self.hmac.verify(to_hash_algo(algo), key, data, tag).await
    }

    async fn hmac_begin<'a>(
        &self,
        _algo: HsmHashAlgo,
        _key: &[u8],
        _state: HsmHashState<'a>,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn hmac_continue(&self, _ctx: &mut Self::HmacCtx<'_>, _data: &[u8]) -> HsmResult<()> {
        todo!()
    }

    async fn hmac_finish<'a>(&self, _ctx: Self::HmacCtx<'a>) -> HsmResult<HsmHashState<'a>> {
        todo!()
    }

    async fn hmac_finish_into(&self, _ctx: Self::HmacCtx<'_>, _dest: &mut [u8]) -> HsmResult<()> {
        todo!()
    }

    async fn hmac_finish_verify(&self, _ctx: Self::HmacCtx<'_>, _tag: &[u8]) -> HsmResult<bool> {
        todo!()
    }
}
