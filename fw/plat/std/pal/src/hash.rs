// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHash`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] enum
//! to [`azihsm_crypto::HashAlgo`] and forwards one-shot hashing to the
//! [`StdHash`](crate::drivers::hash::StdHash) driver.
//!
//! Multi-step hashing is not currently needed by the standard PAL, so
//! those entry points are left as `todo!()` stubs.

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

impl HsmHash for StdHsmPal {
    type HashCtx<'a>
        = HsmHashState<'a>
    where
        Self: 'a;

    async fn hash(
        &self,
        algo: HsmHashAlgo,
        data: &[u8],
        digest: &mut [u8],
        _big_endian: bool,
    ) -> HsmResult<()> {
        self.hash.hash(to_hash_algo(algo), data, digest).await
    }

    async fn hash_begin<'a>(
        &self,
        _algo: HsmHashAlgo,
        _state: HsmHashState<'a>,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn hash_continue(&self, _ctx: &mut Self::HashCtx<'_>, _data: &[u8]) -> HsmResult<()> {
        todo!()
    }

    async fn hash_finish<'a>(
        &self,
        _ctx: Self::HashCtx<'a>,
        _big_endian: bool,
    ) -> HsmResult<HsmHashState<'a>> {
        todo!()
    }
}
