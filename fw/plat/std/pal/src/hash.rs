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

#[allow(dead_code)]
pub struct StdHashCtx<'a> {
    algo: HsmHashAlgo,
    state: &'a mut [u8],
}

impl HsmHash for StdHsmPal {
    type HashCtx<'a>
        = StdHashCtx<'a>
    where
        Self: 'a;

    async fn hash(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        data: &DmaBuf,
        digest: &mut DmaBuf,
        big_endian: bool,
    ) -> HsmResult<()> {
        let digest_len = algo.digest_len();
        if digest.len() < digest_len {
            return Err(HsmError::InvalidArg);
        }
        self.hash
            .hash(to_hash_algo(algo), data, &mut digest[..digest_len])
            .await?;
        if !big_endian {
            // SHA primitive is BE-native; reverse to the wire-LE
            // layout used at the PAL boundary for hashes that feed
            // directly into PKA-style operations (e.g. `ecc_sign`).
            digest[..digest_len].reverse();
        }
        Ok(())
    }

    fn hash_begin<'a>(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<Self::HashCtx<'a>>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn hash_continue(
        &self,
        _io: &impl HsmIo,
        _ctx: &mut Self::HashCtx<'_>,
        _data: &DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn hash_finish(
        &self,
        _io: &impl HsmIo,
        _ctx: Self::HashCtx<'_>,
        _digest: &mut DmaBuf,
        _big_endian: bool,
    ) -> HsmResult<()> {
        todo!()
    }
}
