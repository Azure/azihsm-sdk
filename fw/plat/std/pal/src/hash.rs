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

pub(crate) fn to_hash_algo(algo: HsmHashAlgo) -> HashAlgo {
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

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::to_hash_algo;
    use super::*;
    use crate::drivers::hash::StdHash;
    use crate::worker::WorkerPool;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// NIST FIPS 180-4 "abc" digests in big-endian (standard) byte order.
    const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    /// Hashes `msg` through the PAL with the requested endianness and returns
    /// the digest bytes.
    async fn pal_hash(algo: HsmHashAlgo, msg: &[u8], big_endian: bool) -> Vec<u8> {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);

        let msg_buf = msg.to_vec();
        let data = unsafe { DmaBuf::from_raw(&msg_buf) };
        let digest_len = algo.digest_len();
        let mut buf = [0u8; 64];
        let digest = unsafe { DmaBuf::from_raw_mut(&mut buf[..digest_len]) };

        pal.hash(&io, algo, data, digest, big_endian).await.unwrap();
        buf[..digest_len].to_vec()
    }

    /// Reference big-endian digest computed by the OpenSSL-backed driver.
    async fn openssl_digest(algo: HsmHashAlgo, msg: &[u8]) -> Vec<u8> {
        let driver = StdHash::new(WorkerPool::new(Handle::current()));
        let mut digest = vec![0u8; algo.digest_len()];
        driver
            .hash(to_hash_algo(algo), msg, &mut digest)
            .await
            .unwrap();
        digest
    }

    /// Deterministic multi-block message used for reference-based checks.
    fn multiblock_msg() -> Vec<u8> {
        (0..200u32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3) as u8)
            .collect()
    }

    /// Verifies the PAL hash of `msg` equals `expected_be` in big-endian and
    /// its full byte reversal in little-endian.
    async fn verify_endianness(algo: HsmHashAlgo, msg: &[u8], expected_be: &[u8]) {
        // validate big-endian output
        let be = pal_hash(algo, msg, true).await;
        assert_eq!(be, expected_be);

        // validate little-endian output
        let mut expected_le = expected_be.to_vec();
        expected_le.reverse();
        let le = pal_hash(algo, msg, false).await;
        assert_eq!(le, expected_le);
    }

    #[tokio::test]
    async fn sha1_validate_nist() {
        verify_endianness(HsmHashAlgo::Sha1, b"abc", &hex::decode(SHA1_ABC).unwrap()).await;
    }

    #[tokio::test]
    async fn sha256_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha256,
            b"abc",
            &hex::decode(SHA256_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha384_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha384,
            b"abc",
            &hex::decode(SHA384_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha512_validate_nist() {
        verify_endianness(
            HsmHashAlgo::Sha512,
            b"abc",
            &hex::decode(SHA512_ABC).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn sha1_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha1, &msg).await;
        verify_endianness(HsmHashAlgo::Sha1, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha256_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha256, &msg).await;
        verify_endianness(HsmHashAlgo::Sha256, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha384_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha384, &msg).await;
        verify_endianness(HsmHashAlgo::Sha384, &msg, &reference).await;
    }

    #[tokio::test]
    async fn sha512_validate_openssl() {
        let msg = multiblock_msg();
        let reference = openssl_digest(HsmHashAlgo::Sha512, &msg).await;
        verify_endianness(HsmHashAlgo::Sha512, &msg, &reference).await;
    }
}
