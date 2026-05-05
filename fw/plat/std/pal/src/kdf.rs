// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmKdf`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer that maps the PAL-level [`HsmHashAlgo`] enum to
//! [`azihsm_crypto::HashAlgo`] and forwards the supported KDF operations to
//! the [`StdKdf`](crate::drivers::kdf::StdKdf) driver.
//!
//! HKDF extract/expand and SP 800-108 counter-mode KDF are backed by
//! OpenSSL. The remaining hash-based KDF helpers are currently left as
//! `todo!()` stubs.

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

impl HsmKdf for StdHsmPal {
    async fn hkdf_extract<'a>(
        &self,
        algo: HsmHashAlgo,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>> {
        self.kdf
            .hkdf(
                ikm,
                to_hash_algo(algo),
                azihsm_crypto::HkdfMode::Extract,
                salt,
                &[],
                prk,
            )
            .await?;
        Ok(state)
    }

    async fn hkdf_expand<'a>(
        &self,
        algo: HsmHashAlgo,
        prk: &[u8],
        info: &[u8],
        output: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>> {
        self.kdf
            .hkdf(
                prk,
                to_hash_algo(algo),
                azihsm_crypto::HkdfMode::Expand,
                &[],
                info,
                output,
            )
            .await?;
        Ok(state)
    }

    async fn sp800_108_kdf<'a>(
        &self,
        algo: HsmHashAlgo,
        key: &[u8],
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
        state: HsmKdfState<'a>,
    ) -> HsmResult<HsmKdfState<'a>> {
        self.kdf
            .kbkdf(key, to_hash_algo(algo), label, context, output)
            .await?;
        Ok(state)
    }

    async fn mgf1(
        &self,
        _algo: HsmHashAlgo,
        _seed: &[u8],
        _mask: &mut [u8],
        _state: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn mgf1_xor(
        &self,
        _algo: HsmHashAlgo,
        _seed: &[u8],
        _mask: &mut [u8],
        _state: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn x963_kdf(
        &self,
        _algo: HsmHashAlgo,
        _z: &[u8],
        _shared_info: &[u8],
        _key: &mut [u8],
        _state: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn sp800_56a_kdf(
        &self,
        _algo: HsmHashAlgo,
        _z: &[u8],
        _other_info: &[u8],
        _key: &mut [u8],
        _state: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }
}
