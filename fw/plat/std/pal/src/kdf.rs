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

use core::ops::Deref;

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
    async fn hkdf_extract(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        salt: Option<&DmaBuf>,
        ikm: &DmaBuf,
        prk: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .hkdf(
                ikm,
                to_hash_algo(algo),
                azihsm_crypto::HkdfMode::Extract,
                salt.map(|s| s.deref()),
                None,
                prk,
            )
            .await
    }

    async fn hkdf_expand(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        prk: &DmaBuf,
        info: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .hkdf(
                prk,
                to_hash_algo(algo),
                azihsm_crypto::HkdfMode::Expand,
                None,
                info.map(|s| s.deref()),
                output,
            )
            .await
    }

    async fn sp800_108_kdf(
        &self,
        _io: &impl HsmIo,
        algo: HsmHashAlgo,
        key: &DmaBuf,
        label: Option<&DmaBuf>,
        context: Option<&DmaBuf>,
        output: &mut DmaBuf,
    ) -> HsmResult<()> {
        self.kdf
            .kbkdf(
                key,
                to_hash_algo(algo),
                label.map(|s| s.deref()),
                context.map(|s| s.deref()),
                output,
            )
            .await
    }

    async fn mgf1(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _seed: &DmaBuf,
        _mask: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn mgf1_xor(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _seed: &DmaBuf,
        _mask: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn x963_kdf(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _z: &DmaBuf,
        _shared_info: &DmaBuf,
        _key: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }

    async fn sp800_56a_kdf(
        &self,
        _io: &impl HsmIo,
        _algo: HsmHashAlgo,
        _z: &DmaBuf,
        _other_info: &DmaBuf,
        _key: &mut DmaBuf,
    ) -> HsmResult<()> {
        todo!()
    }
}
