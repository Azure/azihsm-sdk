// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRsa`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (DER byte slices)
//! and the [`StdRsa`](crate::drivers::rsa::StdRsa) driver (OpenSSL
//! key handles).
//!
//! Raw key generation and modular exponentiation are implemented. The
//! newer padding-helper entry points are present in the trait but are not
//! currently used by the standard PAL, so they are left as `todo!()`.

use azihsm_crypto::ExportableKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;

use super::*;

fn key_size_bits(key_size: HsmRsaKey) -> usize {
    key_size.modulus_len() * 8
}

impl HsmRsa for StdHsmPal {
    async fn ras_gen_keypair(
        &self,
        key_size: HsmRsaKey,
        priv_key: &mut [u8],
        pub_key: &mut [u8],
        _pct: HsmRsaPct,
    ) -> Result<(), HsmError> {
        let (pk, pubk) = self.rsa.gen_keypair(key_size_bits(key_size)).await?;

        let priv_len = pk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if priv_key.len() < priv_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        pk.to_bytes(Some(&mut priv_key[..priv_len]))
            .map_err(|_| HsmError::RsaToDerError)?;

        let pub_len = pubk.to_bytes(None).map_err(|_| HsmError::RsaToDerError)?;
        if pub_key.len() < pub_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        pubk.to_bytes(Some(&mut pub_key[..pub_len]))
            .map_err(|_| HsmError::RsaToDerError)?;

        Ok(())
    }

    async fn mod_exp_priv(
        &self,
        _key_size: HsmRsaKey,
        key: &[u8],
        y: &[u8],
        x: &mut [u8],
    ) -> Result<(), HsmError> {
        let priv_key = RsaPrivateKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_priv(&priv_key, y, x).await
    }

    async fn mod_exp_pub(
        &self,
        _key_size: HsmRsaKey,
        key: &[u8],
        x: &[u8],
        y: &mut [u8],
    ) -> Result<(), HsmError> {
        let pub_key = RsaPublicKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_pub(&pub_key, x, y).await
    }

    async fn rsa_pkcs1_encrypt(
        &self,
        _key_size: HsmRsaKey,
        _pub_key: &[u8],
        _message: &[u8],
        _output: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn rsa_pkcs1_decrypt(
        &self,
        _key_size: HsmRsaKey,
        _priv_key: &[u8],
        _ciphertext: &[u8],
        _output: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<usize> {
        todo!()
    }

    async fn rsa_pkcs1_sign(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &[u8],
        _message_hash: &[u8],
        _signature: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn rsa_pkcs1_verify(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &[u8],
        _message_hash: &[u8],
        _signature: &[u8],
        _work: &mut [u8],
    ) -> HsmResult<bool> {
        todo!()
    }

    async fn rsa_oaep_encrypt(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &[u8],
        _message: &[u8],
        _label: &[u8],
        _output: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn rsa_oaep_decrypt(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &[u8],
        _ciphertext: &[u8],
        _label: &[u8],
        _output: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<usize> {
        todo!()
    }

    async fn rsa_pss_sign(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &[u8],
        _message_hash: &[u8],
        _salt_len: usize,
        _signature: &mut [u8],
        _work: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn rsa_pss_verify(
        &self,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &[u8],
        _message_hash: &[u8],
        _salt_len: usize,
        _signature: &[u8],
        _work: &mut [u8],
    ) -> HsmResult<bool> {
        todo!()
    }
}
