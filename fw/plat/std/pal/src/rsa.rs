// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmRsa`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (byte-slice keys —
//! recovered DER on import, the HSM byte layout for vault-stored private
//! keys, wire form for public keys) and the
//! [`StdRsa`](crate::drivers::rsa::StdRsa) driver (OpenSSL key handles).
//!
//! Raw key generation and modular exponentiation are implemented. The
//! newer padding-helper entry points are present in the trait but are not
//! currently used by the standard PAL, so they are left as `todo!()`.

use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::ExportableHsmRsaKey;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::Key;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;

use super::*;

fn key_size_bits(key_size: HsmRsaKey) -> usize {
    key_size.modulus_len() * 8
}

impl HsmRsa for StdHsmPal {
    async fn rsa_gen_keypair(
        &self,
        _io: &impl HsmIo,
        key_size: HsmRsaKey,
        priv_key: &mut DmaBuf,
        pub_key: &mut DmaBuf,
        _pct: HsmRsaPct,
    ) -> Result<(), HsmError> {
        let (pk, pubk) = self.rsa.gen_keypair(key_size_bits(key_size)).await?;

        // The vault stores the RSA private key in HSM byte format (raw
        // components), not DER; a generated key is stored non-CRT.
        let priv_len = pk.hsm_bytes_len();
        if priv_key.len() < priv_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        pk.to_hsm_bytes(&mut priv_key[..priv_len])
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
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        key: &DmaBuf,
        y: &DmaBuf,
        x: &mut DmaBuf,
    ) -> Result<(), HsmError> {
        let priv_key = RsaPrivateKey::from_hsm_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_priv(&priv_key, y, x).await
    }

    async fn mod_exp_pub(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        key: &DmaBuf,
        x: &DmaBuf,
        y: &mut DmaBuf,
    ) -> Result<(), HsmError> {
        let pub_key = RsaPublicKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        self.rsa.mod_exp_pub(&pub_key, x, y).await
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        priv_key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        // The std PAL's vault representation is HSM byte format (raw
        // components): parse it, derive the public key, and emit the raw
        // wire form `n_le || e_le`.  The BE->LE flip lives in the driver.
        // In query mode (`pub_out == None`) only the wire length is returned.
        let pk = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let pubk = pk.public_key().map_err(|_| HsmError::RsaGenerateError)?;
        crate::drivers::rsa::rsa_pub_wire(&pubk, pub_out.map(|b| &mut **b))
    }

    fn rsa_priv_der_to_vault(
        &self,
        _io: &impl HsmIo,
        buf: &mut DmaBuf,
        crt: bool,
    ) -> HsmResult<(usize, usize)> {
        // Parse the recovered DER and re-serialize it in place into the
        // vault HSM byte format: the CRT layout (`n|e|d|p|q|dp|dq|qinv`)
        // when `crt`, else non-CRT (`n|e|p|q`).  Both HSM layouts are no
        // larger than the source DER, so they fit in `buf`.
        let pk = RsaPrivateKey::from_bytes(buf).map_err(|_| HsmError::InvalidArg)?;
        let modulus_len = pk.size();
        let hsm_len = if crt {
            pk.to_hsm_crt_bytes(buf)
        } else {
            pk.to_hsm_bytes(buf)
        }
        .map_err(|_| HsmError::RsaToDerError)?;
        Ok((hsm_len, modulus_len))
    }

    async fn rsa_pkcs1_encrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _pub_key: &DmaBuf,
        _message: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_decrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _priv_key: &DmaBuf,
        _ciphertext: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_sign<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _signature: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pkcs1_verify<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _signature: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_oaep_encrypt<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message: &DmaBuf,
        _label: &DmaBuf,
        _output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_oaep_decrypt<'a>(
        &self,
        _io: &impl HsmIo,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &DmaBuf,
        ciphertext: &DmaBuf,
        label: &DmaBuf,
        output: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        // The trait contract requires the ciphertext to be exactly one
        // modulus block; enforce it (OpenSSL would otherwise accept a
        // shorter block as a number with implicit leading zeros), matching
        // the hardware PAL.
        if ciphertext.len() != key_size.modulus_len() {
            return Err(HsmError::InvalidArg);
        }

        // Vault private key is HSM byte format in the std PAL; parse it,
        // then OAEP decrypt the wire-LE ciphertext (the driver flips
        // LE->BE).  An empty `label` maps to the default empty OAEP label.
        let pk = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let hash = crate::hash::to_hash_algo(algo);
        let label = if label.is_empty() {
            None
        } else {
            Some(label.to_vec())
        };
        self.rsa
            .oaep_decrypt(&pk, hash, label, ciphertext, output)
            .await
    }

    async fn rsa_pss_sign<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _priv_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _salt_len: usize,
        _signature: &mut DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<()>
    where
        Self: 'a,
    {
        todo!()
    }

    async fn rsa_pss_verify<'a>(
        &self,
        _io: &impl HsmIo,
        _key_size: HsmRsaKey,
        _algo: HsmHashAlgo,
        _pub_key: &DmaBuf,
        _message_hash: &DmaBuf,
        _salt_len: usize,
        _signature: &DmaBuf,
        _alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<bool>
    where
        Self: 'a,
    {
        todo!()
    }
}
