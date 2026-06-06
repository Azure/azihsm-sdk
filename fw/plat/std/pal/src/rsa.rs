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

use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;

use super::*;

fn key_size_bits(key_size: HsmRsaKey) -> usize {
    key_size.modulus_len() * 8
}

/// Write the wire-format RSA public key (`n_le || e_le`, zero-padded
/// to fixed widths) from an OpenSSL pub-key handle into the caller's
/// output slot.  `pub_out.len()` must be exactly
/// `key_size.pub_wire_len()`.
///
/// Used by both [`HsmRsa::rsa_gen_keypair`] (after generating the
/// pair) and [`HsmRsa::rsa_priv_pub_key`] (after re-deriving the pub
/// key from an imported private key) so the wire layout stays bit-
/// identical between the two paths.
fn write_rsa_pub_wire(
    pubk: &RsaPublicKey,
    key_size: HsmRsaKey,
    pub_out: &mut [u8],
) -> HsmResult<()> {
    use azihsm_crypto::RsaKeyOp;

    let modulus_len = key_size.modulus_len();
    let exp_len = HsmRsaKey::pub_exp_len();
    let total = modulus_len + exp_len;
    if pub_out.len() != total {
        return Err(HsmError::InvalidArg);
    }

    // Extract the BE components into stack scratch (any modulus up
    // to RSA-4096 fits in 512 bytes), then reverse each into the
    // fixed-width wire-LE slot.  Right-align (leading-zero pad)
    // before reversal so the on-wire layout is independent of how
    // many leading zero bytes OpenSSL stripped.
    let mut n_be = [0u8; 512];
    let mut e_be = [0u8; 8];
    let n_actual = pubk
        .n(Some(&mut n_be[..modulus_len]))
        .map_err(|_| HsmError::RsaToDerError)?;
    let e_actual = pubk
        .e(Some(&mut e_be[..exp_len]))
        .map_err(|_| HsmError::RsaToDerError)?;
    if n_actual > modulus_len || e_actual > exp_len {
        return Err(HsmError::RsaToDerError);
    }
    let mut n_be_padded = [0u8; 512];
    n_be_padded[modulus_len - n_actual..modulus_len].copy_from_slice(&n_be[..n_actual]);
    let mut e_be_padded = [0u8; 8];
    e_be_padded[exp_len - e_actual..exp_len].copy_from_slice(&e_be[..e_actual]);

    pub_out.fill(0);
    for (dst, src) in pub_out[..modulus_len]
        .iter_mut()
        .zip(n_be_padded[..modulus_len].iter().rev())
    {
        *dst = *src;
    }
    for (dst, src) in pub_out[modulus_len..total]
        .iter_mut()
        .zip(e_be_padded[..exp_len].iter().rev())
    {
        *dst = *src;
    }
    Ok(())
}

impl HsmRsa for StdHsmPal {
    /// Generate an RSA key pair, query-alloc-use style.
    ///
    /// In **query mode** (`out = None`) returns the std-PAL
    /// lengths: the raw non-CRT HSM private-key length
    /// ([`HsmRsaKey::priv_key_hsm_len`]) and the wire-format LE
    /// public-key length ([`HsmRsaKey::pub_wire_len`]).  In
    /// **use mode** (`out = Some((priv_out, pub_out))`) it generates
    /// a keypair via [`StdRsa::gen_keypair`], serializes the private
    /// key as raw non-CRT HSM bytes `n || e || p || q` (each integer
    /// zero-padded to its fixed width) via
    /// [`to_hsm_bytes`](azihsm_crypto::ExportableHsmKey::to_hsm_bytes),
    /// and writes the public key as fixed-width `n_le || e_le`
    /// (modulus padded to `key_size.modulus_len()`, exponent padded
    /// to [`HsmRsaKey::pub_exp_len`]).  Both encodings are
    /// fixed-width, so the returned byte counts are deterministic and
    /// `priv_actual == priv_max` (it is the number of HSM private-key
    /// bytes written, always equal to `priv_max`).
    ///
    /// `pct` is currently honored only insofar as the underlying
    /// driver call may run an internal PCT; a TODO covers wiring
    /// the [`HsmRsaPct::EncryptDecrypt`] / [`HsmRsaPct::SignVerify`]
    /// modes explicitly.
    async fn rsa_gen_keypair(
        &self,
        _io: &impl HsmIo,
        _alloc: &impl HsmScopedAlloc,
        key_size: HsmRsaKey,
        out: Option<(&mut DmaBuf, &mut DmaBuf)>,
        _pct: HsmRsaPct,
    ) -> HsmResult<(usize, usize)> {
        let priv_max = key_size.priv_key_hsm_len();
        let pub_wire_len = key_size.pub_wire_len();

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_max, pub_wire_len));
        };

        if priv_out.len() < priv_max || pub_out.len() < pub_wire_len {
            return Err(HsmError::InvalidArg);
        }

        let (pk, pubk) = self.rsa.gen_keypair(key_size_bits(key_size)).await?;

        // Vault the private key in the raw non-CRT HSM form
        // (`n || e || p || q`) so it round-trips with the import
        // path and `from_hsm_bytes`-based private operations.
        let priv_actual = pk
            .to_hsm_bytes(&mut priv_out[..priv_max])
            .map_err(|_| HsmError::RsaToDerError)?;

        // Extract the BE components from the freshly generated pub
        // key and write them into the wire-format LE slot.
        write_rsa_pub_wire(&pubk, key_size, &mut pub_out[..pub_wire_len])?;

        Ok((priv_actual, pub_wire_len))
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

    fn rsa_priv_key_size(&self, _io: &impl HsmIo, key: &DmaBuf) -> HsmResult<HsmRsaKey> {
        use azihsm_crypto::RsaKeyOp;
        let pk = RsaPrivateKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        let modulus_len = pk.n(None).map_err(|_| HsmError::InvalidArg)?;
        match modulus_len {
            256 => Ok(HsmRsaKey::Rsa2048Priv),
            384 => Ok(HsmRsaKey::Rsa3072Priv),
            512 => Ok(HsmRsaKey::Rsa4096Priv),
            _ => Err(HsmError::InvalidArg),
        }
    }

    fn rsa_priv_pub_key(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        pub_out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        use azihsm_crypto::PrivateKey;
        use azihsm_crypto::RsaKeyOp;

        let pk = RsaPrivateKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        let pubk = pk.public_key().map_err(|_| HsmError::InvalidArg)?;
        let modulus_len = pubk.n(None).map_err(|_| HsmError::InvalidArg)?;
        let rsa_size = match modulus_len {
            256 => HsmRsaKey::Rsa2048Pub,
            384 => HsmRsaKey::Rsa3072Pub,
            512 => HsmRsaKey::Rsa4096Pub,
            _ => return Err(HsmError::InvalidArg),
        };
        let pub_wire_len = rsa_size.pub_wire_len();

        let Some(pub_out) = pub_out else {
            return Ok(pub_wire_len);
        };
        if pub_out.len() < pub_wire_len {
            return Err(HsmError::InvalidArg);
        }

        write_rsa_pub_wire(&pubk, rsa_size, &mut pub_out[..pub_wire_len])?;
        Ok(pub_wire_len)
    }

    /// Re-encode the imported PKCS#8 DER private key into the raw
    /// non-CRT HSM form (`n || e || p || q`) the vault stores, so a
    /// later `mod_exp_priv` / `rsa_oaep_decrypt` reads it back via
    /// `from_hsm_bytes`.  Query-alloc-use.
    fn rsa_priv_to_hsm(
        &self,
        _io: &impl HsmIo,
        key: &DmaBuf,
        out: Option<&mut DmaBuf>,
    ) -> HsmResult<usize> {
        let pk = RsaPrivateKey::from_bytes(key).map_err(|_| HsmError::InvalidArg)?;
        let hsm_len = pk.hsm_bytes_len();

        let Some(out) = out else {
            return Ok(hsm_len);
        };

        if out.len() < hsm_len {
            return Err(HsmError::InvalidArg);
        }
        pk.to_hsm_bytes(&mut out[..hsm_len])
            .map_err(|_| HsmError::RsaToDerError)?;
        Ok(hsm_len)
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
        alloc: &'a impl HsmScopedAlloc,
    ) -> HsmResult<usize>
    where
        Self: 'a,
    {
        use azihsm_crypto::Decrypter;
        use azihsm_crypto::HashAlgo;
        use azihsm_crypto::RsaEncryptAlgo;

        let hash = match algo {
            HsmHashAlgo::Sha1 => HashAlgo::sha1(),
            HsmHashAlgo::Sha256 => HashAlgo::sha256(),
            HsmHashAlgo::Sha384 => HashAlgo::sha384(),
            HsmHashAlgo::Sha512 => HashAlgo::sha512(),
        };
        let label_opt: Option<&[u8]> = if label.is_empty() { None } else { Some(label) };

        // Reverse the wire-LE ciphertext to OpenSSL-BE.  The wire
        // contract for RSA integer inputs/outputs is little-endian
        // (PKA-native); the host already LE-flipped the OAEP block
        // before sending.  OpenSSL's RSA primitives expect big-
        // endian, so undo the host-side flip into a scope-allocated
        // scratch.
        let modulus_len = key_size.modulus_len();
        if ciphertext.len() != modulus_len {
            return Err(HsmError::InvalidArg);
        }
        let ct_be = alloc.dma_alloc(modulus_len)?;
        for (dst, src) in ct_be.iter_mut().zip(ciphertext.iter().rev()) {
            *dst = *src;
        }

        let key = RsaPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let mut algo = RsaEncryptAlgo::with_oaep_padding(hash, label_opt);

        // OpenSSL's OAEP decrypt requires an output buffer at least
        // `modulus_len` long even though the recovered plaintext is
        // much shorter; allocate a scope-local scratch sized to the
        // modulus, then copy the actual recovered bytes into the
        // caller's output slot.
        let scratch = alloc.dma_alloc(modulus_len)?;
        let written = Decrypter::decrypt(&mut algo, &key, ct_be, Some(&mut scratch[..]))
            .map_err(|_| HsmError::RsaDecryptFailed)?;
        if output.len() < written {
            return Err(HsmError::InvalidArg);
        }
        output[..written].copy_from_slice(&scratch[..written]);
        Ok(written)
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
