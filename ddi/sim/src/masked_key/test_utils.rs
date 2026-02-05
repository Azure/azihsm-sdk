// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test utilities for masked_key crate

#[cfg(test)]
use azihsm_ddi_types::AES_CBC_IV_SIZE;

#[cfg(test)]
use crate::crypto::aes::*;
#[cfg(test)]
use crate::crypto::rand::rand_bytes;
#[cfg(test)]
use crate::crypto::sha::hmac_sha_384;
#[cfg(test)]
use crate::crypto_env::CryptEnv;
#[cfg(test)]
use crate::errors::ManticoreError;

#[cfg(test)]
pub const AES256_HMAC384_COMBO_KEY: [u8; 80] = [
    // AES key
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    // HMAC key
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
    0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];

#[cfg(test)]
pub struct CryptoTestEnv {}

#[cfg(test)]
impl CryptoTestEnv {
    pub fn new() -> Self {
        CryptoTestEnv {}
    }
}

#[cfg(test)]
impl Default for CryptoTestEnv {
    fn default() -> Self {
        CryptoTestEnv::new()
    }
}

#[cfg(test)]
impl CryptEnv for CryptoTestEnv {
    fn hmac384_tag(&self, key: &[u8], data: &[u8]) -> Result<[u8; 48], ManticoreError> {
        hmac_sha_384(key, data).map_err(|_| ManticoreError::HmacError)
    }

    fn aescbc256_enc_data_len(&self, plaintext_key_len: usize) -> usize {
        plaintext_key_len
    }

    fn aescbc256_encrypt(
        &self,
        key: &[u8],
        plaintext: &[u8],
        iv: &mut [u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ManticoreError> {
        let aes_key = AesKey::from_bytes(key)?;

        let iv_in = &mut [0u8; AES_CBC_IV_SIZE];
        rand_bytes(iv_in).map_err(|_| ManticoreError::RngError)?;

        let result = aes_key.encrypt(plaintext, AesAlgo::Cbc, Some(iv_in))?;

        if ciphertext.len() < result.cipher_text.len() {
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        ciphertext[..result.cipher_text.len()].copy_from_slice(&result.cipher_text);

        iv.copy_from_slice(iv_in);

        Ok(result.cipher_text.len())
    }

    fn aescbc256_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, ManticoreError> {
        let aes_key = AesKey::from_bytes(key)?;

        let result = aes_key.decrypt(ciphertext, AesAlgo::Cbc, Some(iv))?;

        if plaintext.len() < result.plain_text.len() {
            Err(ManticoreError::OutputBufferTooSmall)?;
        }

        plaintext[..result.plain_text.len()].copy_from_slice(&result.plain_text);
        Ok(result.plain_text.len())
    }

    fn kbkdf_sha384(
        &self,
        _key: &[u8],
        _label: Option<&[u8]>,
        _context: Option<&[u8]>,
        _out_len: usize,
        output: &mut [u8],
    ) -> Result<(), ManticoreError> {
        rand_bytes(output).map_err(|_| ManticoreError::RngError)
    }

    fn generate_random(&self, output: &mut [u8]) -> Result<(), ManticoreError> {
        rand_bytes(output).map_err(|_| ManticoreError::RngError)
    }
}
