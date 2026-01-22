// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub struct HsmAesXtsAlgo {
    tweak: u128,
    dul: usize,
}

impl HsmAesXtsAlgo {
    fn validate_dul_size(dul: usize) -> HsmResult<()> {
        if !matches!(dul, 512 | 4096 | 8192) {
            Err(HsmError::InvalidArgument)?;
        }
        Ok(())
    }
    pub fn new(tweak: &[u8], dul: usize) -> HsmResult<Self> {
        let tweak_val = tweak
            .try_into()
            .map(u128::from_le_bytes)
            .map_err(|_| HsmError::InvalidArgument)?;

        //validate dul size
        HsmAesXtsAlgo::validate_dul_size(dul)?;

        Ok(Self {
            tweak: tweak_val,
            dul,
        })
    }
}

impl HsmEncryptOp for HsmAesXtsAlgo {
    type Key = HsmAesXtsKey;
    type Error = HsmError;

    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check that the key is suitable for encryption
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // check plaintext size is multiple of dul
        if !plaintext.len().is_multiple_of(self.dul) {
            Err(HsmError::InvalidArgument)?;
        }

        //return expected size if ciphertext is None
        let Some(ciphertext) = ciphertext else {
            return Ok(plaintext.len());
        };

        // Check that the ciphertext buffer is large enough
        if ciphertext.len() < plaintext.len() {
            Err(HsmError::BufferTooSmall)?;
        }

        //perform aes xts encrypt DDI operation
        ddi::aes_xts_encrypt(key, self.tweak, self.dul, plaintext, ciphertext)
    }
}

impl HsmDecryptOp for HsmAesXtsAlgo {
    type Key = HsmAesXtsKey;
    type Error = HsmError;

    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check that the key is suitable for decryption
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // check ciphertext size is multiple of dul
        if !ciphertext.len().is_multiple_of(self.dul) {
            Err(HsmError::InvalidArgument)?;
        }

        //return expected size if plaintext is None
        let Some(plaintext) = plaintext else {
            return Ok(ciphertext.len());
        };

        // Check that the plaintext buffer is large enough
        if plaintext.len() < ciphertext.len() {
            Err(HsmError::BufferTooSmall)?;
        }

        //perform aes xts decrypt DDI operation
        ddi::aes_xts_decrypt(key, self.tweak, self.dul, ciphertext, plaintext)
    }
}
