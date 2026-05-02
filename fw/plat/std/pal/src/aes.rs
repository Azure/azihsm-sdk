// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All crypto work is offloaded to the worker pool by the driver.
//!
//! ## Data flow (CBC example)
//!
//! ```text
//! Core calls pal.aes_cbc_enc_dec(key, true, iv, input, output)
//!   → self.aes.cbc_enc_dec(key, true, iv, input, output)
//!     → WorkerPool → OpenSSL AES-CBC (no padding)
//!   → output + updated IV written into caller's buffers
//! ```

use super::*;

impl HsmAes for StdHsmPal {
    /// Generate a random AES key by delegating to the driver.
    async fn aes_gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        self.aes.gen_key(key).await
    }

    /// AES-CBC encrypt or decrypt with separate buffers.
    async fn aes_cbc_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        self.aes.cbc_enc_dec(key, encrypt, iv, input, output).await
    }

    /// AES-CBC encrypt or decrypt in-place.
    ///
    /// Uses `data` as both input and output by passing it to the driver
    /// as input and writing the result back.
    async fn aes_cbc_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        data: &mut [u8],
    ) -> HsmResult<()> {
        // Driver needs separate input/output; use a temp copy.
        let input = data.to_vec();
        self.aes.cbc_enc_dec(key, encrypt, iv, &input, data).await
    }

    /// AES-ECB encrypt or decrypt with separate buffers.
    async fn aes_ecb_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        self.aes.ecb_enc_dec(key, encrypt, input, output).await
    }

    /// AES-ECB encrypt or decrypt in-place.
    async fn aes_ecb_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        data: &mut [u8],
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes.ecb_enc_dec(key, encrypt, &input, data).await
    }

    /// AES-GCM encrypt with separate buffers.
    async fn gcm_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        let aad = if aad_len > 0 {
            Some(&plaintext[..aad_len])
        } else {
            None
        };
        let data = &plaintext[aad_len..];
        if let Some(aad) = aad {
            ciphertext[..aad_len].copy_from_slice(aad);
        }
        self.aes
            .gcm_encrypt(key, iv, aad, data, &mut ciphertext[aad_len..], tag)
            .await
    }

    /// AES-GCM encrypt in-place.
    async fn gcm_encrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        data: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        let input = data.to_vec();
        let aad = if aad_len > 0 {
            Some(&input[..aad_len])
        } else {
            None
        };
        let plaintext = &input[aad_len..];
        self.aes
            .gcm_encrypt(key, iv, aad, plaintext, &mut data[aad_len..], tag)
            .await
    }

    /// AES-GCM decrypt with separate buffers.
    async fn gcm_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> HsmResult<()> {
        let aad = if aad_len > 0 {
            plaintext[..aad_len].copy_from_slice(&ciphertext[..aad_len]);
            Some(&ciphertext[..aad_len])
        } else {
            None
        };
        let data = &ciphertext[aad_len..];
        self.aes
            .gcm_decrypt(key, iv, aad, tag, data, &mut plaintext[aad_len..])
            .await
    }

    /// AES-GCM decrypt in-place.
    async fn gcm_decrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        data: &mut [u8],
    ) -> HsmResult<()> {
        let input = data.to_vec();
        let aad = if aad_len > 0 {
            Some(&input[..aad_len])
        } else {
            None
        };
        let ciphertext = &input[aad_len..];
        self.aes
            .gcm_decrypt(key, iv, aad, tag, ciphertext, &mut data[aad_len..])
            .await
    }
}
