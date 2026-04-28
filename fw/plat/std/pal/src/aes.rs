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
}
