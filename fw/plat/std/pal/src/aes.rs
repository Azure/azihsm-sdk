// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAes`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdAes`](crate::drivers::aes::StdAes)
//! driver. All implemented crypto work is offloaded to the worker pool by
//! the driver. Newly added AES-KW/AES-XTS trait entry points are stubbed
//! with `todo!()` for now.

use super::*;

impl HsmAes for StdHsmPal {
    async fn aes_gen_key(&self, key: &mut [u8]) -> HsmResult<()> {
        self.aes.gen_key(key).await
    }

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

    async fn aes_cbc_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        iv: &mut [u8],
        data: &mut [u8],
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes.cbc_enc_dec(key, encrypt, iv, &input, data).await
    }

    async fn aes_ecb_enc_dec(
        &self,
        key: &[u8],
        encrypt: bool,
        input: &[u8],
        output: &mut [u8],
    ) -> HsmResult<()> {
        self.aes.ecb_enc_dec(key, encrypt, input, output).await
    }

    async fn aes_ecb_enc_dec_in_place(
        &self,
        key: &[u8],
        encrypt: bool,
        data: &mut [u8],
    ) -> HsmResult<()> {
        let input = data.to_vec();
        self.aes.ecb_enc_dec(key, encrypt, &input, data).await
    }

    async fn gcm_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        if aad_len > plaintext.len() || aad_len > ciphertext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
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

    async fn gcm_encrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        data: &mut [u8],
        tag: &mut [u8; 16],
    ) -> HsmResult<()> {
        if aad_len > data.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
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

    async fn gcm_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> HsmResult<()> {
        if aad_len > ciphertext.len() || aad_len > plaintext.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
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

    async fn gcm_decrypt_in_place(
        &self,
        key: &[u8],
        iv: &[u8; 12],
        aad_len: usize,
        tag: &[u8; 16],
        data: &mut [u8],
    ) -> HsmResult<()> {
        if aad_len > data.len() {
            return Err(HsmError::AesGcmInvalidBufferSize);
        }
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

    async fn aes_kw_wrap(&self, _key: &[u8], _input: &[u8], _output: &mut [u8]) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kw_unwrap(&self, _key: &[u8], _input: &[u8], _output: &mut [u8]) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kwp_wrap(&self, _key: &[u8], _input: &[u8], _output: &mut [u8]) -> HsmResult<()> {
        todo!()
    }

    async fn aes_kwp_unwrap(
        &self,
        _key: &[u8],
        _input: &[u8],
        _output: &mut [u8],
    ) -> HsmResult<usize> {
        todo!()
    }

    async fn aes_xts_gen_key(&self, _key: &mut [u8]) -> HsmResult<()> {
        todo!()
    }

    async fn aes_xts_encrypt(
        &self,
        _key: &[u8],
        _tweak: &[u8],
        _dul: XtsDataUnitLen,
        _input: &[u8],
        _output: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_xts_decrypt(
        &self,
        _key: &[u8],
        _tweak: &[u8],
        _dul: XtsDataUnitLen,
        _input: &[u8],
        _output: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_xts_encrypt_in_place(
        &self,
        _key: &[u8],
        _tweak: &[u8],
        _dul: XtsDataUnitLen,
        _data: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }

    async fn aes_xts_decrypt_in_place(
        &self,
        _key: &[u8],
        _tweak: &[u8],
        _dul: XtsDataUnitLen,
        _data: &mut [u8],
    ) -> HsmResult<()> {
        todo!()
    }
}
