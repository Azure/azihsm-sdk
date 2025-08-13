// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_api::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::*;
use parking_lot::RwLock;

use crate::ciphers::init::*;
use crate::common::hsm_key::*;
use crate::engine_internal::*;

#[derive(Debug, Clone)]
pub struct AesCbc(Arc<RwLock<AesCbcInner>>);

impl AesCbc {
    pub(super) fn new(aes_type: AesType) -> Self {
        Self(Arc::new(RwLock::new(AesCbcInner::new(aes_type))))
    }

    /// This function performs the encryption/decryption operation for a given AES CBC cipher
    pub(super) fn cipher(&mut self, input: Vec<u8>, enc: bool) -> OpenSSLResult<Vec<u8>> {
        let mode = if enc {
            AesMode::Encrypt
        } else {
            AesMode::Decrypt
        };

        let data_out = self.0.write().aes_cbc_cipher(mode, input)?;
        self.set_iv(Some(data_out.iv.to_vec()))?;
        Ok(data_out.data)
    }

    pub(super) fn generate_key(&mut self) -> OpenSSLResult<()> {
        self.0.write().generate_key()
    }

    pub(super) fn set_key(&mut self, hsm_key: HsmKeyContainer) {
        self.0.write().set_key(hsm_key);
    }

    pub(super) fn set_iv(&mut self, iv: Option<Vec<u8>>) -> OpenSSLResult<()> {
        if let Some(iv) = iv {
            if iv.len() != AES_CBC_IV_LEN {
                Err(OpenSSLError::IncorrectParam(
                    "IV Length".to_string(),
                    AES_CBC_IV_LEN.to_string(),
                    iv.len().to_string(),
                ))?;
            }
            self.0.write().iv.copy_from_slice(iv.as_slice());
        } else {
            self.0.write().iv.copy_from_slice(&[0; AES_CBC_IV_LEN]);
        }
        Ok(())
    }

    pub(super) fn get_iv(&self) -> Vec<u8> {
        let iv = self.0.read().iv;
        iv.to_vec()
    }

    pub(super) fn ctrl(&mut self, _ctrl_op: CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult> {
        Err(OpenSSLError::CipherUnsupportedOperation)
    }

    pub(super) fn ctrl_copy(&mut self, dst_ctx: &mut AesCbc) -> OpenSSLResult<CipherCtrlResult> {
        dst_ctx.0.write().key = self.key_handle();
        let iv = self.get_iv();
        dst_ctx.0.write().iv.copy_from_slice(iv.as_slice());
        dst_ctx.0.write().key_type = self.0.read().key_type;
        Ok(CipherCtrlResult::CopySuccess)
    }

    #[cfg(test)]
    pub(super) fn key_refcount(&self) -> usize {
        if self.key_handle().is_some() {
            Arc::strong_count(&self.0)
        } else {
            0
        }
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.key_handle().is_some()
    }

    fn key_handle(&self) -> Option<Arc<HsmKeyContainer>> {
        self.0.read().key.clone()
    }
}

#[derive(Debug)]
struct AesCbcInner {
    key: Option<Arc<HsmKeyContainer>>,
    iv: [u8; AES_CBC_IV_LEN],
    key_type: AesType,
}

impl AesCbcInner {
    fn new(key_type: AesType) -> Self {
        let key = None;
        let iv = [0; AES_CBC_IV_LEN];
        Self { key, iv, key_type }
    }

    fn generate_key(&mut self) -> OpenSSLResult<()> {
        let key_size = self.key_type.hsm_key_size();
        let hsm_key = HsmKeyContainer::aes_generate(key_size)?;
        self.set_key(hsm_key);
        Ok(())
    }

    fn set_key(&mut self, hsm_key: HsmKeyContainer) {
        self.key = Some(Arc::new(hsm_key));
    }

    fn aes_cbc_cipher(&self, aes_mode: AesMode, data: Vec<u8>) -> OpenSSLResult<AesResult> {
        if let Some(key) = self.key.clone() {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .aes_encrypt_decrypt(&key.hsm_handle(), aes_mode, data, self.iv)
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::CipherCtxNotInitialized)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ciphers::init::AesType;
    use crate::load_engine;

    type TestResult<T> = Result<T, &'static str>;

    #[test]
    fn test_aes_cbc_generate_key() {
        let _e = load_engine();
        let aes128_cbc = create_aes_cbc_ctx(AesType::Aes128Cbc);
        assert_eq!(aes128_cbc.key_refcount(), 1);

        let aes192_cbc = create_aes_cbc_ctx(AesType::Aes192Cbc);
        assert_eq!(aes192_cbc.key_refcount(), 1);

        let aes256_cbc = create_aes_cbc_ctx(AesType::Aes256Cbc);
        assert_eq!(aes256_cbc.key_refcount(), 1);
    }

    #[test]
    fn test_aes_cbc_cipher() {
        assert!(validate_cipher(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cbc_cipher_data_multiblock() {
        assert!(validate_cipher_multiblock(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_multiblock(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_multiblock(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cbc_cipher_iv_mismatch() {
        assert!(validate_cipher_iv_mismatch(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_iv_mismatch(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_iv_mismatch(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cbc_iv_invalid_len() {
        assert!(validate_cipher_invalid_iv_len(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_invalid_iv_len(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_invalid_iv_len(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cipher_data_invalid_size() {
        assert!(validate_cipher_data_invalid_size(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_data_invalid_size(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_data_invalid_size(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cbc_cipher_data_corrupt() {
        assert!(validate_cipher_data_corrupt(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_data_corrupt(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_data_corrupt(AesType::Aes256Cbc).is_ok());
    }

    #[test]
    fn test_aes_cbc_cipher_data_unaligned() {
        assert!(validate_cipher_data_unaligned(AesType::Aes128Cbc).is_ok());
        assert!(validate_cipher_data_unaligned(AesType::Aes192Cbc).is_ok());
        assert!(validate_cipher_data_unaligned(AesType::Aes256Cbc).is_ok());
    }

    // Helper functions to test the AES CBC cipher

    fn create_aes_cbc_ctx(cbc_mode: AesType) -> AesCbc {
        let mut aes_cbc = AesCbc::new(cbc_mode);
        assert!(aes_cbc.key_handle().is_none());
        assert!(aes_cbc.key_refcount() == 0);
        assert_eq!(aes_cbc.get_iv(), vec![0; AES_CBC_IV_LEN]);
        assert!(aes_cbc.generate_key().is_ok());
        assert!(aes_cbc.key_handle().is_some());
        assert_eq!(aes_cbc.key_refcount(), 1);
        aes_cbc
    }

    fn validate_cipher(cbc_mode: AesType) -> TestResult<()> {
        let _e = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);
        let data = vec![0x1; 1024];
        let iv = vec![0x1; AES_CBC_IV_LEN];

        // set IV for encryption
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());

        let encrypted = aes_cbc
            .cipher(data.clone(), true)
            .expect("Could not encrypt data");

        // set IV for decryption
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());

        let decrypted = aes_cbc
            .cipher(encrypted.clone(), false)
            .expect("Could not decrypt data");
        assert!(data == decrypted);
        Ok(())
    }

    fn validate_cipher_multiblock(cbc_mode: AesType) -> TestResult<()> {
        let _engine = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let data1 = vec![0x1; 64];
        let data2 = vec![0x2; 16];
        let iv = vec![0x1; AES_CBC_IV_LEN];
        let mut total_data = vec![0x0; 80];
        total_data[..64].copy_from_slice(data1.as_slice());
        total_data[64..].copy_from_slice(data2.as_slice());

        // Encrypt data1 and data2 separately and combine the data
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());

        let encrypted_data1 = aes_cbc
            .cipher(data1, true)
            .expect("Could not encrypt data1");

        let encrypted_data2 = aes_cbc
            .cipher(data2, true)
            .expect("Could not encrypt data2");

        let mut total_encrypted = vec![0x0; 80];
        total_encrypted[..64].copy_from_slice(encrypted_data1.as_slice());
        total_encrypted[64..].copy_from_slice(encrypted_data2.as_slice());

        // Decrypt the total encrypted data
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());
        let decrypted_data = aes_cbc
            .cipher(total_encrypted.clone(), false)
            .expect("Could not decrypt data");
        assert!(total_data == decrypted_data);
        Ok(())
    }

    fn validate_cipher_iv_mismatch(cbc_mode: AesType) -> TestResult<()> {
        let _e = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let data = vec![0x1; 1024];
        let iv = vec![0x1; AES_CBC_IV_LEN];

        // encrypt data
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());
        let encrypted_data = aes_cbc
            .cipher(data.clone(), true)
            .expect("Could not encrypt data");

        // init with a differnt IV for decryption
        let new_iv = vec![0x2; AES_CBC_IV_LEN];

        let result = aes_cbc.set_iv(Some(new_iv.clone()));
        assert!(result.is_ok());
        let decrypted_data = aes_cbc
            .cipher(encrypted_data.clone(), false)
            .expect("Could not decrypt data");
        assert!(data != decrypted_data);
        Ok(())
    }

    fn validate_cipher_invalid_iv_len(cbc_mode: AesType) -> TestResult<()> {
        let _e = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let iv = vec![0x1; AES_CBC_IV_LEN - 1];

        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_err(), "result {:?}", result);
        Ok(())
    }

    fn validate_cipher_data_invalid_size(cbc_mode: AesType) -> TestResult<()> {
        let _engine = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let data = vec![0x1; 1040];
        let iv = vec![0x1; AES_CBC_IV_LEN];

        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());

        let encrypted = aes_cbc.cipher(data, true);
        assert!(encrypted.is_err());
        Ok(())
    }

    fn validate_cipher_data_corrupt(cbc_mode: AesType) -> TestResult<()> {
        let _engine = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let data = vec![0x1; 1024];
        let iv = vec![0x1; AES_CBC_IV_LEN];

        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());
        let mut encrypted_data = aes_cbc
            .cipher(data.clone(), true)
            .expect("Could not encrypt data");

        // Flip a bit in the encrypted data
        encrypted_data[0] ^= 0x1;

        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());
        let decrypted_data = aes_cbc
            .cipher(encrypted_data, false)
            .expect("Could not decrypt data");
        assert!(data != decrypted_data);
        Ok(())
    }

    fn validate_cipher_data_unaligned(cbc_mode: AesType) -> TestResult<()> {
        let _engine = load_engine();
        let mut aes_cbc = create_aes_cbc_ctx(cbc_mode);

        let data = vec![0x1; 230];
        let iv = vec![0x1; AES_CBC_IV_LEN];
        let result = aes_cbc.set_iv(Some(iv.clone()));
        assert!(result.is_ok());
        let encrypted = aes_cbc.cipher(data, true);
        assert!(encrypted.is_err());
        Ok(())
    }
}
