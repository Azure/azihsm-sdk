// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_api_resilient::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::*;
use parking_lot::RwLock;

use crate::ciphers::init::*;
use crate::common::hsm_key::*;
use crate::engine_internal::*;

#[derive(Debug, Clone)]
pub struct AesXts(Arc<RwLock<AesXtsInner>>);

impl AesXts {
    pub(super) fn new() -> Self {
        Self(Arc::new(RwLock::new(AesXtsInner::new())))
    }

    pub(super) fn key_handle1(&self) -> Option<Arc<HsmKeyContainer>> {
        self.0.read().key1.clone()
    }

    pub(super) fn key_handle2(&self) -> Option<Arc<HsmKeyContainer>> {
        self.0.read().key2.clone()
    }

    // This function performs data encrypt/decrypt using AES XTS mode.
    pub(super) fn cipher(&mut self, input: Vec<u8>, enc: bool) -> OpenSSLResult<Vec<u8>> {
        let mode = if enc {
            AesMode::Encrypt
        } else {
            AesMode::Decrypt
        };

        let result = self.0.write().aes_xts_cipher(mode, input)?;
        Ok(result.data)
    }

    pub(super) fn generate_key(&mut self) -> OpenSSLResult<()> {
        self.0.write().generate_key()
    }

    pub(super) fn set_key(&mut self, hsm_key1: HsmKeyContainer, hsm_key2: HsmKeyContainer) {
        self.0.write().set_key(hsm_key1, hsm_key2);
    }

    pub(super) fn set_iv(&mut self, iv: Option<Vec<u8>>) -> OpenSSLResult<()> {
        if let Some(iv) = iv {
            if iv.len() != AES_XTS_TWEAK_LEN {
                Err(OpenSSLError::IncorrectParam(
                    "Tweak length".to_string(),
                    AES_XTS_TWEAK_LEN.to_string(),
                    iv.len().to_string(),
                ))?;
            }
            self.0.write().tweak.copy_from_slice(&iv);
        } else {
            self.0
                .write()
                .tweak
                .copy_from_slice(&[0; AES_XTS_TWEAK_LEN]);
        }

        Ok(())
    }

    pub(super) fn get_iv(&self) -> Vec<u8> {
        self.0.read().tweak.to_vec()
    }

    pub(super) fn ctrl(&mut self, _ctrl_op: CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult> {
        Err(OpenSSLError::CipherUnsupportedOperation)
    }

    pub(super) fn ctrl_copy(&mut self, dst_ctx: &mut AesXts) -> OpenSSLResult<CipherCtrlResult> {
        dst_ctx.0.write().key1 = self.key_handle1();
        dst_ctx.0.write().key2 = self.key_handle2();
        let tweak = self.get_iv().clone();
        dst_ctx.0.write().tweak.copy_from_slice(tweak.as_slice());
        Ok(CipherCtrlResult::CopySuccess)
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.key_handle1().is_some() && self.key_handle2().is_some()
    }

    #[cfg(test)]
    pub(super) fn key_refcount(&self) -> usize {
        if let (Some(_key1), Some(_key2)) = (self.key_handle1(), self.key_handle2()) {
            Arc::strong_count(&self.0)
        } else {
            0
        }
    }
}

#[derive(Debug)]
struct AesXtsInner {
    key1: Option<Arc<HsmKeyContainer>>,
    key2: Option<Arc<HsmKeyContainer>>,
    tweak: [u8; AES_XTS_TWEAK_LEN],
}

impl AesXtsInner {
    fn new() -> Self {
        Self {
            key1: None,
            key2: None,
            tweak: [0; AES_XTS_TWEAK_LEN],
        }
    }

    fn generate_key(&mut self) -> OpenSSLResult<()> {
        let key_size = AesKeySize::AesXtsBulk256;
        let hsm_key1 = HsmKeyContainer::aes_generate(key_size)?;
        let hsm_key2 = HsmKeyContainer::aes_generate(key_size)?;

        self.set_key(hsm_key1, hsm_key2);
        Ok(())
    }

    fn set_key(&mut self, hsm_key1: HsmKeyContainer, hsm_key2: HsmKeyContainer) {
        self.key1 = Some(Arc::new(hsm_key1));
        self.key2 = Some(Arc::new(hsm_key2));
    }

    fn aes_xts_cipher(&self, aes_mode: AesMode, data: Vec<u8>) -> OpenSSLResult<AesXtsResult> {
        let key1 = self.key1.clone();
        let key2 = self.key2.clone();

        if let (Some(key1), Some(key2)) = (key1, key2) {
            let tweak = self.tweak;
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .aes_xts_encrypt_decrypt(
                    aes_mode,
                    &key1.hsm_handle(),
                    &key2.hsm_handle(),
                    data.len(),
                    tweak,
                    data,
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::CipherCtxNotInitialized)
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl_rust::safeapi::engine::Engine;

    use super::*;
    use crate::load_engine;

    #[test]
    fn test_aes_xts_generate_key() {
        let _e = load_engine();
        let mut aes_xts = AesXts::new();
        aes_xts.generate_key().expect("Could not generate key");
        assert_eq!(aes_xts.key_refcount(), 1);
    }

    #[test]
    fn test_aes_xts_cipher() {
        let (_e, mut aes_xts) = xts_keygen_init();
        let data = vec![2; 1024 * 1024];
        let encrypted = aes_xts
            .cipher(data.clone(), true)
            .expect("Could not encrypt");
        assert!(data != encrypted);

        let decrypted = aes_xts
            .cipher(encrypted.clone(), false)
            .expect("Could not decrypt");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_aes_xts_cipher_data_corrupt() {
        let (_e, mut aes_xts) = xts_keygen_init();
        let data = vec![2; 4096];
        let mut encrypted = aes_xts
            .cipher(data.clone(), true)
            .expect("Could not encrypt");
        assert!(data != encrypted);

        // Corrupt the data
        encrypted[0] ^= 0x01;

        let decrypted = aes_xts
            .cipher(encrypted.clone(), false)
            .expect("Could not decrypt");
        assert_ne!(data, decrypted);
    }

    #[test]
    fn test_aes_xts_cipher_tweak_mismatch() {
        let (_e, mut aes_xts) = xts_keygen_init();
        let data = vec![2; 512];
        let encrypted = aes_xts
            .cipher(data.clone(), true)
            .expect("Could not encrypt");
        assert!(data != encrypted);

        // Corrupt the tweak
        let mut tweak = aes_xts.get_iv();
        tweak[0] ^= 0x01;
        aes_xts
            .set_iv(Some(tweak.clone()))
            .expect("Could not set IV");

        let decrypted = aes_xts
            .cipher(encrypted.clone(), false)
            .expect("Could not decrypt");
        assert_ne!(data, decrypted);
    }

    // Helper functions

    fn xts_keygen_init() -> (Engine, AesXts) {
        let e = load_engine();
        let mut aes_xts = AesXts::new();
        aes_xts.generate_key().expect("Could not generate key");
        let tweak = vec![1; AES_XTS_TWEAK_LEN];
        aes_xts
            .set_iv(Some(tweak.clone()))
            .expect("Could not init IV");
        assert_eq!(aes_xts.key_refcount(), 1);
        assert!(aes_xts.get_iv() == tweak);
        (e, aes_xts)
    }
}
