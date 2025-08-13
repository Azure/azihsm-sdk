// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_api::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::*;
use parking_lot::RwLock;

use crate::ciphers::init::*;
use crate::common::hsm_key::*;
use crate::engine_internal::*;

const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct AesGcm(Arc<RwLock<AesGcmInner>>);

impl AesGcm {
    pub(super) fn new() -> Self {
        Self(Arc::new(RwLock::new(AesGcmInner::new())))
    }

    pub(super) fn key_handle(&self) -> Option<Arc<HsmKeyContainer>> {
        self.0.read().key.clone()
    }

    // This function performs data encrypt/decrypt using AES GCM mode.
    pub(super) fn cipher(
        &mut self,
        input: Vec<u8>,
        is_aad: bool,
        enc: bool,
    ) -> OpenSSLResult<Option<Vec<u8>>> {
        if is_aad {
            self.set_aad(Some(input.clone()));
            return Ok(None);
        }

        let aes_mode = if enc {
            AesMode::Encrypt
        } else {
            AesMode::Decrypt
        };

        let result = self.0.write().aes_gcm_cipher(aes_mode, input)?;

        if let Some(tag) = result.tag {
            self.set_tag(Some(tag.to_vec()));
        }

        Ok(Some(result.data))
    }

    pub(super) fn generate_key(&mut self) -> OpenSSLResult<()> {
        self.0.write().generate_key()
    }

    pub(super) fn set_key(&mut self, hsm_key: HsmKeyContainer) {
        self.0.write().set_key(hsm_key);
    }

    pub(super) fn set_iv(&mut self, iv: Option<Vec<u8>>) -> OpenSSLResult<()> {
        if let Some(iv) = iv {
            if iv.len() != AES_GCM_IV_LEN {
                Err(OpenSSLError::IncorrectParam(
                    "IV Length".to_string(),
                    AES_GCM_IV_LEN.to_string(),
                    iv.len().to_string(),
                ))?;
            }
            self.0.write().iv.copy_from_slice(iv.as_slice());
        } else {
            self.0.write().iv.copy_from_slice(&[0; AES_GCM_IV_LEN]);
        }
        Ok(())
    }

    pub(super) fn get_iv(&self) -> Vec<u8> {
        let iv = self.0.read().iv;
        iv.to_vec()
    }

    pub(super) fn ctrl_copy(&mut self, dst_ctx: &mut AesGcm) -> OpenSSLResult<CipherCtrlResult> {
        dst_ctx.0.write().key = self.key_handle();
        let iv = self.get_iv();
        dst_ctx.0.write().iv.copy_from_slice(iv.as_slice());
        dst_ctx.0.write().aad = self.get_aad();
        dst_ctx.0.write().tag = self.get_tag();
        Ok(CipherCtrlResult::CopySuccess)
    }

    pub(super) fn ctrl(&mut self, ctrl_op: CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult> {
        match ctrl_op {
            CipherCtrlOp::CtxCopy(_ctx) => Ok(CipherCtrlResult::CopySuccess),
            CipherCtrlOp::CtrlInit => {
                self.ctrl_init();
                Ok(CipherCtrlResult::CtrlInitSuccess)
            }
            CipherCtrlOp::SetIvLen(len) => {
                self.ctrl_set_iv_len(len)?;
                Ok(CipherCtrlResult::SetIvLenSuccess)
            }
            CipherCtrlOp::GetIvLen => Ok(CipherCtrlResult::IvLen(AES_GCM_IV_LEN as i32)),
            CipherCtrlOp::SetTag(tag, len) => {
                self.ctrl_set_tag(tag, len)?;
                Ok(CipherCtrlResult::SetTagSuccess)
            }
            CipherCtrlOp::GetTag => Ok(CipherCtrlResult::Tag(self.get_tag().to_vec())),
            CipherCtrlOp::SetTls1Aad(aad) => {
                self.set_aad(Some(aad));
                Ok(CipherCtrlResult::SetTls1AadSuccess)
            }
            _ => Err(OpenSSLError::CipherUnsupportedOperation),
        }
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

    fn set_tag(&mut self, tag: Option<Vec<u8>>) {
        let mut tag_arr = [0; AES_GCM_TAG_LEN];
        if let Some(tag) = tag {
            tag_arr.copy_from_slice(tag.as_slice());
        }
        self.0.write().tag = tag_arr;
    }

    fn get_tag(&self) -> [u8; AES_GCM_TAG_LEN] {
        self.0.read().tag
    }

    fn set_aad(&mut self, aad: Option<Vec<u8>>) {
        self.0.write().aad = aad;
    }

    fn get_aad(&self) -> Option<Vec<u8>> {
        self.0.read().aad.clone()
    }

    fn ctrl_set_tag(&mut self, tag: Option<Vec<u8>>, len: i32) -> OpenSSLResult<()> {
        if len != AES_GCM_TAG_LEN as i32 {
            Err(OpenSSLError::IncorrectParam(
                "Tag Length".to_string(),
                AES_GCM_TAG_LEN.to_string(),
                len.to_string(),
            ))?;
        }
        self.set_tag(tag);
        Ok(())
    }

    fn ctrl_init(&mut self) {
        self.0.write().iv = [0; AES_GCM_IV_LEN];
        self.set_aad(None);
        self.set_tag(None);
    }

    fn ctrl_set_iv_len(&mut self, len: i32) -> OpenSSLResult<()> {
        if len != AES_GCM_IV_LEN as i32 {
            Err(OpenSSLError::IncorrectParam(
                "IV Length".to_string(),
                AES_GCM_IV_LEN.to_string(),
                len.to_string(),
            ))?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct AesGcmInner {
    key: Option<Arc<HsmKeyContainer>>,
    iv: [u8; AES_GCM_IV_LEN],
    aad: Option<Vec<u8>>,
    tag: [u8; AES_GCM_TAG_LEN],
}

impl AesGcmInner {
    fn new() -> Self {
        Self {
            key: None,
            iv: [0; AES_GCM_IV_LEN],
            aad: None,
            tag: [0; AES_GCM_TAG_LEN],
        }
    }

    fn generate_key(&mut self) -> OpenSSLResult<()> {
        let key_size = AesKeySize::AesBulk256;
        let hsm_key = HsmKeyContainer::aes_generate(key_size)?;
        self.set_key(hsm_key);
        Ok(())
    }

    fn set_key(&mut self, hsm_key: HsmKeyContainer) {
        self.key = Some(Arc::new(hsm_key));
    }

    fn aes_gcm_cipher(&self, aes_mode: AesMode, data: Vec<u8>) -> OpenSSLResult<AesGcmResult> {
        if let Some(key) = self.key.clone() {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            let tag = if aes_mode == AesMode::Encrypt {
                None
            } else {
                Some(self.tag)
            };
            app_session
                .aes_gcm_encrypt_decrypt(
                    &key.hsm_handle(),
                    aes_mode,
                    data,
                    self.iv,
                    self.aad.clone(),
                    tag,
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::CipherCtxNotInitialized)
        }
    }
}

#[cfg(test)]
mod test {
    use openssl_rust::safeapi::engine::Engine;

    use super::*;
    use crate::load_engine;

    #[test]
    fn test_aes_gcm_generate_key() {
        let _e = load_engine();
        let mut aes_gcm = AesGcm::new();
        aes_gcm.generate_key().expect("Could not generate key");
        assert_eq!(aes_gcm.key_refcount(), 1);
    }

    #[test]
    fn test_aes_gcm_ctrl_init() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let result = aes_gcm.ctrl(CipherCtrlOp::CtrlInit);
        assert!(result.is_ok());
        assert_eq!(aes_gcm.get_iv(), vec![0; AES_GCM_IV_LEN]);
        assert!(aes_gcm.get_aad().is_none());
        assert_eq!(aes_gcm.get_tag(), [0; AES_GCM_TAG_LEN]);
    }

    #[test]
    fn test_aes_gcm_ctrl_set_get_iv_len() {
        let (_e, mut aes_gcm) = gcm_keygen_init();

        let result = aes_gcm.ctrl(CipherCtrlOp::SetIvLen(AES_GCM_IV_LEN as i32));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CipherCtrlResult::SetIvLenSuccess);

        let result = aes_gcm.ctrl(CipherCtrlOp::SetIvLen(0));
        assert!(result.is_err(), "result {:?}", result);

        let result = aes_gcm.ctrl(CipherCtrlOp::GetIvLen);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            CipherCtrlResult::IvLen(AES_GCM_IV_LEN as i32)
        );
    }

    #[test]
    fn test_aes_gcm_ctrl_set_get_tag() {
        let (_e, mut aes_gcm) = gcm_keygen_init();

        let tag = vec![1; 16usize];
        let result = aes_gcm.ctrl(CipherCtrlOp::SetTag(
            Some(tag.clone()),
            AES_GCM_TAG_LEN as i32,
        ));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CipherCtrlResult::SetTagSuccess);
        let tag_set = aes_gcm.get_tag().to_vec();
        assert!(tag_set == tag);

        let result = aes_gcm.ctrl(CipherCtrlOp::GetTag);
        assert!(result.is_ok());
        if let CipherCtrlResult::Tag(ret_tag) = result.unwrap() {
            assert!(ret_tag == tag);
        } else {
            panic!("Could not get tag");
        }
    }

    #[test]
    fn test_aes_gcm_ctrl_set_aad() {
        let (_e, mut aes_gcm) = gcm_keygen_init();

        let aad = vec![1; 32usize];
        let result = aes_gcm.ctrl(CipherCtrlOp::SetTls1Aad(aad.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CipherCtrlResult::SetTls1AadSuccess);
        let set_aad = aes_gcm.get_aad().expect("Could not get aad");
        assert!(set_aad == aad);
    }

    #[test]
    fn test_aes_gcm_cipher_no_aad() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let aad = false;

        let data = vec![0; 1000];

        let result = aes_gcm
            .cipher(data.clone(), aad, true)
            .expect("Could not encrypt");
        let encrypted = result.expect("No encrypted data");

        let result = aes_gcm
            .cipher(encrypted.clone(), aad, false)
            .expect("Could not decrypt");
        let decrypted = result.expect("No decrypted data");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_aes_gcm_cipher() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let aad = vec![3; 32usize];

        // Set AAD
        let result = aes_gcm.cipher(aad.clone(), true, true);
        assert!(result.is_ok());

        let data = vec![0; 1000];

        let result = aes_gcm
            .cipher(data.clone(), false, true)
            .expect("Could not encrypt");
        let encrypted = result.expect("No encrypted data");

        // Set AAD
        let result = aes_gcm.cipher(aad.clone(), true, false);
        assert!(result.is_ok());

        let result = aes_gcm
            .cipher(encrypted.clone(), false, false)
            .expect("Could not decrypt");
        let decrypted = result.expect("No decrypted data");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_aes_gcm_cipher_data_zero_len_no_aad() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let aad = false;

        let data = Vec::new();
        let result = aes_gcm.cipher(data, aad, true);
        assert!(result.is_err(), "result {:?}", result);
    }

    #[test]
    fn test_aes_gcm_cipher_iv_mismatch_no_aad() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let aad = false;

        let data = vec![0; 1000];

        let result = aes_gcm
            .cipher(data.clone(), aad, true)
            .expect("Could not encrypt");
        let encrypted = result.expect("No encrypted data");

        let iv = vec![2; AES_GCM_IV_LEN];
        aes_gcm.set_iv(Some(iv.clone())).expect("Could not init IV");
        assert_eq!(aes_gcm.get_iv(), iv);

        let decrypted = aes_gcm.cipher(encrypted.clone(), aad, false);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_aes_gcm_corrupt_data_no_aad() {
        let (_e, mut aes_gcm) = gcm_keygen_init();
        let aad = false;

        let data = vec![0; 1000];

        let result = aes_gcm
            .cipher(data.clone(), aad, true)
            .expect("Could not encrypt");
        let mut encrypted = result.expect("No encrypted data");

        encrypted[0] ^= 0x01;
        let decrypted = aes_gcm.cipher(encrypted.clone(), aad, false);
        if decrypted.is_ok() {
            let decrypted = decrypted.unwrap().expect("No decrypted data");
            assert!(data != decrypted);
        }
    }

    fn gcm_keygen_init() -> (Engine, AesGcm) {
        let e = load_engine();
        let mut aes_gcm = AesGcm::new();
        aes_gcm.generate_key().expect("Could not generate key");
        let iv = vec![1; AES_GCM_IV_LEN];
        aes_gcm.set_iv(Some(iv.clone())).expect("Could not init IV");
        assert!(aes_gcm.get_iv() == iv);
        (e, aes_gcm)
    }
}
