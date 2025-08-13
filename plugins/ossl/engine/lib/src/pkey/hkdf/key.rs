// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use engine_common::handle_table::Handle;
use mcr_api::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_pkey::callback::hkdf::*;
use parking_lot::RwLock;

use crate::cbc_mode;
use crate::ciphers::init::AesType;
use crate::common::hsm_key::HsmKeyContainer;
use crate::engine_internal::*;
use crate::NID_sha256 as NID_SHA256;
use crate::NID_sha384 as NID_SHA384;
use crate::NID_sha512 as NID_SHA512;

const HKDF_MAX_INFO_LEN: usize = 16;
const HKDF_MAX_SALT_LEN: usize = 64;
const KBKDF_MAX_LABEL_SIZE: usize = 16;

#[derive(Debug, Clone)]
pub struct HkdfData(Arc<RwLock<HkdfInner>>);

impl Default for HkdfData {
    fn default() -> Self {
        Self::new()
    }
}

impl HkdfData {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HkdfInner::new())))
    }

    pub fn init(&self) {
        self.0.write().init()
    }

    pub fn secret_handle(&self) -> Option<Handle> {
        self.0.read().secret_handle
    }

    pub fn set_secret_handle(&self, secret_handle: Handle) {
        self.0.write().secret_handle = Some(secret_handle);
    }

    pub fn set_md(&self, md: i32) -> OpenSSLResult<()> {
        let md_type = match md as u32 {
            NID_SHA256 => MdType::Sha256,
            NID_SHA384 => MdType::Sha384,
            NID_SHA512 => MdType::Sha512,
            _ => Err(OpenSSLError::IncorrectParam(
                "Invalid digest type".to_string(),
                "SHA256, SHA384, SHA512".to_string(),
                md.to_string(),
            ))?,
        };
        self.0.write().md_type = Some(md_type);
        Ok(())
    }

    pub fn md(&self) -> Option<MdType> {
        self.0.read().md_type.clone()
    }

    pub fn set_mode(&self, mode: i32) -> OpenSSLResult<()> {
        if mode != EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND {
            Err(OpenSSLError::IncorrectParam(
                "Invalid mode".to_string(),
                "0".to_string(),
                mode.to_string(),
            ))?;
        }
        Ok(())
    }

    pub fn mode(&self) -> i32 {
        self.0.read().mode
    }

    pub fn set_salt(&self, salt: Vec<u8>) -> OpenSSLResult<()> {
        let max_salt_len = if self.is_kbkdf() {
            KBKDF_MAX_LABEL_SIZE
        } else {
            HKDF_MAX_SALT_LEN
        };

        if salt.len() > max_salt_len {
            Err(OpenSSLError::IncorrectParam(
                "Salt max length exceeded".to_string(),
                max_salt_len.to_string(),
                salt.len().to_string(),
            ))?;
        }

        self.0.write().salt = Some(salt);
        Ok(())
    }

    pub fn add_info(&self, new_info: Vec<u8>) -> OpenSSLResult<()> {
        let mut info = self.0.read().info.clone().unwrap_or_default();
        let new_len = new_info.len() + info.len();

        if new_len > HKDF_MAX_INFO_LEN {
            Err(OpenSSLError::IncorrectParam(
                "info max length exceeded".to_string(),
                HKDF_MAX_INFO_LEN.to_string(),
                new_len.to_string(),
            ))?;
        }

        info.extend_from_slice(new_info.as_slice());
        self.0.write().info = Some(info);
        Ok(())
    }

    pub fn info(&self) -> Option<Vec<u8>> {
        self.0.read().info.clone()
    }

    pub fn set_key_type(&self, aes_type: AesType) -> OpenSSLResult<()> {
        match aes_type {
            cbc_mode!() | AesType::Aes256Gcm => {
                self.0.write().key_type = Some(aes_type);
                Ok(())
            }
            _ => Err(OpenSSLError::HkdfUnsupportedKeyType(aes_type.nid()))?,
        }
    }

    pub fn key_type(&self) -> Option<AesType> {
        self.0.read().key_type
    }

    pub fn set_kbkdf(&self) -> OpenSSLResult<()> {
        self.0.write().kbkdf = true;
        Ok(())
    }

    pub fn is_kbkdf(&self) -> bool {
        self.0.read().kbkdf
    }

    pub fn derive(
        &self,
        hsm_key: Arc<HsmKeyContainer>,
        out_len: usize,
    ) -> OpenSSLResult<(HsmKeyContainer, AesType)> {
        let key_type = self.0.read().key_type;
        let aes_type = key_type.map_or(len_to_keytype(out_len)?, |key_type| key_type);
        let target_key_type = aes_type.hsm_key_type();

        let key_properties = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::Session,
        };
        let key_handle = self
            .0
            .write()
            .derive(hsm_key, target_key_type, key_properties)?;
        Ok((key_handle, aes_type))
    }
}

fn len_to_keytype(out_len: usize) -> OpenSSLResult<AesType> {
    match out_len {
        16 => Ok(AesType::Aes128Cbc),
        24 => Ok(AesType::Aes192Cbc),
        32 => Ok(AesType::Aes256Cbc),
        _ => Err(OpenSSLError::IncorrectParam(
            "Invalid output length".to_string(),
            "16, 24, 32".to_string(),
            out_len.to_string(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MdType {
    Sha256,
    Sha384,
    Sha512,
}

impl MdType {
    pub fn to_digest_kind(&self) -> DigestKind {
        match self {
            MdType::Sha256 => DigestKind::Sha256,
            MdType::Sha384 => DigestKind::Sha384,
            MdType::Sha512 => DigestKind::Sha512,
        }
    }

    pub fn to_secret_key_type(&self) -> KeyType {
        match self {
            MdType::Sha256 => KeyType::Secret256,
            MdType::Sha384 => KeyType::Secret384,
            MdType::Sha512 => KeyType::Secret521,
        }
    }
}

#[derive(Debug, Clone)]
struct HkdfInner {
    secret_handle: Option<Handle>,
    md_type: Option<MdType>,
    mode: i32,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    key_type: Option<AesType>,
    kbkdf: bool,
}

impl HkdfInner {
    fn new() -> Self {
        Self {
            secret_handle: None,
            md_type: None,
            mode: EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
            salt: None,
            info: None,
            key_type: None,
            kbkdf: false,
        }
    }

    fn init(&mut self) {
        self.md_type = None;
        self.salt = None;
        self.info = None;
        self.mode = EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND;
        self.key_type = None;
        self.kbkdf = false;
    }

    fn info(&self) -> Option<&[u8]> {
        self.info.as_deref()
    }

    fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    fn label(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    fn derive(
        &self,
        hsm_key: Arc<HsmKeyContainer>,
        key_type: KeyType,
        key_properties: KeyProperties,
    ) -> OpenSSLResult<HsmKeyContainer> {
        let digest_kind = if let Some(md_type) = &self.md_type {
            md_type.to_digest_kind()
        } else {
            Err(OpenSSLError::HkdfMissingDigest)?
        };

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;

        let hsm_key = if self.kbkdf {
            let params = KbkdfDeriveParameters {
                hash_algorithm: digest_kind,
                label: self.label(),
                context: self.info(),
            };

            app_session
                .kbkdf_counter_hmac_derive(
                    &hsm_key.hsm_handle(),
                    params,
                    None,
                    key_type,
                    key_properties,
                )
                .map_err(map_hsm_error)?
        } else {
            let params = HkdfDeriveParameters {
                hash_algorithm: digest_kind,
                salt: self.salt(),
                info: self.info(),
            };

            app_session
                .hkdf_derive(
                    &hsm_key.hsm_handle(),
                    params,
                    None,
                    key_type,
                    key_properties,
                )
                .map_err(map_hsm_error)?
        };
        Ok(HsmKeyContainer::new(hsm_key, true))
    }
}
