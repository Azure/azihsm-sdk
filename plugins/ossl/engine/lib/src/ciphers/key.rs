// Copyright (C) Microsoft Corporation. All rights reserved.

use enum_as_inner::EnumAsInner;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::CipherCtrlOp;
use openssl_rust::safeapi::evp_cipher::callback::CipherCtrlResult;

use crate::cbc_mode;
use crate::ciphers::aes_cbc::AesCbc;
use crate::ciphers::aes_gcm::AesGcm;
use crate::ciphers::aes_xts::AesXts;
use crate::ciphers::init::AesType;
use crate::common::hsm_key::HsmKeyContainer;

#[derive(Clone, EnumAsInner, Debug)]
pub enum AesKey {
    Cbc(AesCbc),
    Gcm(AesGcm),
    Xts(AesXts),
}

macro_rules! new_key {
    ($aes_type:expr) => {
        match $aes_type {
            cbc_mode!() => AesKey::Cbc(AesCbc::new($aes_type)),
            AesType::Aes256Gcm => AesKey::Gcm(AesGcm::new()),
            AesType::Aes256Xts => AesKey::Xts(AesXts::new()),
        }
    };
}

macro_rules! aes_call {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            AesKey::Cbc(aes_cbc) => aes_cbc.$method($($args),*),
            AesKey::Gcm(aes_gcm) => aes_gcm.$method($($args),*),
            AesKey::Xts(aes_xts) => aes_xts.$method($($args),*),
        }
    };
}

impl AesKey {
    pub(crate) fn new(aes_type: AesType) -> AesKey {
        new_key!(aes_type)
    }

    pub(crate) fn from_derived_key(
        aes_type: AesType,
        key: HsmKeyContainer,
    ) -> OpenSSLResult<AesKey> {
        match aes_type {
            cbc_mode!() => {
                let mut aes_cbc = AesCbc::new(aes_type);
                aes_cbc.set_key(key);
                Ok(AesKey::Cbc(aes_cbc))
            }
            AesType::Aes256Gcm => {
                let mut aes_gcm = AesGcm::new();
                aes_gcm.set_key(key);
                Ok(AesKey::Gcm(aes_gcm))
            }
            _ => Err(OpenSSLError::CipherUnsupportedOperation),
        }
    }

    pub(super) fn from_imported_key(
        aes_type: AesType,
        key1: HsmKeyContainer,
        key2: Option<HsmKeyContainer>,
    ) -> OpenSSLResult<AesKey> {
        let mut aes_key_ctx = AesKey::new(aes_type);
        match &mut aes_key_ctx {
            AesKey::Cbc(aes_cbc) => aes_cbc.set_key(key1),
            AesKey::Gcm(aes_gcm) => aes_gcm.set_key(key1),
            AesKey::Xts(aes_xts) => {
                let key2 = key2.ok_or(OpenSSLError::InvalidKey)?;
                aes_xts.set_key(key1, key2);
            }
        };

        Ok(aes_key_ctx)
    }

    pub(crate) fn generate_key(&mut self) -> OpenSSLResult<()> {
        aes_call!(self, generate_key)
    }

    pub(super) fn set_iv(&mut self, iv: Option<Vec<u8>>) -> OpenSSLResult<()> {
        aes_call!(self, set_iv, iv)
    }

    pub(super) fn get_iv(&self) -> Vec<u8> {
        aes_call!(self, get_iv)
    }

    pub(super) fn is_initialized(&self) -> bool {
        aes_call!(self, is_initialized)
    }

    pub(super) fn ctrl(&mut self, ctrl_op: CipherCtrlOp) -> OpenSSLResult<CipherCtrlResult> {
        aes_call!(self, ctrl, ctrl_op)
    }

    pub(super) fn ctrl_copy(&mut self, dst_ctx: &mut AesKey) -> OpenSSLResult<CipherCtrlResult> {
        match self {
            AesKey::Cbc(aes_cbc) => {
                if let Some(dst) = dst_ctx.as_cbc_mut() {
                    aes_cbc.ctrl_copy(dst)
                } else {
                    Err(OpenSSLError::CipherUnsupportedOperation)
                }
            }
            AesKey::Gcm(aes_gcm) => {
                if let Some(dst) = dst_ctx.as_gcm_mut() {
                    aes_gcm.ctrl_copy(dst)
                } else {
                    Err(OpenSSLError::CipherUnsupportedOperation)
                }
            }
            AesKey::Xts(aes_xts) => {
                if let Some(dst) = dst_ctx.as_xts_mut() {
                    aes_xts.ctrl_copy(dst)
                } else {
                    Err(OpenSSLError::CipherUnsupportedOperation)
                }
            }
        }
    }

    pub(super) fn cbc_do_cipher(&mut self, input: Vec<u8>, enc: bool) -> OpenSSLResult<Vec<u8>> {
        match self {
            AesKey::Cbc(aes_cbc) => aes_cbc.cipher(input, enc),
            _ => Err(OpenSSLError::CipherUnsupportedOperation),
        }
    }

    pub(super) fn gcm_do_cipher(
        &mut self,
        input: Vec<u8>,
        aad: bool,
        enc: bool,
    ) -> OpenSSLResult<Option<Vec<u8>>> {
        match self {
            AesKey::Gcm(aes_gcm) => aes_gcm.cipher(input, aad, enc),
            _ => Err(OpenSSLError::CipherUnsupportedOperation),
        }
    }

    pub(super) fn xts_do_cipher(&mut self, input: Vec<u8>, enc: bool) -> OpenSSLResult<Vec<u8>> {
        match self {
            AesKey::Xts(aes_xts) => aes_xts.cipher(input, enc),
            _ => Err(OpenSSLError::CipherUnsupportedOperation),
        }
    }
}
