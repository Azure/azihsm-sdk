// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::OnceLock;

use engine_common::*;
use mcr_api_resilient::*;
use openssl_rust::safeapi::callback::EngineCiphersResult;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_cipher::callback::*;
use openssl_rust::safeapi::evp_cipher::method::EvpCipherBuilder;
use openssl_rust::safeapi::evp_cipher::method::EvpCipherMethod;

use crate::ciphers::callback::*;
use crate::NID_aes_128_cbc;
use crate::NID_aes_192_cbc;
use crate::NID_aes_256_cbc;
#[cfg(feature = "gcm")]
use crate::NID_aes_256_gcm;
#[cfg(feature = "xts")]
use crate::NID_aes_256_xts;
use crate::EVP_CIPH_ALWAYS_CALL_INIT;
use crate::EVP_CIPH_CBC_MODE;
#[cfg(any(feature = "gcm", feature = "xts"))]
use crate::EVP_CIPH_CTRL_INIT;
use crate::EVP_CIPH_CUSTOM_COPY;
use crate::EVP_CIPH_CUSTOM_IV;
#[cfg(feature = "gcm")]
use crate::EVP_CIPH_CUSTOM_IV_LENGTH;
#[cfg(any(feature = "gcm", feature = "xts"))]
use crate::EVP_CIPH_FLAG_CUSTOM_CIPHER;
#[cfg(feature = "gcm")]
use crate::EVP_CIPH_GCM_MODE;
use crate::EVP_CIPH_RAND_KEY;
#[cfg(feature = "xts")]
use crate::EVP_CIPH_XTS_MODE;

static AES_128_CBC: OnceLock<EvpCipherMethod> = OnceLock::new();
static AES_192_CBC: OnceLock<EvpCipherMethod> = OnceLock::new();
static AES_256_CBC: OnceLock<EvpCipherMethod> = OnceLock::new();

#[cfg(feature = "gcm")]
static AES_256_GCM: OnceLock<EvpCipherMethod> = OnceLock::new();
#[cfg(feature = "xts")]
static AES_256_XTS: OnceLock<EvpCipherMethod> = OnceLock::new();

static AZIHSM_CIPHER_NIDS: OnceLock<Vec<i32>> = OnceLock::new();

const NID_AES_128_CBC: i32 = NID_aes_128_cbc as i32;
const NID_AES_192_CBC: i32 = NID_aes_192_cbc as i32;
const NID_AES_256_CBC: i32 = NID_aes_256_cbc as i32;

#[cfg(feature = "gcm")]
const NID_AES_256_GCM: i32 = NID_aes_256_gcm as i32;
#[cfg(feature = "xts")]
const NID_AES_256_XTS: i32 = NID_aes_256_xts as i32;

pub(super) const AES_BLOCK_SIZE: i32 = 16;

pub(super) const AES_COMMON_FLAGS: u64 = EVP_CIPH_ALWAYS_CALL_INIT as u64
    | EVP_CIPH_RAND_KEY as u64
    | EVP_CIPH_CUSTOM_COPY as u64
    | EVP_CIPH_CUSTOM_IV as u64;

pub(super) const AES_CBC_FLAGS: u64 = EVP_CIPH_CBC_MODE as u64 | AES_COMMON_FLAGS;

#[cfg(feature = "gcm")]
pub(super) const AES_GCM_FLAGS: u64 = EVP_CIPH_GCM_MODE as u64
    | EVP_CIPH_FLAG_CUSTOM_CIPHER as u64
    | EVP_CIPH_CTRL_INIT as u64
    | EVP_CIPH_CUSTOM_IV_LENGTH as u64
    | AES_COMMON_FLAGS;

#[cfg(feature = "xts")]
pub(super) const AES_XTS_FLAGS: u64 = EVP_CIPH_XTS_MODE as u64
    | EVP_CIPH_FLAG_CUSTOM_CIPHER as u64
    | EVP_CIPH_CTRL_INIT as u64
    | AES_COMMON_FLAGS;

pub(super) const AES_CBC_IV_LEN: usize = AES_BLOCK_SIZE as usize;
#[cfg(feature = "gcm")]
pub(super) const AES_GCM_IV_LEN: usize = 12;
#[cfg(feature = "xts")]
pub(super) const AES_XTS_TWEAK_LEN: usize = AES_BLOCK_SIZE as usize;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesType {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    #[cfg(feature = "gcm")]
    Aes256Gcm,
    #[cfg(feature = "xts")]
    Aes256Xts,
}

#[macro_export]
macro_rules! cbc_mode {
    () => {
        AesType::Aes128Cbc | AesType::Aes192Cbc | AesType::Aes256Cbc
    };
}

impl AesType {
    pub fn from_nid(nid: i32) -> OpenSSLResult<Self> {
        match nid {
            NID_AES_128_CBC => Ok(AesType::Aes128Cbc),
            NID_AES_192_CBC => Ok(AesType::Aes192Cbc),
            NID_AES_256_CBC => Ok(AesType::Aes256Cbc),
            #[cfg(feature = "gcm")]
            NID_AES_256_GCM => Ok(AesType::Aes256Gcm),
            #[cfg(feature = "xts")]
            NID_AES_256_XTS => Ok(AesType::Aes256Xts),

            _ => Err(OpenSSLError::CipherNotSupported(nid)),
        }
    }

    pub fn nid(&self) -> i32 {
        match self {
            AesType::Aes128Cbc => NID_AES_128_CBC,
            AesType::Aes192Cbc => NID_AES_192_CBC,
            AesType::Aes256Cbc => NID_AES_256_CBC,
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => NID_AES_256_GCM,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => NID_AES_256_XTS,
        }
    }

    pub fn hsm_key_size(&self) -> AesKeySize {
        match self {
            AesType::Aes128Cbc => AesKeySize::Aes128,
            AesType::Aes192Cbc => AesKeySize::Aes192,
            AesType::Aes256Cbc => AesKeySize::Aes256,
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => AesKeySize::AesGcmBulk256Unapproved,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => AesKeySize::AesXtsBulk256,
        }
    }

    pub fn hsm_key_type(&self) -> KeyType {
        match self {
            AesType::Aes128Cbc => KeyType::Aes128,
            AesType::Aes192Cbc => KeyType::Aes192,
            AesType::Aes256Cbc => KeyType::Aes256,
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => KeyType::AesGcmBulk256Unapproved,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => KeyType::AesXtsBulk256,
        }
    }

    pub fn hsm_key_class(&self) -> KeyClass {
        match self {
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => KeyClass::AesGcmBulkUnapproved,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => KeyClass::AesXtsBulk,
            _ => KeyClass::Aes,
        }
    }

    pub fn flags(&self) -> u64 {
        match self {
            cbc_mode!() => AES_CBC_FLAGS,
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => AES_GCM_FLAGS,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => AES_XTS_FLAGS,
        }
    }

    pub fn iv_len(&self) -> i32 {
        match self {
            cbc_mode!() => AES_CBC_IV_LEN as i32,
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => AES_GCM_IV_LEN as i32,
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => AES_XTS_TWEAK_LEN as i32,
        }
    }

    fn do_cipher_fn(&self) -> CipherFn {
        match self {
            cbc_mode!() => CipherFn::CipherAesCbc(aes_cbc_do_cipher_cb),
            #[cfg(feature = "gcm")]
            AesType::Aes256Gcm => CipherFn::CipherAesGcm(aes_gcm_do_cipher_cb),
            #[cfg(feature = "xts")]
            AesType::Aes256Xts => CipherFn::CipherAesXts(aes_xts_do_cipher_cb),
        }
    }

    pub fn get(&self) -> OpenSSLResult<EvpCipherMethod> {
        let nid = self.nid();
        let block_size = AES_BLOCK_SIZE;
        // Key length is always size of Handle for all ciphers
        let key_len = ENGINE_KEY_HANDLE_SIZE as i32;
        let iv_len = self.iv_len();
        let flags = self.flags();
        let do_cipher = self.do_cipher_fn();

        EvpCipherBuilder::new(nid, block_size, key_len)
            .set_iv_length(iv_len)
            .set_flags(flags)
            .set_impl_ctx_size(key_len as usize)
            .set_init(aes_init_cb)
            .set_ctrl(aes_ctrl_cb)
            .set_cleanup(aes_cleanup_cb)
            .set_do_cipher(do_cipher)
            .build()
    }
}

/// Get all Cipher NIDs supported by AZIHSM or Get cipher requested by NID.
pub fn engine_ciphers(_e: &Engine, nid: i32) -> OpenSSLResult<EngineCiphersResult> {
    if nid == 0 {
        let nids = AZIHSM_CIPHER_NIDS
            .get()
            .ok_or(OpenSSLError::NoCiphersAvailable)?;
        let num_nids = nids.len() as i32;
        return Ok(EngineCiphersResult::Nids((nids.as_slice(), num_nids)));
    }

    let aes_type = AesType::from_nid(nid)?;

    let cipher_method = match aes_type {
        AesType::Aes128Cbc => AES_128_CBC.get(),
        AesType::Aes192Cbc => AES_192_CBC.get(),
        AesType::Aes256Cbc => AES_256_CBC.get(),
        #[cfg(feature = "gcm")]
        AesType::Aes256Gcm => AES_256_GCM.get(),
        #[cfg(feature = "xts")]
        AesType::Aes256Xts => AES_256_XTS.get(),
    };

    match cipher_method {
        Some(cipher) => Ok(EngineCiphersResult::Cipher(cipher)),
        None => Err(OpenSSLError::CipherNotInitialized),
    }
}

/// Initialize the ciphers supported by the AZIHSM engine
pub fn init_ciphers(engine: &Engine) -> OpenSSLResult<()> {
    engine.set_ciphers(engine_ciphers)?;

    let aes_128_cbc = AesType::Aes128Cbc.get()?;
    AES_128_CBC.get_or_init(|| aes_128_cbc);

    let aes_192_cbc = AesType::Aes192Cbc.get()?;
    AES_192_CBC.get_or_init(|| aes_192_cbc);

    let aes_256_cbc = AesType::Aes256Cbc.get()?;
    AES_256_CBC.get_or_init(|| aes_256_cbc);

    #[cfg(feature = "gcm")]
    {
        let aes_256_gcm = AesType::Aes256Gcm.get()?;
        AES_256_GCM.get_or_init(|| aes_256_gcm);
    }

    #[cfg(feature = "xts")]
    {
        let aes_256_xts = AesType::Aes256Xts.get()?;
        AES_256_XTS.get_or_init(|| aes_256_xts);
    }

    AZIHSM_CIPHER_NIDS.get_or_init(|| {
        #[allow(unused_mut)]
        let mut nids = vec![
            AesType::Aes128Cbc.nid(),
            AesType::Aes192Cbc.nid(),
            AesType::Aes256Cbc.nid(),
        ];
        #[cfg(feature = "gcm")]
        nids.push(AesType::Aes256Gcm.nid());
        #[cfg(feature = "xts")]
        nids.push(AesType::Aes256Xts.nid());
        nids
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_engine;

    #[test]
    fn test_ciphers_init() {
        let engine = load_engine();
        assert!(init_ciphers(&engine).is_ok());
    }

    #[test]
    fn test_engine_ciphers_get_nids() {
        let engine = load_engine();
        let result = engine_ciphers(&engine, 0);
        assert!(result.is_ok());
        #[allow(unused_mut)]
        let mut expected_num_nids = 3;
        #[cfg(feature = "gcm")]
        {
            expected_num_nids += 1;
        }
        #[cfg(feature = "xts")]
        {
            expected_num_nids += 1;
        }

        match result.unwrap() {
            EngineCiphersResult::Nids((nids, num_nids)) => {
                assert_eq!(num_nids, expected_num_nids);
                let mut index = 0;
                assert_eq!(nids[index], AesType::Aes128Cbc.nid());
                index += 1;
                assert_eq!(nids[index], AesType::Aes192Cbc.nid());
                index += 1;
                assert_eq!(nids[index], AesType::Aes256Cbc.nid());
                #[cfg(feature = "gcm")]
                {
                    index += 1;
                    assert_eq!(nids[index], AesType::Aes256Gcm.nid());
                }
                #[cfg(feature = "xts")]
                {
                    index += 1;
                    assert_eq!(nids[index], AesType::Aes256Xts.nid());
                }
            }
            _ => panic!("Expected EngineCiphersResult::Nids"),
        }
    }

    #[test]
    fn test_get_cipher_aes_128_cbc() {
        let engine = load_engine();
        let result = engine_ciphers(&engine, AesType::Aes128Cbc.nid());
        assert!(result.is_ok());
        match result.unwrap() {
            EngineCiphersResult::Cipher(cipher) => {
                assert_eq!(*cipher, *AES_128_CBC.get().unwrap());
                assert_eq!(cipher.nid(), AesType::Aes128Cbc.nid());
                assert_eq!(cipher.block_size(), AES_BLOCK_SIZE);
                assert_eq!(cipher.key_len(), ENGINE_KEY_HANDLE_SIZE as i32);
                assert_eq!(cipher.iv_len(), AES_BLOCK_SIZE);
                assert_eq!(cipher.flags(), AesType::Aes128Cbc.flags());
            }
            _ => panic!("Expected EngineCiphersResult::Cipher"),
        }
    }

    #[test]
    fn test_get_cipher_aes_192_cbc() {
        let engine = load_engine();

        let result = engine_ciphers(&engine, AesType::Aes192Cbc.nid());
        assert!(result.is_ok());
        match result.unwrap() {
            EngineCiphersResult::Cipher(cipher) => {
                assert_eq!(*cipher, *AES_192_CBC.get().unwrap());
                assert_eq!(cipher.nid(), AesType::Aes192Cbc.nid());
                assert_eq!(cipher.block_size(), AES_BLOCK_SIZE);
                assert_eq!(cipher.key_len(), ENGINE_KEY_HANDLE_SIZE as i32);
                assert_eq!(cipher.iv_len(), AES_BLOCK_SIZE);
                assert_eq!(cipher.flags(), AesType::Aes192Cbc.flags());
            }
            _ => panic!("Expected EngineCiphersResult::Cipher"),
        }
    }

    #[test]
    fn test_get_cipher_aes_256_cbc() {
        let engine = load_engine();

        let result = engine_ciphers(&engine, AesType::Aes256Cbc.nid());
        assert!(result.is_ok());
        match result.unwrap() {
            EngineCiphersResult::Cipher(cipher) => {
                assert_eq!(*cipher, *AES_256_CBC.get().unwrap());
                assert_eq!(cipher.nid(), AesType::Aes256Cbc.nid());
                assert_eq!(cipher.block_size(), AES_BLOCK_SIZE);
                assert_eq!(cipher.key_len(), ENGINE_KEY_HANDLE_SIZE as i32);
                assert_eq!(cipher.iv_len(), AES_BLOCK_SIZE);
                assert_eq!(cipher.flags(), AesType::Aes256Cbc.flags());
            }
            _ => panic!("Expected EngineCiphersResult::Cipher"),
        }
    }

    #[cfg(feature = "gcm")]
    #[test]
    fn test_get_cipher_aes_256_gcm() {
        let engine = load_engine();

        let result = engine_ciphers(&engine, AesType::Aes256Gcm.nid());
        assert!(result.is_ok());
        match result.unwrap() {
            EngineCiphersResult::Cipher(cipher) => {
                assert_eq!(*cipher, *AES_256_GCM.get().unwrap());
                assert_eq!(cipher.nid(), AesType::Aes256Gcm.nid());
                assert_eq!(cipher.block_size(), AES_BLOCK_SIZE);
                assert_eq!(cipher.key_len(), ENGINE_KEY_HANDLE_SIZE as i32);
                assert_eq!(cipher.iv_len(), AES_GCM_IV_LEN as i32);
                assert_eq!(cipher.flags(), AesType::Aes256Gcm.flags());
            }
            _ => panic!("Expected EngineCiphersResult::Cipher"),
        }
    }

    #[cfg(feature = "xts")]
    #[test]
    fn test_get_cipher_aes_256_xts() {
        let engine = load_engine();

        let result = engine_ciphers(&engine, AesType::Aes256Xts.nid());
        assert!(result.is_ok());
        match result.unwrap() {
            EngineCiphersResult::Cipher(cipher) => {
                assert_eq!(*cipher, *AES_256_XTS.get().unwrap());
                assert_eq!(cipher.nid(), AesType::Aes256Xts.nid());
                assert_eq!(cipher.block_size(), AES_BLOCK_SIZE);
                assert_eq!(cipher.key_len(), ENGINE_KEY_HANDLE_SIZE as i32);
                assert_eq!(cipher.iv_len(), AES_XTS_TWEAK_LEN as i32);
                assert_eq!(cipher.flags(), AesType::Aes256Xts.flags());
            }
            _ => panic!("Expected EngineCiphersResult::Cipher"),
        }
    }

    #[test]
    fn test_get_cipher_invalid_nid() {
        let engine = load_engine();

        let result = engine_ciphers(&engine, -1);
        assert!(result.is_err());
    }
}
