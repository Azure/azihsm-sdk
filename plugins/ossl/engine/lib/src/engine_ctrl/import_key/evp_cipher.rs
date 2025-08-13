// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;

use api_interface::engine_ctrl::key_import::KeyImport;
use api_interface::AziHsmEngineCommand;
use api_interface::AziHsmKeyImport;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::evp_cipher::ctx::EvpCipherCtx;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;
use openssl_rust::EVP_CIPHER_CTX;

use crate::ciphers::callback::aes_import_key;

pub struct CmdEvpCipherKeyImport;

impl EngineCtrlCmdInfo for CmdEvpCipherKeyImport {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_IMPORT_EVP_CIPHER_CTX as c_uint
    }

    fn name(&self) -> &'static str {
        "evp_cipher_key_import"
    }

    fn desc(&self) -> &'static str {
        "Import an AES key into AZIHSM and update the given EVP_CIPHER_CTX"
    }

    fn flags(&self) -> c_uint {
        ENGINE_CTRL_FLAG_INTERNAL as c_uint
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn callback(
        &self,
        _: &Engine,
        _: c_uint,
        nid: c_long,
        import_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        let import_data = KeyImport::<EVP_CIPHER_CTX>::new(import_data as *mut AziHsmKeyImport)?;
        let wrapped_blob = import_data.wrapped_key_slice()?;
        let wrapped_blob2 = import_data.wrapped_key2_slice().ok();
        let digest_kind = import_data.digest_kind()?;
        let key_usage = import_data.key_usage()?;
        let key_availability = import_data.key_availability()?;
        let key_name = import_data.key_name()?;
        let ctx = EvpCipherCtx::new_from_ptr(import_data.mut_data_ptr());

        if nid as i32 != ctx.nid() {
            Err(OpenSSLError::InvalidKey)?;
        }

        aes_import_key(
            ctx,
            wrapped_blob,
            wrapped_blob2,
            digest_kind,
            key_usage,
            key_availability,
            key_name,
        )
    }
}
