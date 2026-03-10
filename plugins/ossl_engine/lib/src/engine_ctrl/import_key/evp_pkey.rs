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
use openssl_rust::NID_X9_62_prime256v1 as NID_EC_P256;
use openssl_rust::NID_rsaEncryption as NID_RSA_ENCRYPTION;
use openssl_rust::NID_rsaSignature as NID_RSA_SIGNATURE;
use openssl_rust::NID_secp384r1 as NID_EC_P384;
use openssl_rust::NID_secp521r1 as NID_EC_P521;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;
use openssl_rust::EVP_PKEY_CTX;

use crate::pkey::ec::callback::pkey_ec_import_key;
use crate::pkey::rsa::callback::pkey_rsa_import_key;

pub struct CmdEvpPKeyRsaImport;

impl EngineCtrlCmdInfo for CmdEvpPKeyRsaImport {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_RSA as c_uint
    }

    fn name(&self) -> &'static str {
        "evp_pkey_rsa_key_import"
    }

    fn desc(&self) -> &'static str {
        "Unwrap an RSA key into AZIHSM and update the given EVP_PKEY_CTX"
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
        if import_data.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }

        let import_data = KeyImport::<EVP_PKEY_CTX>::new(import_data as *mut AziHsmKeyImport)?;
        match nid as c_uint {
            NID_RSA_ENCRYPTION | NID_RSA_SIGNATURE => {
                let wrapped_blob = import_data.wrapped_key_slice()?;
                let digest_kind = import_data.digest_kind()?;
                let key_usage = import_data.key_usage()?;
                let key_availability = import_data.key_availability()?;
                let key_name = import_data.key_name()?;
                let is_crt = import_data.is_crt();

                pkey_rsa_import_key(
                    import_data.mut_data_ptr(),
                    wrapped_blob,
                    digest_kind,
                    key_usage,
                    key_availability,
                    key_name.as_deref(),
                    is_crt,
                )
            }
            _ => Err(OpenSSLError::InvalidKey),
        }
    }
}

pub struct CmdEvpPKeyEcImport;

impl EngineCtrlCmdInfo for CmdEvpPKeyEcImport {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_IMPORT_EVP_PKEY_CTX_ECC as c_uint
    }

    fn name(&self) -> &'static str {
        "evp_pkey_ec_key_import"
    }

    fn desc(&self) -> &'static str {
        "Unwrap an EC key into AZIHSM and update the given EVP_PKEY_CTX"
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
        curve_name: c_long,
        import_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        if import_data.is_null() {
            Err(OpenSSLError::InvalidKey)?;
        }

        match curve_name as c_uint {
            NID_EC_P256 | NID_EC_P384 | NID_EC_P521 => {
                let import_data =
                    KeyImport::<EVP_PKEY_CTX>::new(import_data as *mut AziHsmKeyImport)?;
                let wrapped_blob = import_data.wrapped_key_slice()?;
                let digest_kind = import_data.digest_kind()?;
                let key_usage = import_data.key_usage()?;
                let key_availability = import_data.key_availability()?;
                let key_name = import_data.key_name()?;
                pkey_ec_import_key(
                    import_data.mut_data_ptr(),
                    curve_name as i32,
                    wrapped_blob,
                    digest_kind,
                    key_usage,
                    key_availability,
                    key_name.as_deref(),
                )
            }
            _ => Err(OpenSSLError::InvalidKey),
        }
    }
}
