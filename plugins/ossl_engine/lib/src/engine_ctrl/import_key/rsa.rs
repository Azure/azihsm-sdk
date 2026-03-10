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
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;
use openssl_rust::RSA;

use crate::rsa::callback::import_rsa_key;

pub struct CmdRsaImport;

impl EngineCtrlCmdInfo for CmdRsaImport {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_IMPORT_RSA as c_uint
    }

    fn name(&self) -> &'static str {
        "rsa_key_import"
    }

    fn desc(&self) -> &'static str {
        "Import an RSA key into AZIHSM and update the given RSA structure"
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
        _: c_long,
        import_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        if import_data.is_null() {
            Err(OpenSSLError::InvalidKeyData)?;
        }

        let import_data = KeyImport::<RSA>::new(import_data as *mut AziHsmKeyImport)?;
        let wrapped_blob = import_data.wrapped_key_slice()?;
        let digest_kind = import_data.digest_kind()?;
        let key_usage = import_data.key_usage()?;
        let key_availability = import_data.key_availability()?;
        let key_name = import_data.key_name()?;
        let is_crt = import_data.is_crt();

        import_rsa_key(
            import_data.mut_data_ptr(),
            wrapped_blob,
            digest_kind,
            key_usage,
            key_availability,
            key_name.as_deref(),
            is_crt,
        )
    }
}
