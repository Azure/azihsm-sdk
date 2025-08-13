// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;

use api_interface::engine_ctrl::attest_key::AttestKey;
use api_interface::AziHsmAttestKey;
use api_interface::AziHsmEngineCommand;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::*;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;
use openssl_rust::EVP_PKEY;

use crate::engine_internal::*;

pub struct CmdAttestBuiltinUnwrapKey;

impl EngineCtrlCmdInfo for CmdAttestBuiltinUnwrapKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_ATTEST_BUILTIN_UNWRAP_KEY as c_uint
    }

    fn name(&self) -> &'static str {
        "builtin_unwrap_key_attest"
    }

    fn desc(&self) -> &'static str {
        "Attest the built-in unwrap key"
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
        c_attest_key_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        if c_attest_key_data.is_null() {
            Err(OpenSSLError::AttestKeyError)?;
        }

        let mut attest_key_data: AttestKey<EVP_PKEY> =
            AttestKey::new(c_attest_key_data as *mut AziHsmAttestKey)?;

        let report_data = attest_key_data.report_data()?;
        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;
        let unwrap_key = app_session.get_unwrapping_key().map_err(map_hsm_error)?;

        let claim = app_session
            .attest_key(&unwrap_key, report_data)
            .map_err(map_hsm_error)?;

        attest_key_data.set_claim(claim.as_slice())
    }
}
