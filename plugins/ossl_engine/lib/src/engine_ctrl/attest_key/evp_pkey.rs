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

use crate::pkey::ec::callback::pkey_ec_attest_key;
use crate::pkey::rsa::callback::pkey_rsa_attest_key;

pub struct CmdAttestPKeyEcKey;

impl EngineCtrlCmdInfo for CmdAttestPKeyEcKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_ATTEST_EVP_PKEY_ECC as c_uint
    }

    fn name(&self) -> &'static str {
        "evp_pkey_ec_attest"
    }

    fn desc(&self) -> &'static str {
        "Attest an ECC key in EVP_PKEY format"
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
        let key = attest_key_data.key();

        let claim = pkey_ec_attest_key(key, report_data)?;

        attest_key_data.set_claim(claim.as_slice())
    }
}

pub struct CmdAttestPKeyRsaKey;

impl EngineCtrlCmdInfo for CmdAttestPKeyRsaKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_ATTEST_EVP_PKEY_RSA as c_uint
    }

    fn name(&self) -> &'static str {
        "evp_pkey_rsa_attest"
    }

    fn desc(&self) -> &'static str {
        "Attest an RSA key in EVP_PKEY format"
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
        let key = attest_key_data.key();

        let claim = pkey_rsa_attest_key(key, report_data)?;

        attest_key_data.set_claim(claim.as_slice())
    }
}
