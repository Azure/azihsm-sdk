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
use openssl_rust::NID_X9_62_prime256v1 as NID_X9_62_PRIME256V1;
use openssl_rust::NID_secp384r1 as NID_SECP384R1;
use openssl_rust::NID_secp521r1 as NID_SECP521R1;
use openssl_rust::EC_KEY;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;

use crate::ec::callback::ec_import_key;

pub struct CmdEcKeyImport;

impl EngineCtrlCmdInfo for CmdEcKeyImport {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_IMPORT_EC_KEY as c_uint
    }

    fn name(&self) -> &'static str {
        "ec_key_import"
    }

    fn desc(&self) -> &'static str {
        "Import an ECC key into AZIHSM and update the given EC_KEY"
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
        let nid = nid as c_uint;
        if nid != NID_X9_62_PRIME256V1 && nid != NID_SECP384R1 && nid != NID_SECP521R1 {
            Err(OpenSSLError::UnsupportedKeyType)?;
        }

        if import_data.is_null() {
            Err(OpenSSLError::InvalidKeyData)?;
        }

        let import_data = KeyImport::<EC_KEY>::new(import_data as *mut AziHsmKeyImport)?;
        let wrapped_blob = import_data.wrapped_key_slice()?;
        let digest_kind = import_data.digest_kind()?;
        let key_usage = import_data.key_usage()?;
        let key_availability = import_data.key_availability()?;
        let key_name = import_data.key_name()?;

        ec_import_key(
            import_data.mut_data_ptr(),
            wrapped_blob,
            digest_kind,
            key_usage,
            key_availability,
            key_name.as_deref(),
        )
    }
}
