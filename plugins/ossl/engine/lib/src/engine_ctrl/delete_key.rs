// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_char;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;

use api_interface::engine_ctrl::open_key::name_from_ptr;
use api_interface::AziHsmEngineCommand;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::ENGINE_CTRL_FLAG_STRING;

use crate::engine_internal::*;

pub struct CmdDeleteKey;

impl EngineCtrlCmdInfo for CmdDeleteKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_DELETE_KEY as c_uint
    }

    fn name(&self) -> &'static str {
        "delete_key"
    }

    fn desc(&self) -> &'static str {
        "Delete AZIHSM key by name"
    }

    fn flags(&self) -> c_uint {
        ENGINE_CTRL_FLAG_STRING as c_uint
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn callback(&self, _: &Engine, _: c_uint, _: c_long, name: *mut c_void) -> OpenSSLResult<()> {
        let name = name_from_ptr(name as *const c_char)?;

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;

        let key_handle = app_session.open_key(&name).map_err(map_hsm_error)?;
        app_session.delete_key(&key_handle).map_err(map_hsm_error)
    }
}
