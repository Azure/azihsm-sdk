// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;

use api_interface::engine_ctrl::wrapping_key::UnwrappingKey;
use api_interface::AziHsmEngineCommand;
use api_interface::AziHsmUnwrappingKey;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;

use crate::engine_internal::*;

pub struct CmdGetUnwrapKey;

impl EngineCtrlCmdInfo for CmdGetUnwrapKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_GET_UNWRAP_KEY as c_uint
    }

    fn name(&self) -> &'static str {
        "get_unwrap_key"
    }

    fn desc(&self) -> &'static str {
        "Get the current unwrapping key"
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
        key_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        let key_data = UnwrappingKey::new(key_data as *mut AziHsmUnwrappingKey)?;

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;
        let unwrap_key = match hsm_ctx_lock.get_unwrap_key() {
            Some(key) => key.hsm_handle(),
            None => app_session.get_unwrapping_key().map_err(map_hsm_error)?,
        };
        key_data.set_key(
            &app_session
                .export_public_key(&unwrap_key)
                .map_err(map_hsm_error)?,
        );
        Ok(())
    }
}

pub struct CmdGetBuiltinUnwrapKey;

impl EngineCtrlCmdInfo for CmdGetBuiltinUnwrapKey {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_GET_BUILTIN_UNWRAP_KEY as c_uint
    }

    fn name(&self) -> &'static str {
        "get_builtin_unwrap_key"
    }

    fn desc(&self) -> &'static str {
        "Get the builtin unwrapping key"
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
        key_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        let key_data = UnwrappingKey::new(key_data as *mut AziHsmUnwrappingKey)?;

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;
        let unwrap_key = app_session.get_unwrapping_key().map_err(map_hsm_error)?;
        key_data.set_key(
            &app_session
                .export_public_key(&unwrap_key)
                .map_err(map_hsm_error)?,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr::addr_of_mut;

    use openssl_rust::safeapi::engine::Engine;
    use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;

    use super::*;
    use crate::bind_helper;

    fn create_engine() -> Engine {
        let engine = Engine::new_engine().expect("Could not make engine");
        let id = CString::new("azihsmengine").expect("Could not make id");
        bind_helper(&engine, id.as_ref()).expect("Could not bind engine");
        engine
    }

    #[test]
    fn test_get_builtin_unwrap_key() {
        let engine = create_engine();
        let cmd_get_builtin_unwrap_key = CmdGetBuiltinUnwrapKey;

        let mut unwrap_key = AziHsmUnwrappingKey::default();
        cmd_get_builtin_unwrap_key
            .callback(&engine, 0, 0, addr_of_mut!(unwrap_key) as *mut c_void)
            .unwrap();
        assert!(unwrap_key.key_len > 0);

        let mut unwrap_key_data = vec![0u8; unwrap_key.key_len];
        unwrap_key.key = unwrap_key_data.as_mut_ptr();
        cmd_get_builtin_unwrap_key
            .callback(&engine, 0, 0, addr_of_mut!(unwrap_key) as *mut c_void)
            .unwrap();

        assert!(vec![0u8; unwrap_key.key_len] != unwrap_key_data)
    }

    #[test]
    fn test_get_unwrap_key() {
        let engine = create_engine();
        let cmd_get_builtin_unwrap_key = CmdGetBuiltinUnwrapKey;
        let cmd_get_unwrap_key = CmdGetBuiltinUnwrapKey;

        // Get the current builtin wrapping key

        let mut builtin_unwrap_key = AziHsmUnwrappingKey::default();
        cmd_get_builtin_unwrap_key
            .callback(
                &engine,
                0,
                0,
                addr_of_mut!(builtin_unwrap_key) as *mut c_void,
            )
            .unwrap();
        assert!(builtin_unwrap_key.key_len > 0);

        let mut builtin_unwrap_key_data = vec![0u8; builtin_unwrap_key.key_len];
        builtin_unwrap_key.key = builtin_unwrap_key_data.as_mut_ptr();
        cmd_get_builtin_unwrap_key
            .callback(
                &engine,
                0,
                0,
                addr_of_mut!(builtin_unwrap_key) as *mut c_void,
            )
            .unwrap();

        // Get the current wrapping key

        let mut current_unwrap_key = AziHsmUnwrappingKey::default();
        cmd_get_unwrap_key
            .callback(
                &engine,
                0,
                0,
                addr_of_mut!(current_unwrap_key) as *mut c_void,
            )
            .unwrap();
        assert!(current_unwrap_key.key_len > 0);

        let mut current_unwrap_key_data = vec![0u8; current_unwrap_key.key_len];
        current_unwrap_key.key = current_unwrap_key_data.as_mut_ptr();
        cmd_get_unwrap_key
            .callback(
                &engine,
                0,
                0,
                addr_of_mut!(current_unwrap_key) as *mut c_void,
            )
            .unwrap();

        // Compare
        assert!(builtin_unwrap_key_data == current_unwrap_key_data);
    }
}
