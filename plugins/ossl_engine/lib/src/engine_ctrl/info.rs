// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_ulong;
use std::ffi::c_ulonglong;
use std::ffi::c_void;
use std::ptr::addr_of;
use std::sync::OnceLock;

use api_interface::engine_ctrl::info::EngineInfo;
use api_interface::AziHsmEngineCommand;
use api_interface::AziHsmEngineFlags;
use api_interface::AziHsmEngineInfo;
use api_interface::AziHsmEngineVersion;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::util::get_openssl_version;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;
use openssl_rust::OPENSSL_VER;

static ENGINE_INFO: OnceLock<AziHsmEngineInfo> = OnceLock::new();

fn get_engine_info() -> &'static AziHsmEngineInfo {
    ENGINE_INFO.get_or_init(|| {
        let mut flags = AziHsmEngineFlags(0);

        if cfg!(feature = "mock") {
            flags |= AziHsmEngineFlags::AZIHSM_FEATURE_MOCK;
        }

        let (major, minor, patch) = get_openssl_version();
        let ossl_version = AziHsmEngineVersion {
            version: OPENSSL_VER as c_ulong,
            major,
            minor,
            patch,
        };

        AziHsmEngineInfo {
            flags: flags.0 as c_ulonglong,
            ossl_version,
        }
    })
}

pub struct CmdGetEngineInfo;

impl EngineCtrlCmdInfo for CmdGetEngineInfo {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_ENGINE_INFO as c_uint
    }

    fn name(&self) -> &'static str {
        "get_engine_info"
    }

    fn desc(&self) -> &'static str {
        "Get engine information"
    }

    fn flags(&self) -> c_uint {
        ENGINE_CTRL_FLAG_INTERNAL as c_uint
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn callback(&self, _: &Engine, _: c_uint, _: c_long, ret: *mut c_void) -> OpenSSLResult<()> {
        let info = EngineInfo::new(addr_of!(*get_engine_info()));
        info.update_ptr(ret);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr::addr_of_mut;
    use std::ptr::null;

    use api_interface::AziHsmEngineInfo;
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
    fn test_get_info() {
        let engine = create_engine();
        let mut info_ptr: *const AziHsmEngineInfo = null();
        let info_cmd = CmdGetEngineInfo;
        info_cmd
            .callback(&engine, 0, 0, addr_of_mut!(info_ptr) as *mut c_void)
            .unwrap();
        assert!(!info_ptr.is_null())
    }
}
