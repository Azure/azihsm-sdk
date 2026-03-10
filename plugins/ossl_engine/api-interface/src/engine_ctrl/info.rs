// Copryright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;

use crate::AziHsmEngineInfo;

pub struct EngineInfo(*const AziHsmEngineInfo);

impl EngineInfo {
    pub fn new(info: *const AziHsmEngineInfo) -> Self {
        Self(info)
    }

    pub fn update_ptr(&self, ptr: *mut c_void) {
        let ptr = ptr as *mut *const AziHsmEngineInfo;
        unsafe {
            *ptr = self.0;
        }
    }
}
