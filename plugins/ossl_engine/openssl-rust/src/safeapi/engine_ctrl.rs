// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_char;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::ffi::CString;
use std::ptr::null;
use std::slice::Iter;
use std::sync::OnceLock;

use crate::openssl_log;
use crate::safeapi::engine::Engine;
use crate::safeapi::error::*;
use crate::ENGINE_CMD_DEFN;

pub(crate) static ENGINE_CTRL_DEFNS: OnceLock<EngineCmdDefnContainer> = OnceLock::new();
pub(crate) static ENGINE_CTRL_CMDS: OnceLock<EngineCtrlCmds> = OnceLock::new();

pub struct EngineCmdDefn {
    num: c_uint,
    name: CString,
    desc: CString,
    flags: c_uint,
}

impl EngineCmdDefn {
    pub(crate) fn new(num: c_uint, name: &str, desc: &str, flags: c_uint) -> OpenSSLResult<Self> {
        let name = CString::new(name).map_err(OpenSSLError::CStringNulError)?;
        let desc = CString::new(desc).map_err(OpenSSLError::CStringNulError)?;
        Ok(Self {
            num,
            name,
            desc,
            flags,
        })
    }

    /// Turn this EngineCmdDefn to a ENGINE_CMD_DEFN, consuming it
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn to_engine_cmd_defn(self) -> ENGINE_CMD_DEFN {
        ENGINE_CMD_DEFN {
            cmd_num: self.num,
            cmd_name: self.name.into_raw(),
            cmd_desc: self.desc.into_raw(),
            cmd_flags: self.flags,
        }
    }
}

pub(crate) struct EngineCmdDefnContainer(pub Vec<ENGINE_CMD_DEFN>);

unsafe impl Send for EngineCmdDefnContainer {}
unsafe impl Sync for EngineCmdDefnContainer {}

impl EngineCmdDefnContainer {
    fn new(defns: Vec<ENGINE_CMD_DEFN>) -> Self {
        Self(defns)
    }

    fn as_ptr(&self) -> *const ENGINE_CMD_DEFN {
        self.0.as_ptr()
    }
}

impl Drop for EngineCmdDefnContainer {
    /// Convert passed strings back into CStrings for dropping
    fn drop(&mut self) {
        for item in self.0.iter() {
            let _ = unsafe { CString::from_raw(item.cmd_name as *mut c_char) };
            let _ = unsafe { CString::from_raw(item.cmd_desc as *mut c_char) };
        }
    }
}

/// Initialize ctrl defns
/// NOTE: this function must be called after init_cmds()
pub(crate) fn init_defns() -> OpenSSLResult<*const ENGINE_CMD_DEFN> {
    match ENGINE_CTRL_CMDS.get() {
        Some(cmds) => match ENGINE_CTRL_DEFNS.get() {
            Some(defns) => Ok(defns.as_ptr()),
            None => {
                let defns = cmds.build_cmd_defns()?;
                Ok(ENGINE_CTRL_DEFNS.get_or_init(|| defns).as_ptr())
            }
        },
        None => {
            openssl_log!(
                OpenSSLError::EngineInitError("ENGINE_CTRL_CMDS not set".to_string(),),
                tracing::Level::ERROR,
                "ENGINE_CTRL_CMDS callback not set",
            );
            Err(OpenSSLError::EngineInitError(
                "ENGINE_CTRL_CMDS not set".to_string(),
            ))
        }
    }
}

pub trait EngineCtrlCmdInfo {
    fn num(&self) -> c_uint;
    fn name(&self) -> &'static str;
    fn desc(&self) -> &'static str;
    fn flags(&self) -> c_uint;
    fn as_any(&self) -> &dyn Any;
    fn callback(
        &self,
        engine: &Engine,
        num: c_uint,
        i: c_long,
        p: *mut c_void,
    ) -> OpenSSLResult<()>;
}

pub struct EngineCtrlCmds(Vec<Box<dyn EngineCtrlCmdInfo>>);

unsafe impl Send for EngineCtrlCmds {}
unsafe impl Sync for EngineCtrlCmds {}

impl Default for EngineCtrlCmds {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineCtrlCmds {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, data: Box<dyn EngineCtrlCmdInfo>) -> &mut Self {
        self.0.push(data);
        self
    }

    pub fn finish(&mut self) -> &mut Self {
        self.0.sort_by_key(|a| a.num());
        self
    }

    pub fn iter(&self) -> Iter<'_, Box<dyn EngineCtrlCmdInfo>> {
        self.0.iter()
    }

    pub(crate) fn build_cmd_defns(&self) -> OpenSSLResult<EngineCmdDefnContainer> {
        let mut defns = Vec::with_capacity(self.0.len());
        for item in self.0.iter() {
            let defn = EngineCmdDefn::new(item.num(), item.name(), item.desc(), item.flags())?;
            defns.push(defn.to_engine_cmd_defn())
        }

        // Empty item at the end for the C API
        defns.push(ENGINE_CMD_DEFN {
            cmd_num: 0,
            cmd_name: null(),
            cmd_desc: null(),
            cmd_flags: 0,
        });

        Ok(EngineCmdDefnContainer::new(defns))
    }
}
