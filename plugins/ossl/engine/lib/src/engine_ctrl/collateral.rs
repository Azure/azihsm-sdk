// Copyright (C) Microsoft Corporation. All rights reserved.

use std::any::Any;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;

use api_interface::engine_ctrl::collateral::Collateral;
use api_interface::AziHsmCollateral;
use api_interface::AziHsmEngineCommand;
use mcr_api::ManticoreCollateral;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmdInfo;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::ENGINE_CTRL_FLAG_INTERNAL;

use crate::engine_internal::*;

pub struct CmdGetCollateral;

impl EngineCtrlCmdInfo for CmdGetCollateral {
    fn num(&self) -> c_uint {
        AziHsmEngineCommand::AZIHSM_CMD_GET_COLLATERAL as c_uint
    }

    fn name(&self) -> &'static str {
        "get_azihsm_collateral"
    }

    fn desc(&self) -> &'static str {
        "Get AZIHSM device collateral (device certificate chain)"
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
        c_collateral_data: *mut c_void,
    ) -> OpenSSLResult<()> {
        let collateral_data = Collateral::new(c_collateral_data as *mut AziHsmCollateral)?;

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;
        let collateral = app_session.get_collateral().map_err(map_hsm_error)?;
        let cert_chain = match collateral {
            ManticoreCollateral::PhysicalManticore(device_cert_chain) => device_cert_chain,
            ManticoreCollateral::VirtualManticore {
                ak_cert,
                tee_cert_chain: _,
                tee_report: _,
            } => {
                // TODO: For now just get the Attest Key Certficate from the virtual manticore
                ak_cert
            }
        };

        collateral_data.set_collateral(&cert_chain)
    }
}
