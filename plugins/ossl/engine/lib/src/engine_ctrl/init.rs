// Copyright (C) Microsoft Corporation. All rights reserved.

use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::engine_ctrl::EngineCtrlCmds;
use openssl_rust::safeapi::error::OpenSSLResult;

use crate::engine_ctrl::attest_key::ec_key::CmdAttestEcKey;
use crate::engine_ctrl::attest_key::evp_pkey::CmdAttestPKeyEcKey;
use crate::engine_ctrl::attest_key::evp_pkey::CmdAttestPKeyRsaKey;
use crate::engine_ctrl::attest_key::rsa_key::CmdAttestRsaKey;
use crate::engine_ctrl::attest_key::unwrap_key::CmdAttestBuiltinUnwrapKey;
use crate::engine_ctrl::collateral::CmdGetCollateral;
use crate::engine_ctrl::delete_key::CmdDeleteKey;
use crate::engine_ctrl::import_key::ec_key::CmdEcKeyImport;
use crate::engine_ctrl::import_key::evp_cipher::CmdEvpCipherKeyImport;
use crate::engine_ctrl::import_key::evp_pkey::CmdEvpPKeyEcImport;
use crate::engine_ctrl::import_key::evp_pkey::CmdEvpPKeyRsaImport;
use crate::engine_ctrl::import_key::rsa::CmdRsaImport;
use crate::engine_ctrl::info::CmdGetEngineInfo;
use crate::engine_ctrl::unwrap_key::get::CmdGetBuiltinUnwrapKey;
use crate::engine_ctrl::unwrap_key::get::CmdGetUnwrapKey;

pub fn init_engine_ctrl(engine: &Engine) -> OpenSSLResult<()> {
    let mut cmds = EngineCtrlCmds::new();
    cmds.push(Box::new(CmdAttestEcKey))
        .push(Box::new(CmdAttestPKeyEcKey))
        .push(Box::new(CmdAttestPKeyRsaKey))
        .push(Box::new(CmdAttestRsaKey))
        .push(Box::new(CmdAttestBuiltinUnwrapKey))
        .push(Box::new(CmdGetCollateral))
        .push(Box::new(CmdDeleteKey))
        .push(Box::new(CmdEcKeyImport))
        .push(Box::new(CmdEvpCipherKeyImport))
        .push(Box::new(CmdEvpPKeyEcImport))
        .push(Box::new(CmdEvpPKeyRsaImport))
        .push(Box::new(CmdRsaImport))
        .push(Box::new(CmdGetEngineInfo))
        .push(Box::new(CmdGetBuiltinUnwrapKey))
        .push(Box::new(CmdGetUnwrapKey))
        .finish();
    engine.set_engine_ctrl(cmds)?;
    Ok(())
}
