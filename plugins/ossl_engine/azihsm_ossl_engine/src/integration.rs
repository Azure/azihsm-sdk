// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration-test helpers for the engine crate.
//!
//! Gated behind the `integration` feature; not part of the production engine —
//! the cdylib OpenSSL loads is built without this feature.

use azihsm_api::HsmEccCurve;
use azihsm_api::HsmEccKeyGenAlgo;
use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyCommonProps;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_ossl_engine_core::error::EngineError;
use azihsm_ossl_engine_core::error::EngineResult;

use crate::context::EngineData;

/// Open the HSM from the ambient `AZIHSM_*` environment, generate a persistent
/// EC key on `curve`, and return its masked blob — the form the loader
/// consumes. Reuses the engine's real open path so a generated blob and a later
/// `ENGINE_load_private_key` share the same masking (via the persisted BMK under
/// the shared resiliency storage dir).
pub fn generate_masked_ec_from_env(curve: HsmEccCurve) -> EngineResult<Vec<u8>> {
    let data = EngineData::new();
    data.open_hsm_from_env()?;
    data.with_session(|session| {
        let build = |class: HsmKeyClass, sign: bool| {
            HsmKeyPropsBuilder::default()
                .class(class)
                .key_kind(HsmKeyKind::Ecc)
                .ecc_curve(curve)
                .is_session(false)
                .can_sign(sign)
                .can_verify(!sign)
                .build()
                .map_err(|e| EngineError::wrap("build EC key props", e))
        };
        let priv_props = build(HsmKeyClass::Private, true)?;
        let pub_props = build(HsmKeyClass::Public, false)?;
        let mut algo = HsmEccKeyGenAlgo::default();
        let (priv_key, _pub) =
            HsmKeyManager::generate_key_pair(session, &mut algo, priv_props, pub_props)
                .map_err(|e| EngineError::wrap("generate EC key pair", e))?;
        priv_key
            .masked_key_vec()
            .map_err(|e| EngineError::wrap("export masked key", e))
    })
}
