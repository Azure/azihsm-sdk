// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_uint;
use std::sync::OnceLock;

use openssl_rust::safeapi::callback::EnginePKeyResult;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::error::*;
use openssl_rust::safeapi::evp_pkey::callback::common::*;
use openssl_rust::safeapi::evp_pkey::method::EvpPKeyMethod;
use openssl_rust::safeapi::evp_pkey::method::EvpPKeyType;

use crate::pkey::ec::callback::*;
use crate::pkey::hkdf::callback::*;
use crate::pkey::rsa::callback::*;

static RSA_PKEY_METH: OnceLock<EvpPKeyMethod> = OnceLock::new();
static HKDF_PKEY_METH: OnceLock<EvpPKeyMethod> = OnceLock::new();
static EC_PKEY_METH: OnceLock<EvpPKeyMethod> = OnceLock::new();

static AZIHSM_PKEY_NIDS: OnceLock<Vec<c_uint>> = OnceLock::new();

/// Create and/or initialize the EvpPKeyMethod object for RSA
fn init_rsa_pkey_meth() -> OpenSSLResult<&'static EvpPKeyMethod> {
    let copy_cb = PKeyCopyFn::Rsa(rsa_copy_cb);
    let ctrl_cb = PKeyCtrlFn::Rsa(rsa_ctrl_cb);
    let enc_init_cb = PKeyEncDecInitFn::Rsa(rsa_encrypt_decrypt_init_cb);
    let dec_init_cb = PKeyEncDecInitFn::Rsa(rsa_encrypt_decrypt_init_cb);
    let enc_cb = PKeyEncDecFn::Rsa(rsa_encrypt_cb);
    let dec_cb = PKeyEncDecFn::Rsa(rsa_decrypt_cb);
    let keygen_init_cb = PKeyGenInitFn::Rsa(rsa_gen_init_cb);
    let keygen_cb = PKeyGenFn::Rsa(rsa_gen_cb);
    let paramgen_init_cb = PKeyParamgenInitFn::Rsa(rsa_gen_init_cb);
    let paramgen_cb = PKeyParamGenFn::Rsa(rsa_gen_cb);
    let sign_init_cb = PKeySignVerifyInitFn::Rsa(rsa_sign_verify_init_cb);
    let signctx_init_cb = PKeySignCtxInitFn::Rsa(rsa_sign_verify_ctx_init_cb);
    let verify_init_cb = PKeySignVerifyInitFn::Rsa(rsa_sign_verify_init_cb);
    let verifyctx_init_cb = PKeyVerifyCtxInitFn::Rsa(rsa_sign_verify_ctx_init_cb);
    let sign_cb = PKeySignFn::Rsa(rsa_sign_cb);
    let signctx_cb = PKeySignCtxFn::Rsa(rsa_signctx_cb);
    let verify_cb = PKeyVerifyFn::Rsa(rsa_verify_cb);
    let verifyctx_cb = PKeyVerifyCtxFn::Rsa(rsa_verifyctx_cb);

    let rsa_pkey_meth = RSA_PKEY_METH.get_or_init(|| EvpPKeyMethod::new(EvpPKeyType::Rsa, 0));
    rsa_pkey_meth
        .init()
        .set_copy(Some(copy_cb))
        .set_ctrl(Some(ctrl_cb), None)
        .set_encrypt(Some(enc_init_cb), Some(enc_cb))
        .set_decrypt(Some(dec_init_cb), Some(dec_cb))
        .set_sign(Some(sign_init_cb), Some(sign_cb))
        .set_sign_ctx(Some(signctx_init_cb), Some(signctx_cb))
        .set_verify(Some(verify_init_cb), Some(verify_cb))
        .set_verify_ctx(Some(verifyctx_init_cb), Some(verifyctx_cb))
        .set_keygen(Some(keygen_init_cb), Some(keygen_cb))
        .set_paramgen(Some(paramgen_init_cb), Some(paramgen_cb))
        .result()
}

fn init_hkdf_pkey_meth() -> OpenSSLResult<&'static EvpPKeyMethod> {
    let hkdf_pkey_meth = HKDF_PKEY_METH.get_or_init(|| EvpPKeyMethod::new(EvpPKeyType::Hkdf, 0));

    let cleanup_cb = PKeyCleanupFn::Hkdf(hkdf_cleanup_cb);
    let ctrl_cb = PKeyCtrlFn::Hkdf(hkdf_ctrl_cb);
    let derive_init_cb = PKeyDeriveInitFn::Hkdf(hkdf_derive_init_cb);
    let derive_cb = PKeyDeriveFn::Hkdf(hkdf_derive_cb);

    hkdf_pkey_meth
        .init()
        .set_cleanup(Some(cleanup_cb))
        .set_ctrl(Some(ctrl_cb), None)
        .set_derive(Some(derive_init_cb), Some(derive_cb))
        .result()
}

fn init_ec_pkey_meth() -> OpenSSLResult<&'static EvpPKeyMethod> {
    let ec_pkey_meth = EC_PKEY_METH.get_or_init(|| EvpPKeyMethod::new(EvpPKeyType::Ec, 0));

    let init_cb = PKeyInitFn::Ec(ec_op_init);
    let cleanup_cb = PKeyCleanupFn::Ec(ec_cleanup_cb);
    let copy_cb = PKeyCopyFn::Ec(ec_copy_cb);
    let ctrl_cb = PKeyCtrlFn::Ec(ec_ctrl_cb);
    let paramgen_init_cb = PKeyParamgenInitFn::Ec(ec_paramgen_init_cb);
    let paramgen_cb = PKeyParamGenFn::Ec(ec_paramgen_cb);
    let keygen_init_cb = PKeyGenInitFn::Ec(ec_op_init);
    let keygen_cb = PKeyGenFn::Ec(ec_keygen_cb);
    let derive_init_cb = PKeyDeriveInitFn::Ec(ec_op_init);
    let derive_cb = PKeyDeriveFn::Ec(ec_derive_cb);
    let sign_init_cb = PKeySignVerifyInitFn::Ec(ec_op_init);
    let signctx_init_cb = PKeySignCtxInitFn::Ec(ec_sign_verify_ctx_init_cb);
    let sign_cb = PKeySignFn::Ec(ec_sign_cb);
    let signctx_cb = PKeySignCtxFn::Ec(ec_signctx_cb);
    let verify_init_cb = PKeySignVerifyInitFn::Ec(ec_op_init);
    let verifyctx_init_cb = PKeyVerifyCtxInitFn::Ec(ec_sign_verify_ctx_init_cb);
    let verify_cb = PKeyVerifyFn::Ec(ec_verify_cb);
    let verifyctx_cb = PKeyVerifyCtxFn::Ec(ec_verifyctx_cb);

    ec_pkey_meth
        .init()
        .set_init(Some(init_cb))
        .set_copy(Some(copy_cb))
        .set_cleanup(Some(cleanup_cb))
        .set_ctrl(Some(ctrl_cb), None)
        .set_paramgen(Some(paramgen_init_cb), Some(paramgen_cb))
        .set_keygen(Some(keygen_init_cb), Some(keygen_cb))
        .set_sign(Some(sign_init_cb), Some(sign_cb))
        .set_sign_ctx(Some(signctx_init_cb), Some(signctx_cb))
        .set_verify(Some(verify_init_cb), Some(verify_cb))
        .set_verify_ctx(Some(verifyctx_init_cb), Some(verifyctx_cb))
        .set_derive(Some(derive_init_cb), Some(derive_cb))
        .result()
}

/// Get all PKey NIDs supported by AZIHSM or get cipher requested by NID.
pub fn engine_pkeys(_e: &Engine, nid: c_uint) -> OpenSSLResult<EnginePKeyResult> {
    if nid == 0 {
        let pkey_nids = AZIHSM_PKEY_NIDS
            .get()
            .ok_or(OpenSSLError::NoPKeyMethodsAvailable)?;
        return Ok(EnginePKeyResult::Nids((
            pkey_nids.as_slice(),
            pkey_nids.len() as c_uint,
        )));
    }

    match EvpPKeyType::from_nid(nid)? {
        EvpPKeyType::Rsa => Ok(EnginePKeyResult::PKey(
            RSA_PKEY_METH
                .get()
                .ok_or(OpenSSLError::PKeyMethodNotInitialized)?,
        )),
        EvpPKeyType::Hkdf => Ok(EnginePKeyResult::PKey(
            HKDF_PKEY_METH
                .get()
                .ok_or(OpenSSLError::PKeyMethodNotInitialized)?,
        )),
        EvpPKeyType::Ec => Ok(EnginePKeyResult::PKey(
            EC_PKEY_METH
                .get()
                .ok_or(OpenSSLError::PKeyMethodNotInitialized)?,
        )),
    }
}

/// Initialize the pkey types supported by the AZIHSM engine
pub fn init_pkeys(engine: &Engine) -> OpenSSLResult<()> {
    if let Err(e) = engine.set_pkey(engine_pkeys) {
        tracing::error!("Could not set pkeys callback: {e}");
        return Err(e);
    }

    init_rsa_pkey_meth()?;
    init_hkdf_pkey_meth()?;
    init_ec_pkey_meth()?;

    AZIHSM_PKEY_NIDS.get_or_init(|| {
        vec![
            EvpPKeyType::Rsa.nid(),
            EvpPKeyType::Hkdf.nid(),
            EvpPKeyType::Ec.nid(),
        ]
    });

    Ok(())
}
