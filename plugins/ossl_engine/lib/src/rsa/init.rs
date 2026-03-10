// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::CString;
use std::sync::OnceLock;

use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::rsa::method::RsaMethod;

use crate::rsa::callback::*;

const RSA_METH_ID: &str = "azihsmengine_rsa";

// C strings are dynamically allocated... so we have to do this.
static C_RSA_METH_ID: OnceLock<CString> = OnceLock::new();

/// Initialize low-level RSA functions
pub(crate) fn init_rsa(engine: &Engine) -> OpenSSLResult<()> {
    let meth_id = CString::new(RSA_METH_ID).map_err(OpenSSLError::CStringNulError)?;
    let meth_id = C_RSA_METH_ID.get_or_init(|| meth_id);

    // We need to map the error as we get a &Result
    let meth = RsaMethod::get_or_init(meth_id)
        .as_ref()
        .map_err(|e| e.clone())?;

    meth.set_priv_dec(Some(rsa_priv_dec))
        .set_finish(Some(rsa_finish))
        .set_pub_dec(Some(rsa_pub_dec))
        .set_priv_enc(Some(rsa_priv_enc))
        .set_pub_enc(Some(rsa_pub_enc))
        .set_sign(Some(rsa_sign))
        .set_verify(Some(rsa_verify))
        .set_keygen(Some(rsa_keygen));

    engine.set_rsa(meth)?;

    Ok(())
}
