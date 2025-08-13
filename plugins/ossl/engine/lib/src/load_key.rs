// Copyright (C) Microsoft Corporation. All rights reserved.

use std::ffi::c_void;

use api_interface::engine_ctrl::open_key::is_key_ecdh;
use openssl_rust::safeapi::engine::Engine;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::EVP_PKEY;
use openssl_rust::UI_METHOD;

use crate::pkey::open::open_private_key;

pub(crate) fn init_load_key(engine: &Engine) -> OpenSSLResult<()> {
    engine.set_load_private_key(load_private_key)
}

/// Load a private key from the HSM
fn load_private_key(
    _: &Engine,
    name: &str,
    _: *mut UI_METHOD,
    is_ecdh: *mut c_void,
) -> OpenSSLResult<*mut EVP_PKEY> {
    let name = name
        .parse::<u16>()
        .map_err(|_| OpenSSLError::InvalidKeyName(name.to_string()))?;
    let is_ecdh = is_key_ecdh(is_ecdh);
    let key = open_private_key(name, is_ecdh)?;
    Ok(key.as_mut_ptr())
}
