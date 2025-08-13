// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_api::*;
use openssl_rust::safeapi::error::OpenSSLError;
use openssl_rust::safeapi::error::OpenSSLResult;
use openssl_rust::safeapi::evp_pkey::pkey::EvpPKey;

use crate::common::hsm_key::HsmKeyContainer;
use crate::pkey::ec::callback::pkey_ec_open_private_key;
use crate::pkey::rsa::callback::pkey_rsa_open_private_key;

/// Open the private HSM key by name
///
/// # Arguments
/// * `key_name` - Name of the key to open
/// * `is_ecdh` - Whether or not this key is ECDH (only for EC)
///
/// # Returns
/// * `OpenSSLResult<EvpPKey>` - An `EvpPKey` with the key data
pub(crate) fn open_private_key(key_name: u16, is_ecdh: bool) -> OpenSSLResult<EvpPKey> {
    let key_container = HsmKeyContainer::open_key(key_name)?;
    match key_container.key_kind() {
        KeyType::Ecc256Private | KeyType::Ecc384Private | KeyType::Ecc521Private => {
            pkey_ec_open_private_key(key_container, is_ecdh)
        }
        KeyType::Rsa2kPrivate
        | KeyType::Rsa2kPrivateCrt
        | KeyType::Rsa3kPrivate
        | KeyType::Rsa3kPrivateCrt
        | KeyType::Rsa4kPrivate
        | KeyType::Rsa4kPrivateCrt => pkey_rsa_open_private_key(key_container),
        _ => Err(OpenSSLError::InvalidKeyType),
    }
}
