// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_api::KeyType;
use openssl_rust::safeapi::error::*;
use openssl_rust::NID_X9_62_prime256v1;
use openssl_rust::NID_secp384r1;
use openssl_rust::NID_secp521r1;

use crate::common::hsm_key::HsmKeyContainer;

#[derive(Clone, Debug)]
pub struct SecretKey(Arc<HsmKeyContainer>);

impl SecretKey {
    pub fn new(key: HsmKeyContainer) -> Self {
        SecretKey(Arc::new(key))
    }

    pub fn hsm_key(&self) -> Arc<HsmKeyContainer> {
        self.0.clone()
    }
}

#[derive(Debug)]
pub enum SecretType {
    Secret256,
    Secret384,
    Secret521,
}

impl SecretType {
    pub fn to_azihsm_key_type(&self) -> KeyType {
        match self {
            SecretType::Secret256 => KeyType::Secret256,
            SecretType::Secret384 => KeyType::Secret384,
            SecretType::Secret521 => KeyType::Secret521,
        }
    }

    pub fn from_curve_name(curve_name: i32) -> OpenSSLResult<Self> {
        #[allow(non_upper_case_globals)]
        match curve_name as u32 {
            NID_X9_62_prime256v1 => Ok(SecretType::Secret256),
            NID_secp384r1 => Ok(SecretType::Secret384),
            NID_secp521r1 => Ok(SecretType::Secret521),
            _ => Err(OpenSSLError::EcUnsupportedCurve),
        }
    }
}
