// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use api_interface::REPORT_DATA_SIZE;
use mcr_api_resilient::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::NID_X9_62_prime256v1 as NID_EC_P256;
use openssl_rust::NID_secp384r1 as NID_EC_P384;
use openssl_rust::NID_secp521r1 as NID_EC_P521;
use parking_lot::RwLock;

use crate::common::hsm_key::HsmKeyContainer;
use crate::common::secret_key::*;
use crate::engine_internal::*;

#[derive(Clone, Debug)]
pub enum EcCurveType {
    P256,
    P384,
    P521,
}

impl EcCurveType {
    pub fn from_curve_name(curve_name: i32) -> OpenSSLResult<Self> {
        match curve_name as u32 {
            NID_EC_P256 => Ok(EcCurveType::P256),
            NID_EC_P384 => Ok(EcCurveType::P384),
            NID_EC_P521 => Ok(EcCurveType::P521),
            _ => Err(OpenSSLError::EcUnsupportedCurve),
        }
    }

    pub fn to_curve_name(&self) -> i32 {
        match self {
            EcCurveType::P256 => NID_EC_P256 as i32,
            EcCurveType::P384 => NID_EC_P384 as i32,
            EcCurveType::P521 => NID_EC_P521 as i32,
        }
    }

    pub fn to_azihsm_curve(&self) -> EccCurve {
        match self {
            EcCurveType::P256 => EccCurve::P256,
            EcCurveType::P384 => EccCurve::P384,
            EcCurveType::P521 => EccCurve::P521,
        }
    }

    pub fn sig_param_len(&self) -> usize {
        match self {
            EcCurveType::P256 => 64,
            EcCurveType::P384 => 96,
            EcCurveType::P521 => 132,
        }
    }
}

impl TryFrom<KeyType> for EcCurveType {
    type Error = OpenSSLError;

    fn try_from(value: KeyType) -> Result<Self, Self::Error> {
        match value {
            KeyType::Ecc256Private | KeyType::Ecc256Public => Ok(EcCurveType::P256),
            KeyType::Ecc384Private | KeyType::Ecc384Public => Ok(EcCurveType::P384),
            KeyType::Ecc521Private | KeyType::Ecc521Public => Ok(EcCurveType::P521),
            _ => Err(OpenSSLError::InvalidKeyType),
        }
    }
}

#[derive(Debug)]
pub struct EcKeyData(Arc<RwLock<EcKeyInner>>);

impl Default for EcKeyData {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EcKeyData {
    fn clone(&self) -> Self {
        let copy = EcKeyData::new();
        copy.copy_from(self);
        copy
    }
}

impl EcKeyData {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(EcKeyInner::new())))
    }

    pub fn set_imported_key(&self, key: HsmKeyContainer) {
        self.0.write().key = Some(Arc::new(key));
    }

    pub fn param_init(&self) {
        self.0.write().init();
    }

    /// Copy the EC key parameters from source EcKeyData object to this object
    pub fn copy_param_from(&self, src: &EcKeyData) {
        let mut dst = self.0.write();
        let src = src.0.read();
        dst.curve_type = src.curve_type.clone();
        dst.key_usage = src.key_usage;
        dst.peer_key_der = src.peer_key_der.clone();
    }

    pub fn generate_key(&self) -> OpenSSLResult<()> {
        self.0.write().generate_key()
    }

    pub fn set_curve(&self, curve_name: i32) -> OpenSSLResult<()> {
        let curve_type = EcCurveType::from_curve_name(curve_name)?;
        self.0.write().curve_type = Some(curve_type);
        Ok(())
    }

    pub fn curve_type(&self) -> Option<EcCurveType> {
        self.0.read().curve_type.clone()
    }

    pub fn set_key_type(&self, ecdh_key: bool) {
        self.0.write().key_usage = if ecdh_key {
            KeyUsage::Derive
        } else {
            KeyUsage::SignVerify
        };
    }

    /// Set the hash type for all operations
    pub fn set_hash_type(&self, hash_type: Option<DigestKind>) {
        self.0.write().hash_type = hash_type
    }

    pub fn get_hash_type(&self) -> Option<DigestKind> {
        self.0.read().hash_type
    }

    pub fn is_ecdh_key(&self) -> bool {
        self.0.read().key_usage == KeyUsage::Derive
    }

    pub fn export_public_key(&self) -> OpenSSLResult<Vec<u8>> {
        self.0.read().export_public_key()
    }

    pub fn set_peer_key(&self, peer_key_der: Vec<u8>) {
        self.0.write().peer_key_der = Some(Arc::new(peer_key_der));
    }

    pub fn peer_key(&self) -> Option<Arc<Vec<u8>>> {
        self.0.read().peer_key_der.clone()
    }

    #[cfg(test)]
    pub fn key_refcount(&self) -> usize {
        if let Some(key) = &self.0.read().key {
            Arc::strong_count(key)
        } else {
            0
        }
    }

    pub fn compute_shared_secret(&self) -> OpenSSLResult<SecretKey> {
        let curve_name = self.curve_type().ok_or(OpenSSLError::EcMissingCurveName)?;
        let secret_type = SecretType::from_curve_name(curve_name.to_curve_name())?;
        self.0.read().compute_shared_secret(secret_type)
    }

    pub fn sign(&self, data: Vec<u8>) -> OpenSSLResult<Vec<u8>> {
        self.0.read().sign(data)
    }

    pub fn verify(&self, dgst: Vec<u8>, sig: Vec<u8>) -> OpenSSLResult<()> {
        self.0.read().verify(dgst, sig)
    }

    pub fn sig_len(&self) -> OpenSSLResult<usize> {
        if let Some(key_kind) = self.0.read().key_kind() {
            match key_kind {
                KeyType::Ecc256Public | KeyType::Ecc256Private => Ok(64),
                KeyType::Ecc384Public | KeyType::Ecc384Private => Ok(96),
                KeyType::Ecc521Public | KeyType::Ecc521Private => Ok(132),
                _ => Err(OpenSSLError::InvalidKey),
            }
        } else {
            Err(OpenSSLError::MissingKey("EC key".to_string()))
        }
    }

    pub fn attest_key(
        &self,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
    ) -> OpenSSLResult<Vec<u8>> {
        self.0.read().attest_key(report_data)
    }

    /// Copy the private key data from source EcKeyData object to this object
    fn copy_from(&self, src: &EcKeyData) {
        self.0.write().key = src.0.read().key.clone();
        self.copy_param_from(src);
    }
}
#[derive(Clone, Debug)]
struct EcKeyInner {
    key: Option<Arc<HsmKeyContainer>>,
    curve_type: Option<EcCurveType>,
    key_usage: KeyUsage,
    hash_type: Option<DigestKind>, // Only used for signctx/verifyctx
    peer_key_der: Option<Arc<Vec<u8>>>,
}

impl Default for EcKeyInner {
    fn default() -> Self {
        Self {
            key: None,
            curve_type: None,
            key_usage: KeyUsage::SignVerify,
            hash_type: None,
            peer_key_der: None,
        }
    }
}

impl EcKeyInner {
    fn new() -> Self {
        Self::default()
    }

    fn init(&mut self) {
        self.curve_type = None;
        self.key_usage = KeyUsage::SignVerify;
        self.hash_type = None;
        self.peer_key_der = None;
    }

    fn generate_key(&mut self) -> OpenSSLResult<()> {
        if let Some(curve) = &self.curve_type {
            let key_properties = KeyProperties {
                key_usage: self.key_usage,
                key_availability: KeyAvailability::Session,
            };

            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            let key = app_session
                .ecc_generate(curve.to_azihsm_curve(), None, key_properties)
                .map_err(map_hsm_error)?;
            self.key = Some(Arc::new(HsmKeyContainer::new(key, true)));
            Ok(())
        } else {
            Err(OpenSSLError::EcMissingCurveName)
        }
    }

    fn export_public_key(&self) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .export_public_key(&key.hsm_handle())
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("EC Private".to_string()))
        }
    }

    fn compute_shared_secret(&self, secret_type: SecretType) -> OpenSSLResult<SecretKey> {
        if let Some(key) = &self.key {
            let peer_key_der = self
                .peer_key_der
                .as_ref()
                .ok_or(OpenSSLError::MissingKey("EC Peer".to_string()))?;

            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            let secret = app_session
                .ecdh_key_exchange(
                    &key.hsm_handle(),
                    peer_key_der,
                    None,
                    secret_type.to_azihsm_key_type(),
                    KeyProperties {
                        key_usage: self.key_usage,
                        key_availability: KeyAvailability::Session,
                    },
                )
                .map_err(map_hsm_error)?;
            Ok(SecretKey::new(HsmKeyContainer::new(secret, true)))
        } else {
            Err(OpenSSLError::MissingKey("EC Private".to_string()))
        }
    }

    fn sign(&self, data: Vec<u8>) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .ecc_sign(&key.hsm_handle(), data)
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("EC Private".to_string()))
        }
    }

    fn verify(&self, dgst: Vec<u8>, sig: Vec<u8>) -> OpenSSLResult<()> {
        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .ecc_verify(&key.hsm_handle(), dgst.to_vec(), sig.to_vec())
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("EC Public".to_string()))
        }
    }

    fn attest_key(&self, report_data: &[u8; REPORT_DATA_SIZE as usize]) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            key.attest_key(report_data)
        } else {
            Err(OpenSSLError::MissingKey("EC Private".to_string()))
        }
    }

    fn key_kind(&self) -> Option<KeyType> {
        self.key.as_ref().map(|key| key.key_kind())
    }
}
