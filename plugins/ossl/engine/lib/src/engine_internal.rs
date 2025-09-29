// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use lazy_static::lazy_static;
use mcr_api_resilient::*;
use openssl_rust::safeapi::error::*;
use parking_lot::RwLock;
use uuid::Uuid;

use crate::common::hsm_key::HsmKeyContainer;

// 70FCF730-B876-4238-B835-8010CE8A3F76
const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

// DB3DC77F-C22E-4300-80D4-1B31B6F04800
const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

pub fn map_hsm_error(e: HsmError) -> OpenSSLError {
    match e {
        HsmError::AesEncryptFailed | HsmError::RsaEncryptFailed => OpenSSLError::EncryptionFailed,
        HsmError::AesDecryptFailed | HsmError::RsaDecryptFailed => OpenSSLError::DecryptionFailed,
        HsmError::EccSignFailed | HsmError::RsaSignFailed => OpenSSLError::SignFailed,
        HsmError::EccVerifyFailed | HsmError::RsaVerifyFailed => OpenSSLError::VerifyFailed,
        HsmError::AesGenerateError | HsmError::EccGenerateError => OpenSSLError::KeyGenerationError,
        HsmError::InvalidParameter => OpenSSLError::IncorrectHsmParam(e.to_string()),
        _ => OpenSSLError::InternalError(format!("HsmError: {e}")),
    }
}

pub struct AziHsmEngine {
    app_session: Option<HsmSession>,
    unwrap_key: Option<Arc<HsmKeyContainer>>,
    app_creds: HsmAppCredentials,
}

lazy_static! {
    pub static ref AZIHSM_ENGINE: Arc<RwLock<AziHsmEngine>> = Arc::default();
}

pub fn azihsm_engine() -> Arc<RwLock<AziHsmEngine>> {
    AZIHSM_ENGINE.clone()
}

impl Default for AziHsmEngine {
    fn default() -> Self {
        let app_creds = HsmAppCredentials {
            id: Uuid::from_bytes(TEST_CRED_ID),
            pin: TEST_CRED_PIN,
        };

        AziHsmEngine {
            app_session: None,
            unwrap_key: None,
            app_creds,
        }
    }
}

impl AziHsmEngine {
    /// Open an app session
    pub fn init(&mut self) -> OpenSSLResult<()> {
        let (device, api_rev) = self.open_device()?;

        // Establish credential
        // We ignore the result as establish credential can fail if
        // another process already established the credentials
        let _result = device.establish_credential(api_rev, self.app_creds);

        // open app session, and cleanup if it fails
        let result = device.open_session(api_rev, self.app_creds).map_err(|e| {
            let _ = self.destroy();
            map_hsm_error(e)
        })?;

        self.app_session = Some(result);
        Ok(())
    }

    /// Get the unwrap key
    pub fn get_unwrap_key(&self) -> Option<Arc<HsmKeyContainer>> {
        self.unwrap_key.clone()
    }

    /// Set the unwrap key
    pub fn set_unwrap_key(&mut self, unwrap_key: Option<Arc<HsmKeyContainer>>) {
        self.unwrap_key = unwrap_key;
    }

    /// Get app session as reference
    pub fn app_session_as_ref(&self) -> OpenSSLResult<&HsmSession> {
        self.app_session
            .as_ref()
            .ok_or(OpenSSLError::EngineNoAppSession)
    }

    /// Get app session as mutable reference
    pub fn app_session_as_mut(&mut self) -> OpenSSLResult<&mut HsmSession> {
        self.app_session
            .as_mut()
            .ok_or(OpenSSLError::EngineNoAppSession)
    }

    pub fn destroy(&mut self) -> OpenSSLResult<()> {
        if self.app_session.is_some() {
            let _ = self
                .app_session_as_mut()
                .map(|session| session.close_session())?;

            self.app_session = None;
        }

        Ok(())
    }

    fn open_device(&self) -> OpenSSLResult<(HsmDevice, HsmApiRevision)> {
        let devices = HsmDevice::get_devices();
        if devices.is_empty() {
            Err(OpenSSLError::InternalError(
                "No AZIHSM devices found".to_string(),
            ))?;
        }
        let device = HsmDevice::open(devices[0].path.as_str()).map_err(map_hsm_error)?;

        let api_rev = device.get_api_revision_range().max;

        Ok((device, api_rev))
    }
}

impl Drop for AziHsmEngine {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_azihsm_ctx() {
        let engine_ctx = azihsm_engine();
        let mut engine_ctx_lock = engine_ctx.write();
        assert!(engine_ctx_lock.app_session.is_none());
        let result = engine_ctx_lock.init();
        assert!(result.is_ok());
        assert!(engine_ctx_lock.app_session.is_some());
        let result = engine_ctx_lock.destroy();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_ctx_multiple_times() {
        // First
        {
            let engine_ctx = azihsm_engine();
            let mut engine_ctx_lock = engine_ctx.write();
            assert!(engine_ctx_lock.app_session.is_none());
            let result = engine_ctx_lock.init();
            assert!(result.is_ok());
            assert!(engine_ctx_lock.app_session.is_some());
            let result = engine_ctx_lock.destroy();
            assert!(result.is_ok());
        }

        // Second
        {
            let engine_ctx = azihsm_engine();
            let mut engine_ctx_lock = engine_ctx.write();
            assert!(engine_ctx_lock.app_session.is_none());
            let result = engine_ctx_lock.init();
            assert!(result.is_ok());
            assert!(engine_ctx_lock.app_session.is_some());
            let result = engine_ctx_lock.destroy();
            assert!(result.is_ok());
        }

        // Third
        {
            let engine_ctx = azihsm_engine();
            let mut engine_ctx_lock = engine_ctx.write();
            assert!(engine_ctx_lock.app_session.is_none());
            let result = engine_ctx_lock.init();
            assert!(result.is_ok());
            assert!(engine_ctx_lock.app_session.is_some());
            let result = engine_ctx_lock.destroy();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_multiple_destroy() {
        let engine_ctx = azihsm_engine();
        let mut engine_ctx_lock = engine_ctx.write();
        assert!(engine_ctx_lock.app_session.is_none());
        let result = engine_ctx_lock.init();
        assert!(result.is_ok());
        assert!(engine_ctx_lock.app_session.is_some());
        let app_session = engine_ctx_lock.app_session_as_ref();
        assert!(app_session.is_ok());
        let result = engine_ctx_lock.destroy();
        assert!(result.is_ok());
        let result = engine_ctx_lock.destroy();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_app_session_as_ref() {
        let engine_ctx = azihsm_engine();
        let mut engine_ctx_lock = engine_ctx.write();
        assert!(engine_ctx_lock.app_session.is_none());
        let result = engine_ctx_lock.init();
        assert!(result.is_ok());
        assert!(engine_ctx_lock.app_session.is_some());
        let app_session = engine_ctx_lock.app_session_as_ref();
        assert!(app_session.is_ok());
        let result = engine_ctx_lock.destroy();
        assert!(result.is_ok());
    }
}
