// Copyright (C) Microsoft Corporation. All rights reserved.

use api_interface::REPORT_DATA_SIZE;
use mcr_api_resilient::*;
use openssl_rust::safeapi::error::OpenSSLResult;

use crate::engine_internal::*;

/// A container to hold an HsmKeyHandle, which will optionally delete the key on drop.
#[derive(Clone, Debug)]
pub struct HsmKeyContainer(HsmKeyHandle, bool);

impl HsmKeyContainer {
    /// Create a new HsmKeyContainer
    ///
    /// # Argument
    /// * `handle` - HsmKeyHandle to init with
    /// * `delete` - Whether or not to delete the key on drop
    pub fn new(handle: HsmKeyHandle, delete: bool) -> Self {
        Self(handle, delete)
    }

    /// Generate a new AES key
    ///
    /// # Argument
    /// * `key_size` - Size of AES key to generate
    pub fn aes_generate(key_size: AesKeySize) -> OpenSSLResult<Self> {
        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;

        let key = app_session
            .aes_generate(
                key_size,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            )
            .map_err(map_hsm_error)?;
        Ok(Self::new(key, true))
    }

    /// Open a key in the HSM by name
    ///
    /// # Argument
    /// * `key_name` - Name of the key to open
    pub fn open_key(key_name: u16) -> OpenSSLResult<Self> {
        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;

        let key = app_session.open_key(key_name).map_err(map_hsm_error)?;

        Ok(Self::new(key, false))
    }

    /// Unwrap a key and import into the HSM using the current unwrapping key
    ///
    /// # Arguments
    /// * `wrapped_key` - Key to unwrap
    /// * `key_class` - Type of key to unwrap
    /// * `dgst_kind` - Type of digest for the key
    /// * `key_usage` - Usage of the key
    /// * `key_availability` - Availability of the key
    /// * `key_name` - Name to assign to the imported key
    ///
    /// # Return
    /// The `HsmKeyContainer` or error
    pub fn unwrap_key(
        wrapped_key: Vec<u8>,
        key_class: KeyClass,
        dgst_kind: DigestKind,
        key_usage: KeyUsage,
        key_availability: KeyAvailability,
        key_name: Option<u16>,
    ) -> OpenSSLResult<Self> {
        let wrapped_key_params = RsaUnwrapParams {
            key_class,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: dgst_kind,
        };

        let hsm_ctx = azihsm_engine();
        let hsm_ctx_lock = hsm_ctx.read();
        let app_session = hsm_ctx_lock.app_session_as_ref()?;

        let unwrapping_key = if let Some(key) = hsm_ctx_lock.get_unwrap_key() {
            key.hsm_handle()
        } else {
            app_session.get_unwrapping_key().map_err(map_hsm_error)?
        };

        let key = app_session
            .rsa_unwrap(
                &unwrapping_key,
                wrapped_key,
                wrapped_key_params,
                key_name,
                KeyProperties {
                    key_usage,
                    key_availability,
                },
            )
            .map_err(map_hsm_error)?;

        Ok(Self::new(key, key_name.is_none()))
    }

    /// Attest the current key
    ///
    /// # Argument
    /// * `report_data` - Report data to send to the HSM
    ///
    /// # Return
    /// A `Vec<u8>` with the attestation data from the HSM
    pub fn attest_key(
        &self,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
    ) -> OpenSSLResult<Vec<u8>> {
        let engine_ctx = azihsm_engine();
        let engine_ctx = engine_ctx.write();
        let app_session = engine_ctx.app_session_as_ref()?;

        app_session
            .attest_key(&self.hsm_handle(), report_data)
            .map_err(map_hsm_error)
    }

    /// Export public key data
    pub fn export_public_key(&self) -> OpenSSLResult<Vec<u8>> {
        let engine_ctx = azihsm_engine();
        let engine_ctx = engine_ctx.write();
        let app_session = engine_ctx.app_session_as_ref()?;
        app_session
            .export_public_key(&self.hsm_handle())
            .map_err(map_hsm_error)
    }

    /// Get the underlying HSM key handle
    pub fn hsm_handle(&self) -> HsmKeyHandle {
        self.0.clone()
    }

    /// Get the key kind
    pub fn key_kind(&self) -> KeyType {
        self.hsm_handle().kind()
    }
}

impl Drop for HsmKeyContainer {
    fn drop(&mut self) {
        if !self.1 {
            // Don't drop
            return;
        }

        // Delete the key when this container goes away
        let engine_ctx = azihsm_engine();
        let engine_ctx = engine_ctx.write();
        let app_session = match engine_ctx.app_session_as_ref() {
            Ok(session) => session,
            Err(e) => {
                tracing::error!("HsmKeyContainer drop: Could not get HSM session: {e}");
                return;
            }
        };

        let _ = app_session.delete_key(&self.hsm_handle());
    }
}
