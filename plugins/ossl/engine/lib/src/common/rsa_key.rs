// Copyright (C) Microsoft Corporation. All rights reserved.

use std::convert::TryFrom;
use std::ffi::c_uint;
use std::sync::Arc;

use api_interface::REPORT_DATA_SIZE;
use mcr_api_resilient::*;
use openssl_rust::safeapi::error::*;
use openssl_rust::RSA_PKCS1_PADDING;
use openssl_rust::RSA_PKCS1_PSS_PADDING;
use parking_lot::RwLock;

use crate::common::hsm_key::HsmKeyContainer;
use crate::engine_internal::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RsaKeyUsage {
    EncryptDecrypt,
    SignVerify,
    Opened,
}

impl TryFrom<RsaKeyUsage> for KeyUsage {
    type Error = OpenSSLError;

    fn try_from(value: RsaKeyUsage) -> Result<Self, Self::Error> {
        match value {
            RsaKeyUsage::EncryptDecrypt => Ok(KeyUsage::EncryptDecrypt),
            RsaKeyUsage::SignVerify => Ok(KeyUsage::SignVerify),
            _ => Err(OpenSSLError::InvalidKeyUsage),
        }
    }
}

impl TryFrom<KeyUsage> for RsaKeyUsage {
    type Error = OpenSSLError;

    fn try_from(value: KeyUsage) -> Result<Self, Self::Error> {
        match value {
            KeyUsage::EncryptDecrypt => Ok(RsaKeyUsage::EncryptDecrypt),
            KeyUsage::SignVerify => Ok(RsaKeyUsage::SignVerify),
            _ => Err(OpenSSLError::InvalidKeyUsage),
        }
    }
}

#[derive(Debug, Default)]
pub struct RsaKeyData(Arc<RwLock<RsaInner>>);

impl Clone for RsaKeyData {
    fn clone(&self) -> Self {
        let mut copy = RsaKeyData::new();
        copy.copy_from(self);
        copy
    }
}

impl RsaKeyData {
    /// Create a new `RsaKeyData` structure
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(RsaInner::new())))
    }

    /// Set the key usage
    pub fn set_key_usage(&self, key_usage: RsaKeyUsage) {
        self.0.write().set_key_usage(key_usage);
    }

    /// Set the imported `HsmKeyContainer`
    pub fn set_imported_key(&self, key: HsmKeyContainer) {
        self.0.write().set_key(Some(Arc::new(key)));
    }

    /// Set the hash type for operations
    pub fn set_hash_type(&self, hash_type: Option<DigestKind>) {
        self.0.write().set_hash_type(hash_type);
    }

    /// Set the salt length for signing/verifying operations
    pub fn set_sig_salt_len(&self, salt_len: Option<u16>) {
        self.0.write().set_sig_salt_len(salt_len);
    }

    /// Set the padding scheme for signatures
    pub fn set_sig_padding(&self, padding: RsaSignaturePadding) {
        self.0.write().set_sig_padding(padding);
    }

    /// Set the optional label bytes, which is used during RSA encrypt/decrypt.
    pub fn set_label(&self, label: Option<&[u8]>) {
        self.0.write().set_label(label);
    }

    /// Get the hash type for operations
    pub fn get_hash_type(&self) -> Option<DigestKind> {
        self.0.read().get_hash_type()
    }

    /// Get the padding scheme for signatures
    pub fn get_sig_padding(&self) -> Option<RsaSignaturePadding> {
        self.0.read().get_sig_padding()
    }

    /// Get the PSS salt length
    pub fn get_sig_salt_len(&self) -> Option<u16> {
        self.0.read().get_sig_salt_len()
    }

    /// Get the optional label bytes (used during RSA encrypt/decrypt).
    pub fn get_label(&self) -> Option<Vec<u8>> {
        self.0.read().get_label()
    }

    /// Get the length of the signature
    pub fn sig_len(&self) -> OpenSSLResult<usize> {
        if let Some(key_kind) = self.0.read().key_kind() {
            match key_kind {
                KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => Ok(256),
                KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => Ok(384),
                KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => Ok(512),
                _ => Err(OpenSSLError::InvalidKey),
            }
        } else {
            Err(OpenSSLError::MissingKey("RSA Private".to_string()))
        }
    }

    /// Get the key refcount
    #[cfg(test)]
    pub fn key_refcount(&self) -> usize {
        if let Some(key) = &self.0.read().key {
            Arc::strong_count(key)
        } else {
            0
        }
    }

    /// Get the key usage
    pub fn get_key_usage(&self) -> Option<RsaKeyUsage> {
        self.0.read().get_key_usage()
    }

    /// Get the underlying `HsmKeyContainer`
    pub fn get_key(&self) -> Option<Arc<HsmKeyContainer>> {
        self.0.read().get_key()
    }

    /// Sign a given digest
    ///
    /// # Argument
    /// * `dgst` - Digest to sign
    ///
    /// # Return
    /// Signed data, or error
    pub fn sign(&self, dgst: &[u8]) -> OpenSSLResult<Vec<u8>> {
        self.0.read().sign(dgst)
    }

    /// Verify a given digest's signature
    ///
    /// # Argument
    /// * `dgst` - Digest to verify
    /// * `sig` - Signature to check
    ///
    /// # Return
    /// `Ok(())` on success, or an `OpenSSLError`
    pub fn verify(&self, dgst: &[u8], sig: &[u8]) -> OpenSSLResult<()> {
        self.0.read().verify(dgst, sig)
    }

    /// Encrypt a block of data
    ///
    /// # Argument
    /// * `data` - Data to encrypt
    ///
    /// # Return
    /// `Vec<u8>` with encrypted data on success, or an `OpenSSLError`
    pub fn encrypt(&self, data: &[u8]) -> OpenSSLResult<Vec<u8>> {
        self.0.read().encrypt(data)
    }

    /// Decrypt a block of data
    ///
    /// # Argument
    /// * `data` - Data to decrypt
    ///
    /// # Return
    /// `Vec<u8>` with decrypted data on success, or an `OpenSSLError`
    pub fn decrypt(&self, data: &[u8]) -> OpenSSLResult<Vec<u8>> {
        self.0.read().decrypt(data)
    }

    /// Attest the underlying key
    ///
    /// # Argument
    /// * `report_data` - Reporting data to the HSM
    ///
    /// # Return
    /// `Vec<u8>` with attestation data from the HSM
    pub fn attest_key(
        &self,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
    ) -> OpenSSLResult<Vec<u8>> {
        self.0.read().attest_key(report_data)
    }

    /// Copy the private key data from src `RsaKeyData` object to this object
    fn copy_from(&mut self, src: &RsaKeyData) {
        self.0.write().copy_from(&src.0.read());
    }
}

/// Parameters specific to RSA signatures
#[derive(Clone, Debug)]
struct RsaSignatureParameters {
    padding: RsaSignaturePadding,
    salt_len: Option<u16>,
}

impl Default for RsaSignatureParameters {
    fn default() -> Self {
        Self {
            padding: RsaSignaturePadding::Pkcs1_5,
            salt_len: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct RsaInner {
    key: Option<Arc<HsmKeyContainer>>,
    key_usage: Option<RsaKeyUsage>,
    hash_type: Option<DigestKind>,
    sig_params: Option<RsaSignatureParameters>,
    label: Option<Vec<u8>>,
}

impl RsaInner {
    fn new() -> Self {
        Self::default()
    }

    fn copy_from(&mut self, src: &Self) {
        self.key = src.key.clone();
        self.key_usage = src.key_usage;
        self.hash_type = src.hash_type;
        self.sig_params = src.sig_params.clone();
    }

    /// Set the underlying key
    fn set_key(&mut self, key: Option<Arc<HsmKeyContainer>>) {
        self.key = key;
    }

    /// Set the key usage
    fn set_key_usage(&mut self, key_usage: RsaKeyUsage) {
        self.key_usage = Some(key_usage);
    }

    /// Set the hash type for all operations
    fn set_hash_type(&mut self, hash_type: Option<DigestKind>) {
        self.hash_type = hash_type;
    }

    /// Set the salt length for signatures
    fn set_sig_salt_len(&mut self, salt_len: Option<u16>) {
        match self.sig_params.as_mut() {
            Some(sig_params) => sig_params.salt_len = salt_len,
            None => {
                self.sig_params = Some(RsaSignatureParameters {
                    salt_len,
                    ..Default::default()
                })
            }
        };
    }

    /// Set the padding scheme for signatures
    fn set_sig_padding(&mut self, padding: RsaSignaturePadding) {
        match self.sig_params.as_mut() {
            Some(sig_params) => sig_params.padding = padding,
            None => {
                self.sig_params = Some(RsaSignatureParameters {
                    padding,
                    ..Default::default()
                })
            }
        };
    }

    /// Set the optional label bytes, which is used during RSA encrypt/decrypt.
    pub fn set_label(&mut self, label: Option<&[u8]>) {
        self.label = None;
        if let Some(label_data) = label {
            // create a new vector and copy the provided bytes
            let mut vec: Vec<u8> = Vec::new();
            vec.extend_from_slice(label_data);
            self.label = Some(vec);
        }
    }

    fn key_kind(&self) -> Option<KeyType> {
        self.key.as_ref().map(|key| key.key_kind())
    }

    /// Get the current key usage
    fn get_key_usage(&self) -> Option<RsaKeyUsage> {
        self.key_usage
    }

    /// Get the hash type for operations
    fn get_hash_type(&self) -> Option<DigestKind> {
        self.hash_type
    }

    /// Get the salt length for signing/verifying operations
    fn get_sig_salt_len(&self) -> Option<u16> {
        match self.sig_params.as_ref() {
            Some(sig_params) => sig_params.salt_len,
            None => None,
        }
    }

    /// Get the padding scheme for signatures
    pub fn get_sig_padding(&self) -> Option<RsaSignaturePadding> {
        self.sig_params
            .as_ref()
            .map(|sig_params| sig_params.padding)
    }

    /// Get the underlying `HsmKeyContainer`
    fn get_key(&self) -> Option<Arc<HsmKeyContainer>> {
        self.key.clone()
    }

    /// Get the optional label bytes (used during RSA encrypt/decrypt).
    pub fn get_label(&self) -> Option<Vec<u8>> {
        self.label.clone()
    }

    /// Sign a given digest
    fn sign(&self, dgst: &[u8]) -> OpenSSLResult<Vec<u8>> {
        let sig_params = match &self.sig_params {
            Some(params) => params,
            None => &RsaSignatureParameters::default(),
        };

        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .rsa_sign(
                    &key.hsm_handle(),
                    dgst.to_vec(),
                    sig_params.padding,
                    self.hash_type,
                    sig_params.salt_len,
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("RSA Private".to_string()))
        }
    }

    /// Verify a given digest against a signature
    fn verify(&self, dgst: &[u8], sig: &[u8]) -> OpenSSLResult<()> {
        let sig_params = match &self.sig_params {
            Some(params) => params,
            None => &RsaSignatureParameters::default(),
        };

        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .rsa_verify(
                    &key.hsm_handle(),
                    dgst.to_vec(),
                    sig.to_vec(),
                    sig_params.padding,
                    self.hash_type,
                    sig_params.salt_len,
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("RSA Public".to_string()))
        }
    }

    /// Encrypt a given block of data
    fn encrypt(&self, data: &[u8]) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .rsa_encrypt(
                    &key.hsm_handle(),
                    data.to_vec(),
                    RsaCryptoPadding::Oaep,
                    self.hash_type,
                    self.label.as_deref(),
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("RSA Private".to_string()))
        }
    }

    /// Decrypt a given block of data
    fn decrypt(&self, data: &[u8]) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            let hsm_ctx = azihsm_engine();
            let hsm_ctx_lock = hsm_ctx.read();
            let app_session = hsm_ctx_lock.app_session_as_ref()?;
            app_session
                .rsa_decrypt(
                    &key.hsm_handle(),
                    data.to_vec(),
                    RsaCryptoPadding::Oaep,
                    self.hash_type,
                    self.label.as_deref(),
                )
                .map_err(map_hsm_error)
        } else {
            Err(OpenSSLError::MissingKey("RSA Public".to_string()))
        }
    }

    /// Attest the underlying key
    fn attest_key(&self, report_data: &[u8; REPORT_DATA_SIZE as usize]) -> OpenSSLResult<Vec<u8>> {
        if let Some(key) = &self.key {
            key.attest_key(report_data)
        } else {
            Err(OpenSSLError::MissingKey("RSA Private".to_string()))
        }
    }
}

/// Get the AZIHSM padding type for the given padding ID
pub(crate) fn azihsm_sig_padding(padding: c_uint) -> OpenSSLResult<Option<RsaSignaturePadding>> {
    match padding {
        0 => Ok(None),
        RSA_PKCS1_PADDING => Ok(Some(RsaSignaturePadding::Pkcs1_5)),
        RSA_PKCS1_PSS_PADDING => Ok(Some(RsaSignaturePadding::Pss)),
        _ => Err(OpenSSLError::PaddingNotSupported),
    }
}

/// Get the RSA padding scheme for the given AZIHSM padding type
pub(crate) fn openssl_sig_padding(padding: Option<RsaSignaturePadding>) -> c_uint {
    match padding {
        None => 0,
        Some(RsaSignaturePadding::Pkcs1_5) => RSA_PKCS1_PADDING,
        Some(RsaSignaturePadding::Pss) => RSA_PKCS1_PSS_PADDING,
    }
}
