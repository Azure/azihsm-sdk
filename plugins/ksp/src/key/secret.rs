// Copyright (C) Microsoft Corporation. All rights reserved.
use std::sync::Arc;

use mcr_api_resilient::DigestKind;
use mcr_api_resilient::EccCurve;
use mcr_api_resilient::HkdfDeriveParameters;
use mcr_api_resilient::HsmKeyHandle;
use mcr_api_resilient::HsmSession;
use mcr_api_resilient::KbkdfDeriveParameters;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyProperties;
use mcr_api_resilient::KeyType;
use mcr_api_resilient::KeyUsage;
use parking_lot::RwLock;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use crate::pcwstr;
use crate::AzIHsmHresult;

const HKDF_INFO_MAX_SIZE: usize = 16;
const HKDF_SALT_MAX_SIZE: usize = 64;
const KBKDF_CONTEXT_MAX_SIZE: usize = 16;
const KBKDF_LABEL_MAX_SIZE: usize = 16;
const KEY_BIT_LENGTH_128: usize = 128;
const KEY_BIT_LENGTH_192: usize = 192;
const KEY_BIT_LENGTH_256: usize = 256;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug)]
pub(crate) enum KdfType {
    HKDF,
    KBKDF,
}

/// Secret
#[derive(Clone, Debug)]
pub(crate) struct Secret(Arc<RwLock<SecretInner>>);

impl Secret {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(SecretInner::new(None))))
    }

    fn set_hsm_secret_handle(&mut self, secret_handle: Option<HsmKeyHandle>) {
        self.0.write().hsm_secret_handle = secret_handle;
    }

    fn get_hsm_secret_handle(&self) -> Option<HsmKeyHandle> {
        self.0.read().hsm_secret_handle.clone()
    }

    fn kdf_target_key_bitlen(&self) -> Option<usize> {
        self.0.read().kdf_properties.target_key_bitlen
    }

    fn kdf_digest_kind(&self) -> Option<DigestKind> {
        self.0.read().kdf_properties.digest_kind
    }

    fn kdf_type(&self) -> Option<KdfType> {
        self.0.read().kdf_properties.kdf_type.clone()
    }

    fn kdf_salt_label(&self) -> Option<Vec<u8>> {
        let property = &self.0.read().kdf_properties;
        if !property.salt_label.clone()?.is_empty() {
            Some(property.salt_label.clone()?)
        } else {
            None
        }
    }

    fn kdf_info_context(&self) -> Option<Vec<u8>> {
        let property = &self.0.read().kdf_properties;
        if !property.info_context.clone()?.is_empty() {
            Some(property.info_context.clone()?)
        } else {
            None
        }
    }

    ///  Generates a secret agreement value from a private and a peer public key
    ///
    /// # Arguments
    /// * `app_session`         - The HsmSession to use for generating the secret
    /// * `priv_key`            - The handle of the private key to use to create the secret agreement value
    /// * `peer_key_der`        - The imported handle of the peer's public key used to generate the secret agreement value
    /// * `curve_type`          - Curve type of the priv_key used to determine the secret type.
    ///
    /// # Returns
    /// `Ok(())` if the secret generation was successful; otherwise, an error code.
    ///
    pub fn generate_secret_agreement(
        &mut self,
        app_session: &HsmSession,
        priv_key: HsmKeyHandle,
        peer_key_der: Vec<u8>,
        curve_type: Option<EccCurve>,
    ) -> Result<(), HRESULT> {
        let secret_type = match curve_type {
            Some(EccCurve::P256) => KeyType::Secret256,
            Some(EccCurve::P384) => KeyType::Secret384,
            Some(EccCurve::P521) => KeyType::Secret521,
            None => {
                tracing::error!("ECC Curve type is not set");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let peer_key_der_slice = peer_key_der.as_slice();
        let secret_agreement = match app_session.ecdh_key_exchange(
            &priv_key,
            peer_key_der_slice,
            None,
            secret_type,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        ) {
            Ok(secret_agreement) => Some(secret_agreement),
            Err(err) => {
                tracing::error!(
                    ?err,
                    "Error during ECDH key exchange, aka secret generation.",
                );
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        self.set_hsm_secret_handle(secret_agreement);
        Ok(())
    }

    /// Deletes and sets the HSM Secret handle to None.
    ///
    /// # Arguments
    ///  * `app_session` - The HsmSession
    ///
    /// # Returns
    /// `Ok(())` if the secret handle was deleted successfully; otherwise, an error code.
    ///
    pub fn delete_secret(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.get_hsm_secret_handle().is_none() {
            tracing::warn!("Hsm key is not created, nothing to delete.");
            return Ok(());
        }
        let hsm_secret_handle = self.get_hsm_secret_handle().ok_or_else(|| {
            tracing::error!("Secret handle not set");
            HRESULT(E_UNEXPECTED)
        })?;
        match app_session.delete_key(&hsm_secret_handle) {
            Ok(_) => {
                self.set_hsm_secret_handle(None);
                Ok(())
            }
            Err(err) => {
                tracing::error!(?err, "Error during deletion of hsm handle for secret.",);
                self.set_hsm_secret_handle(None);
                Err(HRESULT(E_UNEXPECTED))?
            }
        }
    }

    /// Extracts the KDF hash algorithm from the buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer containing the KDF parameters.
    ///
    /// # Returns
    /// A `DigestKind` option if a supported algorithm is found; otherwise, an error.
    fn extract_kdf_hash_alg(&self, buffer: &BCryptBuffer) -> Result<Option<DigestKind>, HRESULT> {
        let buffer_data = unsafe {
            std::slice::from_raw_parts(buffer.pvBuffer as *const u8, buffer.cbBuffer as usize)
        };
        let alg_id: PCWSTR = unsafe { std::mem::transmute(buffer_data.as_ptr()) };
        tracing::debug!("KDF Hash Algorithm: {:?}", alg_id);

        if pcwstr::equals(alg_id, BCRYPT_SHA1_ALGORITHM) {
            Ok(Some(DigestKind::Sha1))
        } else if pcwstr::equals(alg_id, BCRYPT_SHA256_ALGORITHM) {
            Ok(Some(DigestKind::Sha256))
        } else if pcwstr::equals(alg_id, BCRYPT_SHA384_ALGORITHM) {
            Ok(Some(DigestKind::Sha384))
        } else if pcwstr::equals(alg_id, BCRYPT_SHA512_ALGORITHM) {
            Ok(Some(DigestKind::Sha512))
        } else {
            tracing::error!("Unsupported KDF hash algorithm: {:?}", alg_id);
            Err(HRESULT(NTE_NOT_SUPPORTED))
        }
    }

    /// Extracts the KDF salt/label from the buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer containing the KDF salt.
    ///
    /// # Returns
    /// A slice of bytes representing the salt/label, or an error if extraction fails.
    fn extract_kdf_salt_label(&self, buffer: &BCryptBuffer) -> Result<Vec<u8>, HRESULT> {
        let buffer_data = unsafe {
            std::slice::from_raw_parts(buffer.pvBuffer as *const u8, buffer.cbBuffer as usize)
        };
        Ok(buffer_data.to_vec())
    }

    /// Extracts the KDF key bit length from the buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer containing the KDF key bit length.
    ///
    /// # Returns
    /// The key bit length as `usize`, or an error if the buffer size is invalid.
    fn extract_kdf_bit_len(&self, buffer: &BCryptBuffer) -> Result<usize, HRESULT> {
        if buffer.cbBuffer < std::mem::size_of::<u32>() as u32 {
            tracing::error!(
                "Invalid buffer size for KDF key bit length: {}",
                buffer.cbBuffer
            );
            return Err(HRESULT(NTE_INVALID_PARAMETER));
        }
        let key_bitlen = unsafe { *(buffer.pvBuffer as *const u32) };
        Ok(key_bitlen as usize)
    }

    /// Extracts the KDF info/context field from the buffer.
    ///
    /// # Arguments
    /// * `buffer` - The buffer containing the HKDF info.
    ///
    /// # Returns
    /// A slice of bytes representing the HKDF info/context, or an error if extraction fails.
    fn extract_kdf_info_context(&self, buffer: &BCryptBuffer) -> Result<Vec<u8>, HRESULT> {
        let buffer_data = unsafe {
            std::slice::from_raw_parts(buffer.pvBuffer as *const u8, buffer.cbBuffer as usize)
        };
        Ok(buffer_data.to_vec())
    }

    /// Extracts and sets HKDF parameters by parsing the input buffer
    ///
    /// # Arguments
    /// * buffer_desc - A reference to a BCryptBufferDesc, which contains the input
    ///   buffer from which HKDF parameters will be extracted
    ///
    /// # Returns
    /// Ok(()) if the parameters are parsed & set successfully.
    /// Otherwise, an error code.
    fn set_hkdf_params(&mut self, buffer_desc: &BCryptBufferDesc) -> AzIHsmHresult<()> {
        // Set the KDF type
        self.0.write().kdf_properties.kdf_type = Some(KdfType::HKDF);

        // Parse the buffer description and set other kdf parameters
        for idx in 0..buffer_desc.cBuffers {
            let buffer = unsafe { &*buffer_desc.pBuffers.add(idx as usize) };
            let buffer_type = buffer.BufferType;

            if ([
                KDF_HASH_ALGORITHM,
                KDF_HKDF_SALT,
                KDF_HKDF_INFO,
                KDF_KEYBITLENGTH,
            ]
            .contains(&buffer_type))
                && (buffer.cbBuffer == 0 || buffer.pvBuffer.is_null())
            {
                Err(HRESULT(NTE_INVALID_PARAMETER))?
            }

            match buffer_type {
                KDF_HASH_ALGORITHM => {
                    self.0.write().kdf_properties.digest_kind =
                        self.extract_kdf_hash_alg(buffer)?;
                }
                KDF_HKDF_SALT => {
                    self.0.write().kdf_properties.salt_label =
                        Some(self.extract_kdf_salt_label(buffer)?);
                }
                KDF_KEYBITLENGTH => {
                    self.0.write().kdf_properties.target_key_bitlen =
                        Some(self.extract_kdf_bit_len(buffer)?);
                }
                KDF_HKDF_INFO => {
                    self.0.write().kdf_properties.info_context =
                        Some(self.extract_kdf_info_context(buffer)?);
                }
                _ => {
                    tracing::warn!("Unsupported HKDF parameter type: {:?}", buffer.BufferType);
                }
            }
        }

        Ok(())
    }

    /// Extracts and sets KBKDF parameters by parsing the input buffer
    ///
    /// # Arguments
    /// * buffer_desc - A reference to a BCryptBufferDesc, which contains the input
    ///   buffer from which KBKDF parameters will be extracted
    ///
    /// # Returns
    /// Ok(()) if the parameters are parsed & set successfully.
    /// Otherwise, an error code.
    fn set_kbkdf_params(&mut self, buffer_desc: &BCryptBufferDesc) -> AzIHsmHresult<()> {
        // Set the KDF type
        self.0.write().kdf_properties.kdf_type = Some(KdfType::KBKDF);

        // Parse the buffer description and set other kdf parameters
        for idx in 0..buffer_desc.cBuffers {
            let buffer = unsafe { &*buffer_desc.pBuffers.add(idx as usize) };
            let buffer_type = buffer.BufferType;

            if ([KDF_HASH_ALGORITHM, KDF_LABEL, KDF_CONTEXT, KDF_KEYBITLENGTH]
                .contains(&buffer_type))
                && (buffer.cbBuffer == 0 || buffer.pvBuffer.is_null())
            {
                Err(HRESULT(NTE_INVALID_PARAMETER))?
            }

            match buffer_type {
                KDF_HASH_ALGORITHM => {
                    self.0.write().kdf_properties.digest_kind =
                        self.extract_kdf_hash_alg(buffer)?;
                }
                KDF_LABEL => {
                    self.0.write().kdf_properties.salt_label =
                        Some(self.extract_kdf_salt_label(buffer)?);
                }
                KDF_CONTEXT => {
                    self.0.write().kdf_properties.info_context =
                        Some(self.extract_kdf_info_context(buffer)?);
                }
                KDF_KEYBITLENGTH => {
                    self.0.write().kdf_properties.target_key_bitlen =
                        Some(self.extract_kdf_bit_len(buffer)?);
                }
                _ => {
                    tracing::warn!("Unsupported KBKDF parameter type: {:?}", buffer.BufferType);
                }
            }
        }

        Ok(())
    }

    /// Sets KDF parameters by parsing input buffer
    ///
    /// # Arguments
    /// * `kdf` - The key derivation function to use.
    /// * `buffer_desc` - A reference to a BCryptBufferDesc, which contains the input buffer from which KDF parameters will be extracted
    ///
    /// # Notes
    ///   `BCRYPT_KDF_HKDF` => HKDF
    ///   `BCRYPT_SP800108_CTR_HMAC_ALGORITHM` => KBKDF
    ///
    /// # Returns
    /// `Ok(())` if the parameters are parsed & set successfully.
    ///  otherwise, an error code.
    fn set_kdf_params(
        &mut self,
        kdf: KdfType,
        buffer_desc: &BCryptBufferDesc,
    ) -> AzIHsmHresult<()> {
        match kdf {
            KdfType::HKDF => self.set_hkdf_params(buffer_desc),
            KdfType::KBKDF => self.set_kbkdf_params(buffer_desc),
        }
    }

    /// Calls set_kdf_params() to set kdf parameters and infers
    /// target key type based on key bit-length
    ///
    /// # Arguments
    /// * `kdf` - The key derivation function to use.
    /// * `buffer_desc` - A reference to a BCryptBufferDesc, which contains the input buffer from which KDF parameters will be extracted
    ///
    /// # Returns
    /// returns `Ok(KeyType)` if execution is successful,
    /// otherwise, an error code.
    pub fn infer_target_key_type(
        &mut self,
        kdf: KdfType,
        buffer_desc: &BCryptBufferDesc,
    ) -> Result<Option<KeyType>, HRESULT> {
        // Extract and set kdf parameters
        self.set_kdf_params(kdf, buffer_desc)?;

        // Get the target key bit length
        let target_key_bitlen = self.kdf_target_key_bitlen();

        // Infer the target_key_type using key usage and target_key_bitlen
        let target_key_type = match target_key_bitlen {
            Some(KEY_BIT_LENGTH_128) => Some(KeyType::Aes128),
            Some(KEY_BIT_LENGTH_192) => Some(KeyType::Aes192),
            Some(KEY_BIT_LENGTH_256) => Some(KeyType::Aes256),
            _ => {
                tracing::error!("Unsupported key bit length for AES key");
                Err(HRESULT(E_INVALIDARG))?
            }
        };

        if target_key_type.is_none() {
            tracing::error!("Target key type could not be inferred");
            Err(HRESULT(E_INVALIDARG))?;
        }
        Ok(target_key_type)
    }

    /// Derives a target key using the specified KDF type (HKDF or KBKDF).
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession that provides context for the derivation.
    /// * `target_key_type` - The target key type to be derived.
    ///
    /// # Returns
    /// Returns `Ok(HsmKeyHandle)` for the derived target key if execution is successful,
    /// otherwise, an error code.
    pub fn kdf_derive(
        &self,
        app_session: &HsmSession,
        target_key_type: KeyType,
    ) -> Result<HsmKeyHandle, HRESULT> {
        match self.kdf_type() {
            Some(KdfType::HKDF) => self.hkdf_derive(app_session, target_key_type),
            Some(KdfType::KBKDF) => self.kbkdf_derive(app_session, target_key_type),
            None => Err(HRESULT(NTE_NOT_SUPPORTED)),
        }
    }

    /// Calls mcr_api to derive target key using HKDF parameters.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession
    /// * `target_key_type` - The target key type to be derived
    ///
    /// # Returns
    /// returns `Ok(HsmKeyHandle)` for target key if execution is successful,
    /// otherwise, an error code.
    fn hkdf_derive(
        &self,
        app_session: &HsmSession,
        target_key_type: KeyType,
    ) -> Result<HsmKeyHandle, HRESULT> {
        tracing::debug!("hkdf_derive called");
        let target_key_bitlen = self.kdf_target_key_bitlen();
        let digest_kind = self.kdf_digest_kind();
        let info = self.kdf_info_context();
        let salt = self.kdf_salt_label();

        if target_key_bitlen.is_none() || digest_kind.is_none() {
            tracing::error!(
                "Invalid KDF Parameters: target key bit length or digest kind is none.
                target_key_bitlen: {:?}, target_key_bitlen: {:?}",
                target_key_bitlen,
                target_key_bitlen
            );
            Err(HRESULT(E_INVALIDARG))?
        }

        if let Some(info_slice) = info.as_deref() {
            if info_slice.is_empty() {
                tracing::error!("Invalid KDF Parameter: info vector is empty");
                Err(HRESULT(E_INVALIDARG))?
            }
            if info_slice.len() > HKDF_INFO_MAX_SIZE {
                tracing::error!("Invalid KDF Parameter: info length exceeds max size");
                Err(HRESULT(E_INVALIDARG))?
            }
        }

        if let Some(salt_slice) = salt.as_deref() {
            if salt_slice.is_empty() {
                tracing::error!("Invalid KDF Parameter: salt vector is empty");
                Err(HRESULT(E_INVALIDARG))?
            }
            if salt_slice.len() > HKDF_SALT_MAX_SIZE {
                tracing::error!("Invalid KDF Parameter: salt length exceeds max size");
                Err(HRESULT(E_INVALIDARG))?
            }
        }

        let hash_algorithm = match digest_kind {
            Some(digest) => digest,
            None => {
                tracing::error!("Invalid KDF Parameter: Digest_kind");
                return Err(HRESULT(NTE_INVALID_PARAMETER));
            }
        };

        let derive_params: HkdfDeriveParameters = HkdfDeriveParameters {
            hash_algorithm,
            salt: salt.as_deref(),
            info: info.as_deref(),
        };

        let key_properties: KeyProperties = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::Session,
        };

        let hsm_key_handle = match self.get_hsm_secret_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };
        let result = app_session.hkdf_derive(
            &hsm_key_handle,
            derive_params,
            None,
            target_key_type,
            key_properties,
        );
        match result {
            Ok(hsm_handle) => Ok(hsm_handle),
            Err(err) => {
                tracing::error!(?err, "Error during hkdf key derivation",);
                Err(HRESULT(E_UNEXPECTED))
            }
        }
    }

    /// Calls mcr_api to derive target key using KB-KDF parameters.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession
    /// * `target_key_type` - The target key type to be derived
    ///
    /// # Returns
    /// returns `Ok(HsmKeyHandle)` for target key if execution is successful,
    /// otherwise, an error code.
    fn kbkdf_derive(
        &self,
        app_session: &HsmSession,
        target_key_type: KeyType,
    ) -> Result<HsmKeyHandle, HRESULT> {
        tracing::debug!("kbkdf_derive called");
        let target_key_bitlen = self.kdf_target_key_bitlen();
        let digest_kind = self.kdf_digest_kind();
        let context = self.kdf_info_context();
        let label = self.kdf_salt_label();

        if target_key_bitlen.is_none() || digest_kind.is_none() {
            tracing::error!(
                "Invalid KDF Parameters: target key bit length or digest kind is none.
                target_key_bitlen: {:?}, target_key_bitlen: {:?}",
                target_key_bitlen,
                target_key_bitlen
            );
            Err(HRESULT(E_INVALIDARG))?
        }

        if let Some(context_slice) = context.as_deref() {
            if context_slice.is_empty() {
                tracing::error!("Invalid KDF Parameter: context vector is empty");
                Err(HRESULT(E_INVALIDARG))?
            }
            if context_slice.len() > KBKDF_CONTEXT_MAX_SIZE {
                tracing::error!("Invalid KDF Parameter: context length exceeds max size");
                Err(HRESULT(E_INVALIDARG))?
            }
        }

        if let Some(label_slice) = label.as_deref() {
            if label_slice.is_empty() {
                tracing::error!("Invalid KDF Parameter: label vector is empty");
                Err(HRESULT(E_INVALIDARG))?
            }
            if label_slice.len() > KBKDF_LABEL_MAX_SIZE {
                tracing::error!("Invalid KDF Parameter: label length exceeds max size");
                Err(HRESULT(E_INVALIDARG))?
            }
        }

        let hash_algorithm = match digest_kind {
            Some(digest) => digest,
            None => {
                tracing::error!("Invalid KDF Parameter: Digest_kind");
                Err(HRESULT(NTE_INVALID_PARAMETER))?
            }
        };

        let derive_params: KbkdfDeriveParameters = KbkdfDeriveParameters {
            hash_algorithm,
            label: label.as_deref(),
            context: context.as_deref(),
        };

        let key_properties: KeyProperties = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::Session,
        };

        let hsm_key_handle = match self.get_hsm_secret_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };
        let result = app_session.kbkdf_counter_hmac_derive(
            &hsm_key_handle,
            derive_params,
            None,
            target_key_type,
            key_properties,
        );
        match result {
            Ok(hsm_handle) => Ok(hsm_handle),
            Err(err) => {
                tracing::error!(?err, "Error during kbkdf key derivation",);
                Err(HRESULT(E_UNEXPECTED))
            }
        }
    }
}

#[derive(Debug)]
pub struct KdfProperties {
    kdf_type: Option<KdfType>,
    digest_kind: Option<DigestKind>,
    salt_label: Option<Vec<u8>>,
    info_context: Option<Vec<u8>>,
    target_key_bitlen: Option<usize>,
}

#[derive(Debug)]
struct SecretInner {
    hsm_secret_handle: Option<HsmKeyHandle>,
    kdf_properties: KdfProperties,
}

impl SecretInner {
    pub fn new(secret: Option<HsmKeyHandle>) -> Self {
        Self {
            hsm_secret_handle: secret,
            kdf_properties: KdfProperties {
                kdf_type: None,
                digest_kind: None,
                salt_label: None,
                target_key_bitlen: None,
                info_context: None,
            },
        }
    }
}
