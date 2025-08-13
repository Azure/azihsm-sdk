// Copyright (C) Microsoft Corporation. All rights reserved.
use std::mem;
use std::sync::Arc;

use mcr_api::DigestKind;
use mcr_api::HsmKeyHandle;
use mcr_api::HsmSession;
use mcr_api::KeyClass;
use mcr_api::KeyType;
use mcr_api::KeyUsage;
use mcr_api::RsaCryptoPadding;
use mcr_api::RsaSignaturePadding;
use parking_lot::RwLock;
use winapi::shared::winerror::ERROR_INVALID_DATA;
use winapi::shared::winerror::ERROR_INVALID_STATE;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_DATA;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BAD_SIGNATURE;
use winapi::shared::winerror::NTE_BAD_TYPE;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::NCRYPT_ALLOW_DECRYPT_FLAG;
use windows::Win32::Security::Cryptography::NCRYPT_ALLOW_KEY_IMPORT_FLAG;
use windows::Win32::Security::Cryptography::NCRYPT_ALLOW_SIGNING_FLAG;
use windows::Win32::Security::Cryptography::NCRYPT_RSA_ALGORITHM_GROUP;

use super::super::REPORT_DATA_SIZE;
use crate::bcrypt_util;
use crate::handle_table::Handle;
use crate::helpers::validate_output_buffer;
use crate::key::base_key::BaseKey;
use crate::key::base_key::KeyOrigin;
use crate::key::base_key::KeyPropertyIdentifier;
use crate::key::base_key::AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED;
use crate::key::base_key::AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED;
use crate::pcwstr;
use crate::AzIHsmHresult;

const RSA_2K_KEY_LENGTH: u32 = 2048;
const RSA_3K_KEY_LENGTH: u32 = 3072;
const RSA_4K_KEY_LENGTH: u32 = 4096;

pub(crate) const RSA_2K_DATA_SIZE_LIMIT: usize = 256;
pub(crate) const RSA_3K_DATA_SIZE_LIMIT: usize = 384;
pub(crate) const RSA_4K_DATA_SIZE_LIMIT: usize = 512;
pub const RSA_2K_CRT_PUBLIC_BUFFER_MAX: usize = 1284;
pub const RSA_3K_CRT_PUBLIC_BUFFER_MAX: usize = 1924;
pub const RSA_4K_CRT_PUBLIC_BUFFER_MAX: usize = 2564;
// Max size of a RSA Public Key
const RSA_PUBLIC_KEY_MAX_SIZE: usize = 550;

pub(crate) struct RsaSignParams<'a> {
    pub input: &'a [u8],
    pub padding: RsaSignaturePadding,
    pub digest_kind: Option<DigestKind>,
    pub salt_len: Option<u16>,
    pub output: &'a mut [u8],
    pub output_size: &'a mut u32,
}

/// RsaKey
#[derive(Clone, Debug)]
pub struct RsaKey(Arc<RwLock<RsaKeyInner>>);
impl RsaKey {
    /// Create a new RsaKey
    pub fn new(prov_handle: Handle, key_length: u32) -> Self {
        Self(Arc::new(RwLock::new(RsaKeyInner::new(
            prov_handle,
            key_length,
        ))))
    }

    // Securely import Rsakey
    pub fn secure_key_import(
        prov_handle: Handle,
        key_length: u32,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
    ) -> Self {
        Self(Arc::new(RwLock::new(RsaKeyInner::secure_key_import(
            prov_handle,
            key_length,
            key_data,
            digest_kind,
            import_key_handle,
        ))))
    }

    pub fn set_hsm_handle(&self, hsm_handle: HsmKeyHandle) {
        self.0.write().base_key.hsm_handle = Some(hsm_handle);
    }

    pub fn hsm_key_handle(&self) -> Option<HsmKeyHandle> {
        self.0.read().base_key.hsm_handle.clone()
    }

    pub fn key_length(&self) -> u32 {
        self.0.read().key_length
    }

    fn set_key_length(&mut self, key_length: u32) {
        self.0.write().key_length = key_length;
    }

    pub fn key_usage(&self) -> Option<KeyUsage> {
        self.0.read().base_key.get_key_usage()
    }

    pub fn key_origin(&self) -> KeyOrigin {
        self.0.read().base_key.get_key_origin()
    }

    pub fn key_class(&self) -> Option<KeyClass> {
        self.0.read().base_key.get_key_class()
    }

    pub fn set_key_usage(&mut self, key_usage: KeyUsage) -> AzIHsmHresult<()> {
        tracing::debug!(?key_usage, "Setting key usage");
        self.0.write().base_key.set_key_usage(key_usage)
    }

    /// Export public key.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use.
    /// * `output` - The output buffer to store the exported blob.
    /// * `output_size` - The size of the output buffer.
    /// # Returns
    /// `Ok(())` if the key export was successful; otherwise, an error code.
    ///
    pub fn export_public_key(
        &self,
        app_session: &HsmSession,
        output: &mut [u8],
        output_size: &mut u32,
    ) -> AzIHsmHresult<()> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let max_len = match hsm_key_handle.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa3kPrivate | KeyType::Rsa4kPrivate => {
                RSA_PUBLIC_KEY_MAX_SIZE as u32
            }
            KeyType::Rsa2kPrivateCrt => RSA_2K_CRT_PUBLIC_BUFFER_MAX as u32,
            KeyType::Rsa3kPrivateCrt => RSA_3K_CRT_PUBLIC_BUFFER_MAX as u32,
            KeyType::Rsa4kPrivateCrt => RSA_4K_CRT_PUBLIC_BUFFER_MAX as u32,
            _ => {
                tracing::error!("Invalid key type: {:?}", hsm_key_handle.kind());
                Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
            }
        };

        validate_output_buffer!(output, output_size, max_len);

        self.0
            .write()
            .base_key
            .export_public_key(app_session, output, output_size)
    }

    /// Export BCRYPT structure public key blob
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use.
    /// * `output` - The output buffer to store the exported blob.
    /// * `output_size` - The size of the output buffer.
    /// # Returns
    /// `Ok(())` if the key export was successful; otherwise, an error code.
    ///
    pub fn export_bcrypt_blob(
        &self,
        app_session: &HsmSession,
        output: &mut [u8],
        output_size: &mut u32,
    ) -> AzIHsmHresult<()> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let key_bits = match hsm_key_handle.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt | KeyType::Rsa2kPublic => 2048,
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt | KeyType::Rsa3kPublic => 3072,
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt | KeyType::Rsa4kPublic => 4096,
            _ => {
                tracing::error!("Invalid key type: {:?}", hsm_key_handle.kind());
                Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
            }
        };

        // Get DER format key data
        let mut der_format_output = [0u8; RSA_PUBLIC_KEY_MAX_SIZE];
        let mut der_format_output_size = 0u32;
        self.0.write().base_key.export_public_key(
            app_session,
            &mut der_format_output,
            &mut der_format_output_size,
        )?;

        let magic_blob = bcrypt_util::rsa_der_to_bcrypt(
            &der_format_output[..der_format_output_size as usize],
            key_bits,
        )?;

        validate_output_buffer!(output, output_size, magic_blob.len() as u32);

        output[..magic_blob.len()].copy_from_slice(&magic_blob);
        *output_size = magic_blob.len() as u32;

        Ok(())
    }

    /// Deletes the key from the HSM.
    ///
    /// # Arguments
    ///  * `app_session` - The HsmSession to use for deleting the key.
    ///
    /// # Returns
    /// `Ok(())` if the key was deleted successfully; otherwise, an error code.
    ///
    pub fn delete_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        self.0.write().base_key.delete_key(app_session)
    }

    /// Encrypts or decrypts data using the RSA key.
    ///
    /// # Arguments
    /// * `app_session`  = The application session.
    /// * `input`        = The input data to encrypt or decrypt.
    /// * `digest_kind`  = The digest kind.
    /// * `output`       = The output buffer to store the encrypted or decrypted data.
    /// * `output_size`  = The size of the output buffer.
    /// * `encrypt_data` = A boolean value that indicates whether to encrypt or decrypt the data.
    ///
    /// # Returns
    /// `Ok(())` if the data was encrypted or decrypted successfully; otherwise, an error code.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_decrypt(
        &self,
        app_session: &HsmSession,
        input: &[u8],
        digest_kind: Option<DigestKind>,
        label: Option<&[u8]>,
        output: &mut [u8],
        output_size: &mut u32,
        encrypt_data: bool,
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT::from_win32(ERROR_INVALID_STATE))?
            }
        };

        // Note: The key usage SignVerify allows encryption at AZIHSM API layer.
        // This behavior was verified with the Software KSP, which exhibits the same behavior.
        // Therefore, the code is designed to allow encryption when the key usage is SignVerify.
        match self.key_usage() {
            Some(KeyUsage::EncryptDecrypt) => {
                // Allow both encryption and decryption
            }
            Some(KeyUsage::SignVerify) => {
                if !encrypt_data {
                    tracing::error!("Key is not allowed to be used for decryption.");
                    Err(HRESULT(E_UNEXPECTED))?
                }
                // Allow encryption
            }
            _ => {
                tracing::error!("Key is not allowed to be used for encryption or decryption.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        }

        let result = match encrypt_data {
            true => {
                // [TODO] Review if CRT keys should be supported.
                // If not, remove them from the match.
                let max_len = match hsm_key_handle.kind() {
                    KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => 256,
                    KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => 384,
                    KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => 512,
                    _ => {
                        tracing::error!("Invalid key type: {:?}", hsm_key_handle.kind());
                        Err(HRESULT(NTE_BAD_DATA))?
                    }
                };

                validate_output_buffer!(output, output_size, max_len);

                app_session.rsa_encrypt(
                    &hsm_key_handle,
                    input.to_vec(),
                    RsaCryptoPadding::Oaep,
                    digest_kind,
                    label,
                )
            }
            false => {
                validate_output_buffer!(output, output_size, input.len() as u32);

                app_session.rsa_decrypt(
                    &hsm_key_handle,
                    input.to_vec(),
                    RsaCryptoPadding::Oaep,
                    digest_kind,
                    label,
                )
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(?err, "HsmSession::rsa_encrypt_decrypt failed",);
                Err(HRESULT(NTE_BAD_DATA))?
            }
        };
        output[..result.len()].copy_from_slice(&result);
        *output_size = result.len() as u32;
        tracing::debug!("RSA: encrypt/decrypt data succeeded");
        Ok(())
    }

    /// Sets the property of the key.
    ///
    /// # Arguments
    /// * `property` - The property to set.
    /// * `value`    - The value of the property.
    ///
    /// # Returns
    /// `Ok(())` if the property was set successfully; otherwise, an error code.
    ///
    pub fn set_property(
        &mut self,
        property: &KeyPropertyIdentifier,
        value: &[u8],
    ) -> AzIHsmHresult<()> {
        tracing::debug!(?property, "Setting property of RSA key");

        match property {
            KeyPropertyIdentifier::ClrEphemeral => {
                if value.len() != mem::size_of::<u8>() {
                    tracing::error!("Invalid CLR IsEphemeral value");
                    Err(HRESULT(E_INVALIDARG))?;
                }

                if value[0] != 1 {
                    tracing::error!("Invalid CLR IsEphemeral value");
                    Err(HRESULT(E_INVALIDARG))?;
                }
            }
            KeyPropertyIdentifier::KeyUsage => {
                if value.len() != mem::size_of::<u32>() {
                    tracing::error!("Invalid KeyUsage value");
                    Err(HRESULT(E_INVALIDARG))?;
                }
                let key_usage = u32::from_le_bytes(value.try_into().map_err(|err| {
                    tracing::error!("Failed to convert to bytes: {:?}", err);
                    HRESULT(NTE_INVALID_PARAMETER)
                })?);
                if (key_usage & NCRYPT_ALLOW_DECRYPT_FLAG) != 0 {
                    self.set_key_usage(KeyUsage::EncryptDecrypt)?;
                } else if (key_usage & NCRYPT_ALLOW_SIGNING_FLAG) != 0 {
                    self.set_key_usage(KeyUsage::SignVerify)?;
                } else if (key_usage & NCRYPT_ALLOW_KEY_IMPORT_FLAG) != 0 {
                    self.set_key_usage(KeyUsage::WrapUnwrap)?;
                } else {
                    tracing::error!("Invalid KeyUsage value");
                    Err(HRESULT(E_INVALIDARG))?;
                }
            }
            KeyPropertyIdentifier::RsaCrtEnabled => {
                // attempt to convert the input bytes into a 32-bit unsigned
                // int, then interpret the result such that:
                //  1. Any non-zero value is an indication that CRT should be
                //     enabled.
                //  2. Zero is an indication that CRT should be disabled.
                let param = u32::from_le_bytes(value.try_into().map_err(|err| {
                    tracing::error!("Failed to convert bytes into u32: {:?}", err);
                    HRESULT(NTE_INVALID_PARAMETER)
                })?);
                if param != 0 {
                    // if CRT is to be enabled, update the key's class to be
                    // `RsaCrt`, rather than the default (`Rsa`). This class
                    // will be passed to the AZIHSM device when the imported key
                    // is finalized
                    tracing::debug!("Enabling CRT for RSA key");
                    self.0.write().base_key.set_key_class(KeyClass::RsaCrt)?;
                } else {
                    // if CRT is to be disabled, use the standard `Rsa` class
                    tracing::debug!("Disabling CRT for RSA key");
                    self.0.write().base_key.set_key_class(KeyClass::Rsa)?;
                }
            }
            KeyPropertyIdentifier::Unknown => Err(HRESULT(E_INVALIDARG))?,
            _ => Err(HRESULT(NTE_NOT_SUPPORTED))?,
        }
        Ok(())
    }

    /// Gets the property of the key.
    ///
    /// # Arguments
    /// * `property`   - The property to get.
    /// * `value`      - The output buffer to store the property value.
    /// * `value_size` - The size of the output buffer.
    ///
    /// # Returns
    /// `Ok(())` if the property was retrieved successfully; otherwise, an error code.
    ///
    pub fn get_property(
        &self,
        property: &KeyPropertyIdentifier,
        value: &mut [u8],
        value_size: &mut u32,
    ) -> AzIHsmHresult<()> {
        match property {
            KeyPropertyIdentifier::AlgorithmGroup => {
                if pcwstr::copy_pcwstr_to_slice(NCRYPT_RSA_ALGORITHM_GROUP, value, value_size) == 0
                {
                    return Err(HRESULT(NTE_INVALID_PARAMETER));
                }
            }
            KeyPropertyIdentifier::KeyLength => {
                let output = self.key_length().to_le_bytes();
                let output_size = output.len() as u32;
                validate_output_buffer!(value, value_size, output_size);
                value[..output_size as usize].copy_from_slice(&output);
                *value_size = output_size;
            }
            KeyPropertyIdentifier::KeyUsage => {
                let key_usage = match self.key_usage() {
                    Some(KeyUsage::EncryptDecrypt) => NCRYPT_ALLOW_DECRYPT_FLAG,
                    Some(KeyUsage::SignVerify) => NCRYPT_ALLOW_SIGNING_FLAG,
                    Some(KeyUsage::WrapUnwrap) => NCRYPT_ALLOW_KEY_IMPORT_FLAG,
                    _ => {
                        tracing::error!("Key usage is not set");
                        Err(HRESULT::from_win32(ERROR_INVALID_STATE))?
                    }
                };
                let output = key_usage.to_le_bytes();
                let output_size = output.len() as u32;
                validate_output_buffer!(value, value_size, output_size);
                value[..output_size as usize].copy_from_slice(&output);
                *value_size = output_size;
            }
            KeyPropertyIdentifier::RsaCrtEnabled => {
                // retrieve the inner base key's key class
                let key_class = match self.key_class() {
                    Some(kc) => kc,
                    None => {
                        tracing::error!("Failed to get key class.");
                        return Err(HRESULT(NTE_BAD_KEY));
                    }
                };

                // use the key class to determine what to return; throw an error
                // if we find something unexpected (the key class should be
                // either `Rsa` or `RsaCrt`)
                let result: u32 = match key_class {
                    KeyClass::Rsa => AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED,
                    KeyClass::RsaCrt => AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED,
                    _ => {
                        tracing::error!("Found unexpected key class for RSA key.");
                        return Err(HRESULT(NTE_BAD_KEY));
                    }
                };

                // write the result into the output buffer
                let output = result.to_le_bytes();
                let output_size = output.len() as u32;
                validate_output_buffer!(value, value_size, output_size);
                value[..output_size as usize].copy_from_slice(&output);
                *value_size = output_size;
            }
            KeyPropertyIdentifier::Unknown => return Err(HRESULT(E_INVALIDARG)),
            _ => Err(HRESULT(NTE_NOT_SUPPORTED))?,
        }
        Ok(())
    }

    // Opens built-in AZIHSM unwrap key.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use for opening the key.
    ///
    /// # Returns
    /// `Ok(())` if the key was opened successfully; otherwise, an error code.
    ///
    pub fn open_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        let result = app_session.get_unwrapping_key();
        match result {
            Ok(hsm_handle) => {
                self.set_hsm_handle(hsm_handle);
                tracing::debug!("rsa key hsm handle set successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to get unwrapping key: {:?}", e);
                Err(HRESULT(E_UNEXPECTED))
            }
        }
    }

    /// Assign default RSA key properties.
    /// If not set, following property will be defaulted to
    /// 1. Key Usage: SignVerify
    ///
    /// Key Length will be set during key finalization by device.
    pub fn assign_default(&mut self, _app_session: &HsmSession) -> AzIHsmHresult<()> {
        tracing::debug!("Assigning default RSA key properties");

        // Default key usage to SignVerify
        if self.key_usage().is_none() {
            self.set_key_usage(KeyUsage::SignVerify)?;
        }

        Ok(())
    }

    /// Finalizes the key.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use for finalizing the key.
    ///
    /// # Returns
    /// `Ok(())` if the key was finalized successfully; otherwise, an error code.
    ///
    pub fn finalize_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.hsm_key_handle().is_some() {
            tracing::error!("Key is already imported. Cannot finalize again");
            Err(HRESULT(E_UNEXPECTED))?
        }

        match self.key_origin() {
            KeyOrigin::Import => {
                let hsm_key_handle = self
                    .0
                    .write()
                    .base_key
                    .finalize_secure_import(app_session)?;
                let key_type = hsm_key_handle.kind();
                match key_type {
                    KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => {
                        self.set_key_length(RSA_2K_KEY_LENGTH);
                    }
                    KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => {
                        self.set_key_length(RSA_3K_KEY_LENGTH);
                    }
                    KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => {
                        self.set_key_length(RSA_4K_KEY_LENGTH);
                    }
                    _ => {
                        tracing::error!("Invalid key type: {:?}", key_type);
                        Err(HRESULT(NTE_BAD_TYPE))?
                    }
                }
                Ok(())
            }
            _ => Err(HRESULT(NTE_NOT_SUPPORTED)),
        }
    }

    fn signature_size(hsm_key_handle: &HsmKeyHandle) -> Result<usize, HRESULT> {
        match hsm_key_handle.kind() {
            KeyType::Rsa2kPrivate | KeyType::Rsa2kPrivateCrt => Ok(RSA_2K_DATA_SIZE_LIMIT),
            KeyType::Rsa3kPrivate | KeyType::Rsa3kPrivateCrt => Ok(RSA_3K_DATA_SIZE_LIMIT),
            KeyType::Rsa4kPrivate | KeyType::Rsa4kPrivateCrt => Ok(RSA_4K_DATA_SIZE_LIMIT),
            _ => Err(HRESULT::from_win32(ERROR_INVALID_DATA))?,
        }
    }

    /// Signs the input data using the RSA key.
    /// The input data is signed using the specified padding, digest kind, and salt.
    ///
    /// # Arguments
    /// * `app_session`    - The application session.
    /// * `params`         - The parameters for signing the data.
    ///
    /// # Returns
    /// `Ok(())` if the data was signed successfully; otherwise, an error code.
    ///
    pub fn sign(&self, app_session: &HsmSession, params: RsaSignParams) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot sign at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        // Early check to reject RSA SHA-1 option
        // Without this, RSA Sign with empty buffer and SHA-1 will pass
        // Where it should fail
        if params.digest_kind == Some(DigestKind::Sha1) {
            tracing::error!("SHA-1 is not supported for RSA Sign");
            Err(HRESULT(E_INVALIDARG))?
        }

        let signature_size = Self::signature_size(&hsm_key_handle)? as u32;
        validate_output_buffer!(params.output, params.output_size, signature_size);

        let signature = match app_session.rsa_sign(
            &hsm_key_handle,
            params.input.to_vec(),
            params.padding,
            params.digest_kind,
            params.salt_len,
        ) {
            Ok(signature) => signature,
            Err(err) => {
                tracing::error!(?err, "HsmSession::rsa_sign failed.",);
                Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
            }
        };
        params.output[..signature.len()].copy_from_slice(&signature);
        *params.output_size = signature.len() as u32;
        tracing::debug!("RsaKey::sign succeeded");
        Ok(())
    }

    /// Verifies the input hash and signature using the RSA key.
    ///
    /// # Arguments
    /// * `app_session`    - The application session.
    /// * `hash_value`     - The hash value to verify.
    /// * `padding`        - The padding to use for verifying.
    /// * `digest_kind`    - The digest kind.
    /// * `salt`           - The salt to use for verifying.
    /// * `signature`      - The signature to verify.
    ///
    /// # Returns
    /// `Ok(())` if the data was verified successfully; otherwise, an error code.
    ///
    pub fn verify(
        &self,
        app_session: &HsmSession,
        hash_value: &[u8],
        padding: RsaSignaturePadding,
        digest_kind: Option<DigestKind>,
        salt: Option<u16>,
        signature: &[u8],
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot verify at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        match app_session.rsa_verify(
            &hsm_key_handle,
            hash_value.to_vec(),
            signature.to_vec(),
            padding,
            digest_kind,
            salt,
        ) {
            Ok(_) => {
                tracing::debug!("RsaKey::verify succeeded");
                Ok(())
            }
            Err(err) => {
                tracing::error!(?err, "HsmSession::rsa_verify failed",);
                Err(HRESULT(NTE_BAD_SIGNATURE))
            }
        }
    }

    /// Creates a claim.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use for creating the claim.
    /// * `report_data` - The report data to use for creating the claim.
    /// * `claim` - The output buffer to store the claim.
    /// * `result` - The result of the claim creation.
    ///
    /// # Returns
    /// `Ok(())` if the claim was created successfully; otherwise, an error code.
    ///
    pub fn create_claim(
        &self,
        app_session: &HsmSession,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
        claim: &mut [u8],
        result: &mut u32,
    ) -> AzIHsmHresult<()> {
        self.0
            .write()
            .base_key
            .create_claim(app_session, report_data, claim, result)
    }
}

#[derive(Debug)]
struct RsaKeyInner {
    base_key: BaseKey,
    key_length: u32,
}
impl RsaKeyInner {
    pub fn new(provider_handle: Handle, key_length: u32) -> Self {
        Self {
            base_key: BaseKey::new(provider_handle),
            key_length,
        }
    }

    pub fn secure_key_import(
        prov_handle: Handle,
        key_length: u32,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
    ) -> Self {
        Self {
            base_key: BaseKey::secure_key_import(
                prov_handle,
                key_data,
                digest_kind,
                import_key_handle,
                None,
                KeyClass::RsaCrt, // <-- RSA keys are imported with CRT enabled by default
            ),
            key_length,
        }
    }
}
