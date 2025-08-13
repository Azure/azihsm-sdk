// Copyright (C) Microsoft Corporation. All rights reserved.

use std::mem;
use std::sync::Arc;

use mcr_api::AesKeySize;
use mcr_api::AesMode;
use mcr_api::DigestKind;
use mcr_api::HsmKeyHandle;
use mcr_api::HsmSession;
use mcr_api::KeyAvailability;
use mcr_api::KeyClass;
use mcr_api::KeyProperties;
use mcr_api::KeyType;
use mcr_api::KeyUsage;
use parking_lot::RwLock;
use winapi::shared::winerror::ERROR_INVALID_DATA;
use winapi::shared::winerror::ERROR_INVALID_STATE;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BAD_LEN;
use winapi::shared::winerror::NTE_BAD_TYPE;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use winapi::shared::winerror::NTE_NO_KEY;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use crate::handle_table::Handle;
use crate::helpers::validate_output_buffer;
use crate::key::base_key::BaseKey;
use crate::key::base_key::KeyOrigin;
use crate::key::base_key::KeyPropertyIdentifier;
use crate::key::secret::Secret;
use crate::utils::*;
use crate::AzIHsmHresult;

pub const AZIHSM_CIPHERPADDINGINFO_CBC_IVSIZE: usize = 16;
#[cfg(not(feature = "disable-fp"))]
pub const AZIHSM_CIPHERPADDINGINFO_XTS_TWEAKSIZE: usize = 16;
#[cfg(not(feature = "disable-fp"))]
pub const AZIHSM_CIPHERPADDINGINFO_GCM_IVSIZE: usize = 12;
#[cfg(not(feature = "disable-fp"))]
pub const AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE: usize = 16;
pub const AES_KEY_SIZE_128: u32 = 128;
pub const AES_KEY_SIZE_192: u32 = 192;
pub const AES_KEY_SIZE_256: u32 = 256;

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AesEncryptionMode {
    CBC,
    #[cfg(not(feature = "disable-fp"))]
    GCM,
    #[cfg(not(feature = "disable-fp"))]
    XTS,
}

#[cfg(not(feature = "disable-fp"))]
pub(crate) struct AesGcmParams<'a> {
    pub mode: AesMode,
    pub input: &'a [u8],
    pub iv: &'a mut [u8],
    pub aad: Option<Vec<u8>>,
    pub tag: &'a mut [u8],
    pub output: &'a mut [u8],
    pub output_size: &'a mut u32,
}

/// AesKey
#[derive(Clone, Debug)]
pub struct AesKey(Arc<RwLock<AesKeyInner>>);

impl AesKey {
    pub fn new(
        provider_handle: Handle,
        key_length: Option<u32>,
        encryption_mode: Option<AesEncryptionMode>,
    ) -> Self {
        Self(Arc::new(RwLock::new(AesKeyInner::new(
            provider_handle,
            key_length,
            encryption_mode,
        ))))
    }

    pub fn secure_key_import(
        prov_handle: Handle,
        key_length: Option<u32>,
        encryption_mode: Option<AesEncryptionMode>,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
    ) -> Self {
        Self(Arc::new(RwLock::new(AesKeyInner::secure_key_import(
            prov_handle,
            key_length,
            encryption_mode,
            key_data,
            digest_kind,
            import_key_handle,
        ))))
    }

    fn set_encryption_mode(&mut self, mode: AesEncryptionMode) {
        tracing::debug!(?mode, "Setting encryption mode");
        self.0.write().encryption_mode = Some(mode);
    }

    pub fn set_secret_handle(&mut self, handle: Secret) {
        self.0.write().secret_handle = Some(handle);
    }

    fn secret_handle(&self) -> Option<Secret> {
        self.0.read().secret_handle.clone()
    }

    pub fn get_encryption_mode(&self) -> Option<AesEncryptionMode> {
        self.0.read().encryption_mode
    }

    fn set_key_length(&mut self, key_length: u32) {
        self.0.write().key_length = Some(key_length);
    }

    fn key_length(&self) -> Option<u32> {
        self.0.read().key_length
    }

    pub fn set_hsm_handle(&self, hsm_handle: HsmKeyHandle) {
        self.0.write().base_key.hsm_handle = Some(hsm_handle);
    }

    fn hsm_key_handle(&self) -> Option<HsmKeyHandle> {
        self.0.read().base_key.hsm_handle.clone()
    }

    #[cfg(not(feature = "disable-fp"))]
    fn hsm_key_handle2(&self) -> Option<HsmKeyHandle> {
        self.0.read().hsm_handle2.clone()
    }

    pub fn key_origin(&self) -> KeyOrigin {
        self.0.read().base_key.get_key_origin()
    }

    pub fn set_key_origin(&mut self, key_origin: KeyOrigin) {
        tracing::debug!(?key_origin, "Setting key origin");
        self.0.write().base_key.set_key_origin(key_origin);
    }

    #[cfg(not(feature = "disable-fp"))]
    pub fn set_key_class(&mut self, key_class: KeyClass) -> AzIHsmHresult<()> {
        tracing::debug!(?key_class, "Setting key class");
        self.0.write().base_key.set_key_class(key_class)
    }

    pub fn key_class(&self) -> Option<KeyClass> {
        self.0.read().base_key.get_key_class()
    }

    /// Sets the property of the key.
    ///
    /// # Arguments
    ///  * `property` - The property to set.
    /// * `value` - The value of the property.
    ///
    /// # Returns
    /// `Ok(())` if the property was set successfully; otherwise, an error code.
    ///
    pub fn set_property(
        &mut self,
        property: &KeyPropertyIdentifier,
        value: &[u8],
    ) -> AzIHsmHresult<()> {
        tracing::debug!(?property, "Setting property of AES Key");

        match property {
            KeyPropertyIdentifier::KeyLength => {
                if value.len() != mem::size_of::<u32>() {
                    tracing::error!("Invalid key length");
                    Err(HRESULT(NTE_INVALID_PARAMETER))?;
                }

                let key_length = u32::from_le_bytes(value.try_into().map_err(|err| {
                    tracing::error!(?err, "Failed to get bytes");
                    HRESULT(NTE_INVALID_PARAMETER)
                })?);
                if key_length == 0 {
                    tracing::error!("Invalid key length of 0");
                    Err(HRESULT(NTE_INVALID_PARAMETER))?;
                }

                self.set_key_length(key_length);
                tracing::debug!(?key_length, "Set Key Length");
            }
            KeyPropertyIdentifier::ChainingMode => {
                let chaining_mode = PCWSTR::from_raw(value.as_ptr() as *mut u16);

                if pcwstr::equals(chaining_mode, BCRYPT_CHAIN_MODE_CBC) {
                    self.set_encryption_mode(AesEncryptionMode::CBC);
                } else if pcwstr::equals(chaining_mode, BCRYPT_CHAIN_MODE_GCM) {
                    #[cfg(not(feature = "disable-fp"))]
                    {
                        self.set_encryption_mode(AesEncryptionMode::GCM);
                        self.set_key_class(KeyClass::AesBulk)?;
                    }
                    #[cfg(feature = "disable-fp")]
                    {
                        Err(HRESULT(NTE_NOT_SUPPORTED))?;
                    }
                } else {
                    Err(HRESULT(NTE_INVALID_PARAMETER))?;
                }
            }
            KeyPropertyIdentifier::ClrEphemeral => {
                if value.len() != mem::size_of::<u8>() {
                    tracing::error!("Invalid CLR IsEphemeral value. Should be size of u8");
                    Err(HRESULT(NTE_INVALID_PARAMETER))?;
                }

                if value[0] != 1 {
                    tracing::error!("Invalid CLR IsEphemeral value. Should be 1");
                    Err(HRESULT(NTE_INVALID_PARAMETER))?;
                }
            }
            KeyPropertyIdentifier::Unknown => Err(HRESULT(NTE_INVALID_PARAMETER))?,
            _ => Err(HRESULT(NTE_NOT_SUPPORTED))?,
        }
        Ok(())
    }

    /// Assigns default AES key properties like `set_property`.
    /// If not set, following property will be defaulted to
    /// 1. Encryption Mode: CBC
    /// 2. Key Length: 128 bits
    pub fn assign_default(&mut self, _app_session: &HsmSession) -> AzIHsmHresult<()> {
        tracing::debug!("Assigning default AES key properties");

        if self.get_encryption_mode().is_none() {
            self.set_encryption_mode(AesEncryptionMode::CBC);
        }

        // NOTE: when importing wrapped AES key
        // key length is determined by firmware (calculated from size of the wrapped key)
        // So exact value here doesn't matter.
        // `set_key_length` will be called in `finalize_key` method with correct length from device.
        if self.key_length().is_none() {
            self.set_key_length(AES_KEY_SIZE_128);
        }

        Ok(())
    }

    /// Finalize the key. This function will create the key in the HSM.
    ///
    /// # Arguments
    ///   * `app_session` - The HsmSession to use for finalizing the key.
    ///
    /// # Returns
    ///    `Ok(())` if the key was finalized successfully; otherwise, an error code.
    ///
    pub fn finalize_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.hsm_key_handle().is_some() {
            tracing::error!("Hsm Key is already created. Cannot finalize again");
            Err(HRESULT(E_UNEXPECTED))?;
        }

        match self.key_origin() {
            KeyOrigin::Import => {
                if self.get_encryption_mode().is_none() {
                    tracing::error!("Aes Encryption Mode shouldn't be None");
                    Err(HRESULT(NTE_BAD_KEY))?;
                }
                let hsm_key_handle = self
                    .0
                    .write()
                    .base_key
                    .finalize_secure_import(app_session)?;
                let key_type = hsm_key_handle.kind();
                let key_class = self.key_class().ok_or(HRESULT(NTE_BAD_KEY))?;

                match (key_type, key_class) {
                    (KeyType::Aes128, KeyClass::Aes) => self.set_key_length(128),
                    (KeyType::Aes192, KeyClass::Aes) => self.set_key_length(192),
                    (KeyType::Aes256, KeyClass::Aes) => self.set_key_length(256),
                    (KeyType::AesBulk256, KeyClass::AesBulk) => self.set_key_length(256),
                    _ => {
                        tracing::error!(
                        "Mismatch between key type set by caller and the key type returned by the HSM. \
                        Value set by caller: {:?}; Value returned by HSM: {:?}",
                        key_class,
                        key_type
                    );
                        Err(HRESULT(NTE_BAD_TYPE))?;
                    }
                }
                Ok(())
            }
            KeyOrigin::Derive => {
                let secret = self.secret_handle().ok_or_else(|| {
                    tracing::error!("Secret handle not set!");
                    HRESULT(E_UNEXPECTED)
                })?;

                let encryption_mode = self.get_encryption_mode();
                if encryption_mode != Some(AesEncryptionMode::CBC) {
                    tracing::error!("Aes Encryption Mode should be CBC");
                    return Err(HRESULT(NTE_NOT_SUPPORTED));
                }

                let key_length = self.key_length();

                let key_type = match key_length {
                    Some(AES_KEY_SIZE_128) => KeyType::Aes128,
                    Some(AES_KEY_SIZE_192) => KeyType::Aes192,
                    Some(AES_KEY_SIZE_256) => KeyType::Aes256,
                    _ => {
                        tracing::error!("Invalid key length for AES CBC: {:?}", key_length);
                        return Err(HRESULT(NTE_BAD_LEN));
                    }
                };

                // Key Derivation
                let hsm_handle = secret.kdf_derive(app_session, key_type)?;
                self.set_hsm_handle(hsm_handle);
                tracing::debug!("Derived AES key hsm handle set successfully");
                Ok(())
            }
            KeyOrigin::Generate => self.0.write().finalize_key(app_session),
        }
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
        if let Some(handle) = self.0.read().hsm_handle2.as_ref() {
            match app_session.delete_key(handle) {
                Ok(_) => {}
                Err(err) => {
                    tracing::error!(?err, "Failed to delete hsm_handle2",);
                    Err(HRESULT(NTE_NO_KEY))?;
                }
            }
        } else {
            tracing::error!("hsm_handle2 is None");
        }

        self.0.write().base_key.delete_key(app_session)
    }

    /// AES CBC encrypt\decrypt operation.
    /// Encrypts\Decrypts the input data using the key.
    ///
    /// # Arguments
    ///   * `mode` - Specifies encrypt or decrypt mode
    ///   * `app_session` - The HsmSession to use for encryption\decryption.
    ///   * `input` - The data to encrypt\decrypt.
    ///   * `iv` - The initialization vector.
    ///   * `output` - The encrypted\decrypted data.
    ///   * `result` - The encrypted\decrypted data size in bytes.
    ///
    /// # Returns
    ///   `Ok(())` if the data was encrypted\decrypted successfully; otherwise, an error code.
    ///
    pub fn encrypt_decrypt_cbc(
        &self,
        mode: AesMode,
        app_session: &HsmSession,
        input: &[u8],
        iv: &mut [u8],
        output: &mut [u8],
        output_size: &mut u32,
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        validate_output_buffer!(output, output_size, input.len() as u32);

        if iv.len() != AZIHSM_CIPHERPADDINGINFO_CBC_IVSIZE {
            tracing::error!(
                iv_len = iv.len(),
                "Aes Encryption Mode - CBC: Invalid IV length"
            );
            Err(HRESULT::from_win32(ERROR_INVALID_DATA))?;
        }
        let mut iv_in = [0u8; AZIHSM_CIPHERPADDINGINFO_CBC_IVSIZE];
        iv_in.copy_from_slice(&iv[..AZIHSM_CIPHERPADDINGINFO_CBC_IVSIZE]);

        let data_result =
            match app_session.aes_encrypt_decrypt(&hsm_key_handle, mode, input.to_vec(), iv_in) {
                Ok(data_result) => data_result,
                Err(err) => {
                    tracing::error!(?err, "HsmSession::aes_encrypt_decrypt - {:?} failed", mode);
                    Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
                }
            };
        output[..data_result.data.len()].copy_from_slice(&data_result.data);
        *output_size = data_result.data.len() as u32;

        iv.copy_from_slice(&data_result.iv);

        tracing::debug!("Aes Encryption Mode - CBC: {:?} data successful", mode);
        Ok(())
    }

    /// AES GCM encrypt\decrypt operation.
    /// Encrypts\Decrypts the input data using the key
    ///
    /// # Arguments
    ///   * `app_session` - The HsmSession to use for encryption\decryption.
    ///  * `params` - The parameters for the AES GCM operation.
    ///
    /// # Returns
    ///   `Ok(())` if the data was encrypted\decrypted successfully; otherwise, an error code.
    ///
    #[cfg(not(feature = "disable-fp"))]
    pub fn encrypt_decrypt_gcm(
        &self,
        app_session: &HsmSession,
        params: AesGcmParams,
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT::from_win32(ERROR_INVALID_STATE))?
            }
        };

        validate_output_buffer!(params.output, params.output_size, params.input.len() as u32);

        if params.iv.len() != AZIHSM_CIPHERPADDINGINFO_GCM_IVSIZE {
            tracing::error!("Aes Encryption Mode - GCM: Invalid IV length");
            Err(HRESULT::from_win32(ERROR_INVALID_DATA))?;
        }
        let mut iv_in = [0u8; AZIHSM_CIPHERPADDINGINFO_GCM_IVSIZE];
        iv_in.copy_from_slice(&params.iv[..AZIHSM_CIPHERPADDINGINFO_GCM_IVSIZE]);

        if params.tag.len() != AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE {
            tracing::error!("Aes Encryption Mode - GCM: Invalid Tag length");
            Err(HRESULT::from_win32(ERROR_INVALID_DATA))?;
        }
        let Ok(tag_in): Result<[u8; AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE], _> =
            params.tag[..AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE].try_into()
        else {
            tracing::error!("Aes Encryption Mode - GCM: Invalid Tag length");
            Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
        };

        let aad_in = match params.aad {
            Some(aad_vec) => {
                if !aad_vec.is_empty() {
                    Some(aad_vec.clone())
                } else {
                    tracing::debug!("Aes Encryption Mode - GCM: AuthData input buffer is empty");
                    None
                }
            }
            None => {
                tracing::debug!("Aes Encryption Mode - GCM: AuthData input is NULL");
                None
            }
        };

        let data_result = match app_session.aes_gcm_encrypt_decrypt(
            &hsm_key_handle,
            params.mode,
            params.input.to_vec(),
            iv_in,
            aad_in,
            Some(tag_in),
        ) {
            Ok(data_result) => data_result,
            Err(err) => {
                tracing::error!(
                    ?err,
                    "HsmSession::aes_gcm_encrypt_decrypt - {:?} failed.",
                    params.mode
                );
                Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
            }
        };
        params.output[..data_result.data.len()].copy_from_slice(&data_result.data);
        *params.output_size = data_result.data.len() as u32;

        match params.mode {
            AesMode::Encrypt => {
                if let Some(ref tag_data) = data_result.tag {
                    params.tag.copy_from_slice(tag_data);
                } else {
                    tracing::error!(
                        "aes_gcm_encrypt_decrypt - TAG not produced for AES GCM encryption"
                    );
                    Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
                }
            }
            AesMode::Decrypt => (),
        };

        tracing::debug!(
            "Aes Encryption Mode - GCM: {:?} data successful",
            params.mode
        );
        Ok(())
    }

    /// AES XTS encrypt/decrypt operation.
    /// Encrypts or decrypts the input data using the key, based on the mode specified.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use for encryption or decryption.
    /// * `mode` - The mode of operation, either `AesMode::Encrypt` or `AesMode::Decrypt`.
    /// * `input` - The input data to encrypt or decrypt.
    /// * `tweak` - The tweak data.
    /// * `output` - The output buffer to store the encrypted or decrypted data.
    /// * `output_size` - The size of the output buffer.
    ///
    /// # Returns
    /// `Ok(())` if the data was processed successfully; otherwise, an error code.
    ///
    #[cfg(not(feature = "disable-fp"))]
    pub fn encrypt_decrypt_xts(
        &self,
        app_session: &HsmSession,
        mode: AesMode,
        input: &[u8],
        tweak: &[u8],
        output: &mut [u8],
        output_size: &mut u32,
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot encrypt/decrypt at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let hsm_key_handle2 = match self.hsm_key_handle2() {
            Some(hsm_key_handle2) => hsm_key_handle2,
            None => {
                tracing::error!("HSM Key 2 is not created, cannot encrypt/decrypt at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        if tweak.len() != AZIHSM_CIPHERPADDINGINFO_XTS_TWEAKSIZE {
            tracing::error!("Invalid Tweak length");
            Err(HRESULT(NTE_INVALID_PARAMETER))?
        }

        let tweak_array: [u8; AZIHSM_CIPHERPADDINGINFO_XTS_TWEAKSIZE] = tweak
            [..AZIHSM_CIPHERPADDINGINFO_XTS_TWEAKSIZE]
            .try_into()
            .map_err(|_| {
                tracing::error!("Invalid Tweak length");
                HRESULT(NTE_INVALID_PARAMETER)
            })?;

        validate_output_buffer!(output, output_size, input.len() as u32);

        let data_result = app_session
            .aes_xts_encrypt_decrypt(
                mode,
                &hsm_key_handle,
                &hsm_key_handle2,
                input.len(),
                tweak_array,
                input.to_vec(),
            )
            .map_err(|err| {
                tracing::error!(?err, "HsmSession::aes_encrypt_decrypt - {:?} failed.", mode,);
                HRESULT::from_win32(ERROR_INVALID_DATA)
            })?;

        output[..data_result.data.len()].copy_from_slice(&data_result.data);
        *output_size = data_result.data.len() as u32;
        tracing::debug!("Aes XTS: Data {:?} successfully", mode);
        Ok(())
    }

    /// Gets the property of the key.
    ///
    /// # Arguments
    ///  * `property` - The property to get.
    ///  * `value` - The output buffer to store the property value.
    ///  * `value_size` - The size of the output buffer.
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
            KeyPropertyIdentifier::AuthTagLength => {
                #[cfg(feature = "disable-fp")]
                {
                    return Err(HRESULT(NTE_INVALID_PARAMETER));
                }
                #[cfg(not(feature = "disable-fp"))]
                {
                    let tag_length = AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE as u32;
                    let tag_length_bytes = tag_length.to_le_bytes();
                    let required_size = tag_length_bytes.len() as u32;

                    validate_output_buffer!(value, value_size, required_size);

                    value[..required_size as usize].copy_from_slice(&tag_length_bytes);
                    *value_size = required_size;
                }
            }
            KeyPropertyIdentifier::ChainingMode => {
                let chaining_mode = match self.get_encryption_mode() {
                    Some(AesEncryptionMode::CBC) => BCRYPT_CHAIN_MODE_CBC,
                    #[cfg(not(feature = "disable-fp"))]
                    Some(AesEncryptionMode::GCM) => BCRYPT_CHAIN_MODE_GCM,
                    _ => return Err(HRESULT(E_INVALIDARG)),
                };

                if pcwstr::copy_pcwstr_to_slice(chaining_mode, value, value_size) == 0 {
                    return Err(HRESULT(NTE_INVALID_PARAMETER));
                }
            }
            KeyPropertyIdentifier::KeyLength => {
                let output: [u8; 4] = self.key_length().unwrap_or(0).to_le_bytes();
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
}

#[derive(Debug)]
struct AesKeyInner {
    base_key: BaseKey,
    encryption_mode: Option<AesEncryptionMode>,
    key_length: Option<u32>,
    hsm_handle2: Option<HsmKeyHandle>, // This property is only applicable to AES XTS mode
    secret_handle: Option<Secret>,     // Caches a reference to the secret object, used for invoking
                                       // the key derivation method in the Secret class in Finalize
}

impl AesKeyInner {
    pub fn new(
        provider_handle: Handle,
        key_length: Option<u32>,
        encryption_mode: Option<AesEncryptionMode>,
    ) -> Self {
        Self {
            base_key: BaseKey::new(provider_handle),
            encryption_mode,
            key_length,
            hsm_handle2: None,
            secret_handle: None,
        }
    }

    pub fn secure_key_import(
        prov_handle: Handle,
        key_length: Option<u32>,
        encryption_mode: Option<AesEncryptionMode>,
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
                Some(KeyUsage::EncryptDecrypt),
                KeyClass::Aes,
            ),
            key_length,
            encryption_mode,
            hsm_handle2: None,
            secret_handle: None,
        }
    }

    pub fn finalize_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.base_key.hsm_handle.clone().is_some() {
            tracing::error!("Hsm Key is already created");
            Err(HRESULT(E_UNEXPECTED))?
        }

        // Helper closure to generate an AES key
        let generate_key =
            |app_session: &HsmSession, key_size: AesKeySize| -> AzIHsmHresult<HsmKeyHandle> {
                app_session
                    .aes_generate(
                        key_size,
                        None,
                        KeyProperties {
                            key_usage: KeyUsage::EncryptDecrypt,
                            key_availability: KeyAvailability::Session,
                        },
                    )
                    .map_err(|err| {
                        tracing::error!(?err, "HsmSession::aes_generate failed",);
                        HRESULT(E_UNEXPECTED)
                    })
            };

        let key_size = match self.encryption_mode {
            Some(AesEncryptionMode::CBC) => {
                match self.key_length {
                    Some(AES_KEY_SIZE_128) => AesKeySize::Aes128,
                    Some(AES_KEY_SIZE_192) => AesKeySize::Aes192,
                    Some(AES_KEY_SIZE_256) => AesKeySize::Aes256,
                    _ => {
                        tracing::error!("Aes Encryption Mode - CBC: Invalid key length: should be 128, 192 or 256");
                        return Err(HRESULT(E_INVALIDARG));
                    }
                }
            }
            #[cfg(not(feature = "disable-fp"))]
            Some(AesEncryptionMode::GCM) => {
                if self.key_length != Some(256) {
                    tracing::error!("Aes Encryption Mode - GCM: Invalid key length: should be 256");
                    Err(HRESULT(E_INVALIDARG))?;
                }
                AesKeySize::AesBulk256
            }
            #[cfg(not(feature = "disable-fp"))]
            Some(AesEncryptionMode::XTS) => match self.key_length {
                Some(512) => AesKeySize::AesBulk256,
                _ => {
                    tracing::error!("Aes Encryption Mode - XTS: Invalid key length: should be 512");
                    return Err(HRESULT(E_INVALIDARG));
                }
            },
            None => {
                tracing::error!("Aes Encryption Mode: Unknown");
                return Err(HRESULT::from_win32(ERROR_INVALID_STATE));
            }
        };

        self.base_key.hsm_handle = Some(generate_key(app_session, key_size)?);

        #[cfg(not(feature = "disable-fp"))]
        if self.encryption_mode == Some(AesEncryptionMode::XTS) {
            self.hsm_handle2 = Some(generate_key(app_session, key_size)?);
        }

        Ok(())
    }
}
