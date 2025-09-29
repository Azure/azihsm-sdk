// Copyright (C) Microsoft Corporation. All rights reserved.

use std::cmp;
use std::ops::BitAnd;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use lazy_static::lazy_static;
use mcr_api_resilient::AesMode;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::EccCurve;
use mcr_api_resilient::HsmApiRevision;
use mcr_api_resilient::HsmApiRevisionRange;
use mcr_api_resilient::HsmAppCredentials;
use mcr_api_resilient::HsmDevice;
use mcr_api_resilient::HsmSession;
use mcr_api_resilient::KeyType;
use mcr_api_resilient::ManticoreCertificate;
use mcr_api_resilient::RsaSignaturePadding;
use p256::pkcs8::DecodePublicKey;
use parking_lot::RwLock;
use uuid::Uuid;
use winapi::ctypes::c_void;
use winapi::shared::winerror::ERROR_INVALID_STATE;
use winapi::shared::winerror::ERROR_LOCK_FAILED;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_BAD_TYPE;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_HANDLE;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use winapi::shared::winerror::NTE_PROVIDER_DLL_FAIL;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use super::AZIHSM_DEVICE_CERT_CHAIN_PROPERTY;
use super::AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY;
use super::AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY;
use super::BCRYPT_PKCS11_RSA_AES_WRAP_BLOB;
use super::BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC;
use super::REPORT_DATA_SIZE;
use crate::bcrypt_util;
use crate::handle_table::*;
use crate::helpers::app_session_ref;
use crate::helpers::cast_ptr;
use crate::helpers::cast_void_ptr;
use crate::helpers::create_mut_slice_from_raw_parts;
use crate::helpers::create_slice_from_raw_parts;
use crate::helpers::key_func_call;
use crate::helpers::key_obj;
use crate::key::aes_key::*;
use crate::key::base_key::*;
use crate::key::ecdh_key::*;
use crate::key::ecdsa_key::*;
use crate::key::rsa_key::*;
use crate::key::secret::*;
use crate::pcwstr;

lazy_static! {
    static ref APP_CREDENTIALS_MUTEX: Mutex<Option<HsmAppCredentials>> = Mutex::new(None);
}

// Copied from virtual Manticore
// The max number of keys a table can hold
const AZIHSM_MAX_TABLE_KEY_COUNT: u32 = 256;
// The max amount of info a table can hold, in KB
const AZIHSM_MAX_TABLE_KILOBYTES: u32 = 16;

// Note: ACTIVE_APP_SESSION_COUNT is protected by APP_CREDENTIALS_MUTEX.
static ACTIVE_APP_SESSION_COUNT: AtomicU32 = AtomicU32::new(0);

// 70FCF730-B876-4238-B835-8010CE8A3F76
const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

// DB3DC77F-C22E-4300-80D4-1B31B6F04800
const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

const SUPPORTED_API_REV_RANGE: HsmApiRevisionRange = HsmApiRevisionRange {
    min: HsmApiRevision { major: 1, minor: 0 },
    max: HsmApiRevision { major: 1, minor: 0 },
};

#[derive(Debug, PartialEq)]
pub(crate) enum ProviderPropertyIdentifier {
    AzIHsmDeviceCertChain, // AZIHSM_DEVICE_CERT_CHAIN_PROPERTY
    AziHsmMaxKeyCount,     // AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY
    AziHsmMaxStorageSize,  // AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY
    Unknown,
}

impl From<PCWSTR> for ProviderPropertyIdentifier {
    fn from(id: PCWSTR) -> ProviderPropertyIdentifier {
        if pcwstr::equals(id, AZIHSM_DEVICE_CERT_CHAIN_PROPERTY) {
            ProviderPropertyIdentifier::AzIHsmDeviceCertChain
        } else if pcwstr::equals(id, AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY) {
            ProviderPropertyIdentifier::AziHsmMaxKeyCount
        } else if pcwstr::equals(id, AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY) {
            ProviderPropertyIdentifier::AziHsmMaxStorageSize
        } else {
            ProviderPropertyIdentifier::Unknown
        }
    }
}

pub(crate) struct AesEncDecParams<'a> {
    pub mode: AesMode,
    pub aes_key: &'a AesKey,
    pub input: &'a [u8],
    pub ppaddinginfo: *const c_void,
    pub output: &'a mut [u8],
    pub result: &'a mut u32,
    pub flags: NCRYPT_FLAGS,
}

pub(crate) struct RsaEncDecParams<'a> {
    pub key: &'a RsaKey,
    pub input: &'a [u8],
    pub ppaddinginfo: *const c_void,
    pub output: &'a mut [u8],
    pub result: &'a mut u32,
    pub flags: NCRYPT_FLAGS,
    pub is_encrypt: bool,
}

pub(crate) struct EncDecParams<'a> {
    pub is_encrypt: bool,
    pub key_handle: Handle,
    pub input: &'a [u8],
    pub ppaddinginfo: *const c_void,
    pub output: &'a mut [u8],
    pub result: &'a mut u32,
    pub flags: NCRYPT_FLAGS,
}

/// Provider
#[derive(Default, Clone)]
pub(crate) struct Provider {
    inner: Arc<RwLock<ProviderInner>>,
}

impl Provider {
    /// Sets the handle of the provider.
    ///
    /// # Arguments
    /// * `handle` - The handle of the provider.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_set_handle")]
    pub fn set_handle(&self, handle: Handle) {
        self.inner.write().set_handle(handle);
    }

    /// Returns the handle of the provider.
    ///
    /// # Returns
    /// The handle of the provider.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_handle")]
    pub fn handle(&self) -> Handle {
        self.inner.read().handle()
    }

    /// Adds a key to the provider.
    ///
    /// # Arguments
    /// * `key` - The key to add.
    ///
    /// # Returns
    /// The handle of the key.
    ///
    fn add_key(&self, key: Key) -> Handle {
        self.inner.write().keys.insert(key)
    }

    /// Gets a key from the provider.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the key to get.
    ///
    /// # Returns
    /// The key, if found; otherwise, `None`.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_get_key")]
    pub fn get_key(&self, key_handle: Handle) -> Option<Key> {
        key_obj!(self, key_handle)
    }

    /// Removes a key from the provider.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the key to remove.
    ///
    /// # Returns
    /// The key, if found; otherwise, `None`.
    ///
    fn remove_key(&self, key_handle: Handle) -> Option<Key> {
        self.inner.write().keys.remove(key_handle)
    }

    /// Adds a secret to the provider.
    ///
    /// # Arguments
    /// * `secret` - The secret handle to add.
    ///
    /// # Returns
    /// The handle of the secret.
    ///
    fn add_secret(&self, secret: Secret) -> Handle {
        self.inner.write().secrets.insert(secret)
    }

    /// Gets a secret from the provider.
    ///
    /// # Arguments
    /// * `secret_handle` - The handle of the secret to get.
    ///
    /// # Returns
    /// The secret, if found; otherwise, `None`.
    ///
    fn get_secret(&self, secret_handle: Handle) -> Option<Secret> {
        self.inner.read().secrets.get(secret_handle)
    }

    /// Removes a secret from the provider.
    ///
    /// # Arguments
    /// * `secret_handle` - The handle of the secret to remove.
    ///
    /// # Returns
    /// The secret, if found; otherwise, `None`.
    ///
    fn remove_secret(&self, secret_handle: Handle) -> Option<Secret> {
        self.inner.write().secrets.remove(secret_handle)
    }

    /// Helper function to handle AES Encrypt\Decrypt
    ///
    /// # Arguments
    /// *params* - AesEncDecParams struct containing the parameters for AES encryption\decryption.
    ///
    /// # Returns
    /// `Ok(())` if the data was encrypted\decrypted successfully;
    ///  otherwise, an error code.
    ///
    fn encrypt_decrypt_aes(&self, params: AesEncDecParams) -> Result<(), HRESULT> {
        self.validate_flags_aes(params.flags)?;

        let padding_info = self.get_padding_info(params.flags, params.ppaddinginfo)?;

        match params.aes_key.get_encryption_mode() {
            Some(AesEncryptionMode::CBC) => self.encrypt_decrypt_cbc(params, padding_info),
            #[cfg(not(feature = "disable-fp"))]
            Some(AesEncryptionMode::GCM) => self.encrypt_decrypt_gcm(params, padding_info),
            #[cfg(not(feature = "disable-fp"))]
            Some(AesEncryptionMode::XTS) => self.encrypt_decrypt_xts(params, padding_info),
            None => {
                tracing::error!("Aes Encryption mode not set!");
                Err(HRESULT::from_win32(ERROR_INVALID_STATE))
            }
        }
    }

    fn validate_flags_aes(&self, flags: NCRYPT_FLAGS) -> Result<(), HRESULT> {
        if flags.bitand(
            !(NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG)
                | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG)
                | NCRYPT_SILENT_FLAG),
        ) != NCRYPT_FLAGS(0)
        {
            tracing::error!("Bad flags provided for AES encryption/decryption");
            Err(HRESULT(NTE_BAD_FLAGS))
        } else {
            Ok(())
        }
    }

    fn get_padding_info(
        &self,
        flags: NCRYPT_FLAGS,
        ppaddinginfo: *const c_void,
    ) -> Result<&NCRYPT_CIPHER_PADDING_INFO, HRESULT> {
        if flags.contains(NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG)) && !ppaddinginfo.is_null() {
            let padding_info: &NCRYPT_CIPHER_PADDING_INFO = cast_void_ptr!(ppaddinginfo);
            if padding_info.cbSize != std::mem::size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32 {
                Err(HRESULT(NTE_INVALID_PARAMETER))
            } else {
                Ok(padding_info)
            }
        } else {
            tracing::error!(
                "Aes Encryption: both NCRYPT_PAD_CIPHER_FLAG in flags and Padding Info should be provided"
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))
        }
    }

    fn encrypt_decrypt_cbc(
        &self,
        params: AesEncDecParams,
        padding_info: &NCRYPT_CIPHER_PADDING_INFO,
    ) -> Result<(), HRESULT> {
        let iv = if padding_info.cbIV > 0 && !padding_info.pbIV.is_null() {
            create_mut_slice_from_raw_parts!(padding_info.pbIV, padding_info.cbIV as usize)
        } else {
            tracing::error!(
                "Aes Encryption Mode - CBC: Invalid IV (cbIV must be greater than zero, and pbIV must be non-null)",
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))?
        };

        params.aes_key.encrypt_decrypt_cbc(
            params.mode,
            app_session_ref!(self),
            params.input,
            iv,
            params.output,
            params.result,
        )
    }

    #[cfg(not(feature = "disable-fp"))]
    fn encrypt_decrypt_gcm(
        &self,
        params: AesEncDecParams,
        padding_info: &NCRYPT_CIPHER_PADDING_INFO,
    ) -> Result<(), HRESULT> {
        let other_padding_info = self.get_other_padding_info(params.flags, padding_info)?;

        let iv = self.get_iv_gcm(other_padding_info)?;
        let mut default_tag = [0u8; AZIHSM_AUTHCIPHERMODEINFO_GCM_TAGSIZE];
        let tag = self
            .get_tag_gcm(other_padding_info)
            .unwrap_or(&mut default_tag);

        let aad = self.get_aad_gcm(other_padding_info)?;

        let gcm_params = AesGcmParams {
            mode: params.mode,
            input: params.input,
            iv,
            aad,
            tag,
            output: params.output,
            output_size: params.result,
        };

        params
            .aes_key
            .encrypt_decrypt_gcm(app_session_ref!(self), gcm_params)
    }

    #[cfg(not(feature = "disable-fp"))]
    fn get_other_padding_info(
        &self,
        flags: NCRYPT_FLAGS,
        padding_info: &NCRYPT_CIPHER_PADDING_INFO,
    ) -> Result<&BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, HRESULT> {
        if flags.contains(NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG))
            && !padding_info.pbOtherInfo.is_null()
            && padding_info.cbOtherInfo
                >= std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32
        {
            let other_padding_info: &BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
                cast_void_ptr!(padding_info.pbOtherInfo);
            if other_padding_info.cbSize
                != std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32
            {
                Err(HRESULT(NTE_INVALID_PARAMETER))
            } else {
                Ok(other_padding_info)
            }
        } else {
            tracing::error!(
                "Aes Encryption Mode - GCM: pbOtherInfo field of paddingInfo is invalid"
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))
        }
    }

    #[cfg(not(feature = "disable-fp"))]
    fn get_iv_gcm(
        &self,
        other_padding_info: &BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    ) -> Result<&mut [u8], HRESULT> {
        if other_padding_info.cbNonce > 0 && !other_padding_info.pbNonce.is_null() {
            Ok(create_mut_slice_from_raw_parts!(
                other_padding_info.pbNonce,
                other_padding_info.cbNonce as usize
            ))
        } else {
            tracing::error!(
                "Aes Encryption Mode - GCM: Invalid Nonce (cbNonce must be greater than zero, and pbNonce must be non-null)",
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))
        }
    }

    #[cfg(not(feature = "disable-fp"))]
    fn get_tag_gcm(
        &self,
        other_padding_info: &BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    ) -> Result<&mut [u8], HRESULT> {
        if other_padding_info.cbTag > 0 && !other_padding_info.pbTag.is_null() {
            Ok(create_mut_slice_from_raw_parts!(
                other_padding_info.pbTag,
                other_padding_info.cbTag as usize
            ))
        } else {
            Err(HRESULT(NTE_INVALID_PARAMETER))
        }
    }

    #[cfg(not(feature = "disable-fp"))]
    fn get_aad_gcm(
        &self,
        other_padding_info: &BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    ) -> Result<Option<Vec<u8>>, HRESULT> {
        if other_padding_info.cbAuthData > 0 && !other_padding_info.pbAuthData.is_null() {
            let aad_slice = create_slice_from_raw_parts!(
                other_padding_info.pbAuthData,
                other_padding_info.cbAuthData as usize
            );
            let aad_vec = aad_slice.to_vec();
            Ok(Some(aad_vec))
        } else {
            Ok(None)
        }
    }

    #[cfg(not(feature = "disable-fp"))]
    fn encrypt_decrypt_xts(
        &self,
        params: AesEncDecParams,
        padding_info: &NCRYPT_CIPHER_PADDING_INFO,
    ) -> Result<(), HRESULT> {
        let tweak = if padding_info.cbIV > 0 && !padding_info.pbIV.is_null() {
            create_slice_from_raw_parts!(padding_info.pbIV, padding_info.cbIV as usize)
        } else {
            tracing::error!(
                "Aes Encryption Mode - XTS: Invalid tweak (cbIV must be greater than zero, and pbIV must be non-null)",
            );
            return Err(HRESULT(NTE_INVALID_PARAMETER));
        };

        params.aes_key.encrypt_decrypt_xts(
            app_session_ref!(self),
            params.mode,
            params.input,
            tweak,
            params.output,
            params.result,
        )
    }

    /// Helper function to handle RSA Encrypt\Decrypt
    ///
    /// # Arguments
    /// *params* - RsaEncDecParams struct containing the parameters for RSA encryption\decryption.
    ///
    /// # Returns
    /// `Ok(())` if the data was encrypted\decrypted successfully;
    /// otherwise, an error code.
    ///
    fn encrypt_decrypt_rsa(&self, params: RsaEncDecParams) -> Result<(), HRESULT> {
        // Check for invalid flags
        if params
            .flags
            .bitand(!(NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG))
            != NCRYPT_FLAGS(0)
        {
            tracing::error!(
                "Bad flags provided for RSA encryption/decryption {:?}",
                params.flags
            );
            Err(HRESULT(NTE_BAD_FLAGS))?
        }

        // Ensure that NCRYPT_PAD_OAEP_FLAG is present
        if !params.flags.contains(NCRYPT_PAD_OAEP_FLAG) {
            tracing::error!("NCRYPT_PAD_OAEP_FLAG is required for RSA encryption/decryption");
            Err(HRESULT(NTE_INVALID_PARAMETER))?
        }

        // [TODO] Review if the padding info needs to be mandatory.
        let mut digest_kind: Option<DigestKind> = None;
        let mut label: Option<&[u8]> = None;
        if params.flags.contains(NCRYPT_PAD_OAEP_FLAG) && !params.ppaddinginfo.is_null() {
            let padding_info: &BCRYPT_OAEP_PADDING_INFO = cast_void_ptr!(params.ppaddinginfo);

            // ensure the algorithm ID string isn't null, and convert it into a
            // `DigestKind` enum
            let alg_id = padding_info.pszAlgId;
            if alg_id.is_null() {
                tracing::error!("AlgId in padding info is null");
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            }
            digest_kind = pcwstr::digest_kind(alg_id);
            if digest_kind.is_none() {
                tracing::error!("Unsupported algorithm in padding info");
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            }

            // check for a non-null label pointer and a non-zero label length
            let label_ptr = padding_info.pbLabel;
            let label_len = padding_info.cbLabel as usize;
            if label_ptr.is_null() && label_len != 0 {
                tracing::error!(
                    "Padding info label pointer is null, but a non-zero label length was specified"
                );
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            } else if !label_ptr.is_null() && label_len == 0 {
                tracing::error!(
                    "Padding info label pointer is non-null, but the label length was set to zero"
                );
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            } else if label_ptr.is_null() {
                // from_raw_parts does not support null ptr
                label = Some(&[]);
            } else {
                // if above checks above succeed, then we have a non-null label
                // pointer and a non-zero label length; convert the label
                // pointer (`*mut u8`) into a slice of the appropriate length
                label = unsafe { Some(std::slice::from_raw_parts(label_ptr, label_len)) };
            }

            tracing::debug!("RSA OAEP Padding with {:?}", digest_kind);
        }
        params.key.encrypt_decrypt(
            app_session_ref!(self),
            params.input,
            digest_kind,
            label,
            params.output,
            params.result,
            params.is_encrypt,
        )
    }

    /// Opens an app session.
    ///
    /// # Returns
    /// `Ok(())` if the app session was opened successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_open_app_session")]
    pub fn open_app_session(&mut self) -> Result<(), HRESULT> {
        self.inner.write().open_app_session()
    }

    /// Closes an app session.
    ///
    /// # Returns
    /// `Ok(())` if the app session was closed successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_close_app_session")]
    pub fn close_app_session(&mut self) -> Result<(), HRESULT> {
        self.inner.write().close_app_session()
    }

    /// Create a key.
    ///
    /// # Arguments
    /// * `kind` - The kind of key to create.
    ///
    /// # Returns
    /// The key.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_create_key")]
    pub fn create_key(&self, kind: KeyKind) -> Key {
        match kind {
            KeyKind::Aes {
                key_length,
                encryption_mode,
            } => Key::Aes(AesKey::new(self.handle(), key_length, encryption_mode)),
            KeyKind::Ecdsa { curve_type } => Key::Ecdsa(EcdsaKey::new(self.handle(), curve_type)),
            KeyKind::Rsa { key_length } => Key::Rsa(RsaKey::new(self.handle(), key_length)),
            KeyKind::Ecdh { curve_type } => Key::Ecdh(EcdhKey::new(self.handle(), curve_type)),
        }
    }

    /// Create and add a key to the handle table.
    ///
    /// # Arguments
    /// * `kind` - The kind of key to create.
    ///
    /// # Returns
    /// The handle of the key.
    ///
    #[cfg_attr(
        feature = "expose-symbols",
        export_name = "provider_create_and_add_key"
    )]
    pub fn create_and_add_key(&self, kind: KeyKind) -> Handle {
        let key = self.create_key(kind);
        self.add_key(key.clone())
    }

    /// Create a Secret.
    ///
    ///  Creates a new secret and sets the hsm_handle to none.
    ///  and adds the secret handle to secret handle table.
    ///
    /// # Returns
    /// `Ok(handle)` if the secret was created successfully; otherwise, an error code.
    ///
    fn create_secret(&self) -> Handle {
        let secret = Secret::new();
        self.add_secret(secret.clone())
    }

    /// Deletes a key.
    ///
    /// # Arguments
    /// * `handle` - The handle of the key to delete.
    ///
    /// # Returns
    /// `Ok(())` if the key was deleted successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_delete_key")]
    pub fn delete_key(&self, key_handle: Handle) -> Result<(), HRESULT> {
        let key = match self.get_key(key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        key_func_call!(mut key, delete_key, app_session_ref!(self), ?);
        self.remove_key(key_handle);
        Ok(())
    }

    /// Deletes a secret.
    ///
    /// # Arguments
    /// * `handle` - The handle of the secret to delete.
    ///
    /// # Returns
    /// `Ok(())` if the secret was deleted successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_delete_secret")]
    pub fn delete_secret(&self, secret_handle: Handle) -> Result<(), HRESULT> {
        let mut secret = match self.get_secret(secret_handle) {
            Some(secret) => secret,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        secret.delete_secret(app_session_ref!(self))?;
        self.remove_secret(secret_handle);
        Ok(())
    }

    /// Set a key property.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the key to set the property on.
    /// * `property` - The property to set.
    /// * `value` - The value to set the property to.
    ///
    /// # Returns
    /// `Ok(())` if the property was set successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_set_key_property")]
    pub fn set_key_property(
        &self,
        key_handle: Handle,
        property: &KeyPropertyIdentifier,
        value: &[u8],
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        key_func_call!(mut key, set_property, property, value)
    }

    /// Get a key property.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the key to get the property from.
    /// * `property` - The property to get.
    /// * `value` - The value of the property.
    /// * `result` - The size of the value.
    ///
    /// # Returns
    /// `Ok(())` if the property was retrieved successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_get_key_property")]
    pub fn get_key_property(
        &self,
        key_handle: Handle,
        property: &KeyPropertyIdentifier,
        value: &mut [u8],
        result: &mut u32,
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        key_func_call!(key, get_property, property, value, result)
    }

    /// Assign default value to a key before finalizing it.
    /// If user creates a key without NCRYPT_DO_NOT_FINALIZE_FLAG, we need to assign default values.
    ///
    /// # Arguments
    /// * `handle` - The handle of the key to assign default value.
    ///
    /// # Returns
    /// `Ok(())` if the operation successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_assign_default")]
    pub fn assign_default(&self, key_handle: Handle) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        key_func_call!(mut key, assign_default, app_session_ref!(self))
    }

    /// Finalize a key.
    ///
    /// # Arguments
    /// * `handle` - The handle of the key to finalize.
    ///
    /// # Returns
    /// `Ok(())` if the key was finalized successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_finalize_key")]
    pub fn finalize_key(&self, key_handle: Handle) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        key_func_call!(mut key, finalize_key, app_session_ref!(self))
    }

    /// Encrypts\decrypts the input data using the key.
    ///
    /// # Arguments
    /// *params* - EncDecParams struct containing the parameters for encryption\decryption.
    ///
    /// # Returns
    /// `Ok(())` if the data was encrypted\decrypted successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_encrypt_decrypt")]
    pub fn encrypt_decrypt(&self, params: EncDecParams) -> Result<(), HRESULT> {
        let key_handle = params.key_handle;
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        match key {
            Key::Aes(key) => {
                let mode = if params.is_encrypt {
                    AesMode::Encrypt
                } else {
                    AesMode::Decrypt
                };
                tracing::debug!(?mode, "AES Encrypt/Decrypt");

                let aes_params = AesEncDecParams {
                    mode,
                    aes_key: &key,
                    input: params.input,
                    ppaddinginfo: params.ppaddinginfo,
                    output: params.output,
                    result: params.result,
                    flags: params.flags,
                };

                self.encrypt_decrypt_aes(aes_params)
            }

            Key::Rsa(key) => {
                let rsa_params = RsaEncDecParams {
                    key: &key,
                    input: params.input,
                    ppaddinginfo: params.ppaddinginfo,
                    output: params.output,
                    result: params.result,
                    flags: params.flags,
                    is_encrypt: params.is_encrypt,
                };
                tracing::debug!(is_encrypt = params.is_encrypt, "RSA Encrypt/Decrypt");

                self.encrypt_decrypt_rsa(rsa_params)
            }
            _ => Err(HRESULT(NTE_NOT_SUPPORTED))?,
        }
    }

    /// Internal method to get the padding information for RSA.
    fn padding_info_rsa(
        &self,
        ppaddinginfo: *const c_void,
        flags: NCRYPT_FLAGS,
    ) -> Result<(Option<DigestKind>, Option<u16>, RsaSignaturePadding), HRESULT> {
        let mut digest_kind: Option<DigestKind> = None;
        let mut salt_len: Option<u16> = None;
        let mut padding: RsaSignaturePadding = RsaSignaturePadding::Pkcs1_5;

        let validate_alg_arg = |alg_id: PCWSTR| -> Result<(), HRESULT> {
            if alg_id.is_null() {
                tracing::error!("AlgId in padding info is null");
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            }
            Ok(())
        };

        if !ppaddinginfo.is_null() {
            if flags.contains(NCRYPT_PAD_PKCS1_FLAG) {
                let padding_info: &BCRYPT_PKCS1_PADDING_INFO = cast_void_ptr!(ppaddinginfo);
                validate_alg_arg(padding_info.pszAlgId)?;
                digest_kind = pcwstr::digest_kind(padding_info.pszAlgId);
            } else if flags.contains(NCRYPT_PAD_PSS_FLAG) {
                let padding_info: &BCRYPT_PSS_PADDING_INFO = cast_void_ptr!(ppaddinginfo);
                padding = RsaSignaturePadding::Pss;
                validate_alg_arg(padding_info.pszAlgId)?;
                digest_kind = pcwstr::digest_kind(padding_info.pszAlgId);
                salt_len = Some(padding_info.cbSalt as u16);
            } else {
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            }
            if digest_kind.is_none() {
                tracing::error!("Unsupported algorithm in padding info");
                Err(HRESULT(NTE_INVALID_PARAMETER))?;
            }
        }

        Ok((digest_kind, salt_len, padding))
    }

    /// Internal method to sign the digest using an ECDSA key.
    fn sign_ecdsa(
        &self,
        key: &EcdsaKey,
        hash_value: &[u8],
        output: &mut [u8],
        result: &mut u32,
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        if flags.bitand(!NCRYPT_SILENT_FLAG) != NCRYPT_FLAGS(0) {
            tracing::error!("Bad flags provided for ECDSA signing");
            Err(HRESULT(NTE_BAD_FLAGS))?;
        }

        key.sign(app_session_ref!(self), hash_value, output, result)
    }

    /// Internal method to sign the input data using a RSA key.
    fn sign_rsa(
        &self,
        key: &RsaKey,
        input: &[u8],
        ppaddinginfo: *const c_void,
        output: &mut [u8],
        result: &mut u32,
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        let (digest_kind, salt_len, padding) = self.padding_info_rsa(ppaddinginfo, flags)?;

        let params = RsaSignParams {
            input,
            padding,
            digest_kind,
            salt_len,
            output,
            output_size: result,
        };

        key.sign(app_session_ref!(self), params)
    }

    /// Sign the input data using the key.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the key to use for signing.
    /// * `input` - The data to sign.
    /// * `padding_info` - The padding information.
    /// * `output` - The signature.
    /// * `result` - The signature size in bytes.
    /// * `flags` - Flags to use for signing.
    ///
    /// # Returns
    /// `Ok(())` if the data was signed successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_sign")]
    pub fn sign(
        &self,
        key_handle: Handle,
        input: &[u8],
        ppaddinginfo: *const c_void,
        output: &mut [u8],
        result: &mut u32,
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        match key {
            Key::Ecdsa(key) => self.sign_ecdsa(&key, input, output, result, flags),
            Key::Rsa(key) => self.sign_rsa(&key, input, ppaddinginfo, output, result, flags),
            _ => Err(HRESULT(NTE_NOT_SUPPORTED)),
        }
    }

    /// Internal method to verify the signature using an ECDSA key.
    fn verify_ecdsa(
        &self,
        key: &EcdsaKey,
        hash_value: &[u8],
        signature: &[u8],
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        if flags.bitand(!NCRYPT_SILENT_FLAG) != NCRYPT_FLAGS(0) {
            tracing::error!("Bad flags provided for ECDSA verification");
            Err(HRESULT(NTE_BAD_FLAGS))?;
        }

        key.verify(app_session_ref!(self), hash_value, signature)
    }

    /// Internal method to verify the digest and signature using a RSA key.
    fn verify_rsa(
        &self,
        key: &RsaKey,
        hash_value: &[u8],
        ppaddinginfo: *const c_void,
        signature: &[u8],
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        let (digest_kind, salt_len, padding) = self.padding_info_rsa(ppaddinginfo, flags)?;

        key.verify(
            app_session_ref!(self),
            hash_value,
            padding,
            digest_kind,
            salt_len,
            signature,
        )
    }

    /// Verify the input data using the key.
    ///
    /// # Arguments
    /// * `key_handle`   - The handle of the key to use for verification.
    /// * `hash_value`   - The hash value to verify.
    /// * `padding_info` - The padding information.
    /// * `signature`    - The signature to verify.
    /// * `flags`        - Flags to use for verification.
    ///
    /// # Returns
    /// `Ok(())` if the data was verified successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_verify")]
    pub fn verify(
        &self,
        key_handle: Handle,
        hash_value: &[u8],
        ppaddinginfo: *const c_void,
        signature: &[u8],
        flags: NCRYPT_FLAGS,
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        match key {
            Key::Ecdsa(key) => self.verify_ecdsa(&key, hash_value, signature, flags),
            Key::Rsa(key) => self.verify_rsa(&key, hash_value, ppaddinginfo, signature, flags),
            _ => Err(HRESULT(NTE_NOT_SUPPORTED)),
        }
    }

    /// Import a key.
    ///
    /// # Arguments
    /// * `pszblobtype` - The type of the key blob.
    /// * `key_data` - The key data.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was imported successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_import_key")]
    pub fn import_key(&self, pszblobtype: PCWSTR, key_data: &[u8]) -> Result<Handle, HRESULT> {
        if !pcwstr::equals(pszblobtype, NCRYPT_OPAQUETRANSPORT_BLOB) {
            tracing::error!("Unsupported key type. Please use NCRYPT_OPAQUETRANSPORT_BLOB");
            Err(HRESULT(NTE_NOT_SUPPORTED))?
        }

        if p256::PublicKey::from_public_key_der(key_data).is_ok()
            || p384::PublicKey::from_public_key_der(key_data).is_ok()
            || p521::PublicKey::from_public_key_der(key_data).is_ok()
        {
            let key_handle = self.create_and_add_key(KeyKind::Ecdh { curve_type: None });
            let mut ecdh_key = self
                .get_key(key_handle)
                .ok_or(HRESULT(NTE_INVALID_HANDLE))?
                .into_ecdh()
                .map_err(|_err| {
                    tracing::error!("Failed to import key: not EcdhKey");
                    HRESULT(E_UNEXPECTED)
                })?;
            ecdh_key.import_public_key(key_data)?;
            Ok(key_handle)
        } else {
            tracing::error!(
                "Expecting key type to be ECC Key when using NCRYPT_OPAQUETRANSPORT_BLOB"
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))?
        }
    }

    /// Import a bcrypt blob
    ///
    /// # Arguments
    /// * `pszblobtype` - The type of the key blob.
    /// * `key_data` - The key data.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was imported successfully; otherwise, an error code.
    ///
    #[cfg_attr(
        feature = "expose-symbols",
        export_name = "provider_import_bcrypt_blob"
    )]
    pub fn import_bcrypt_blob(&self, key_data: &[u8]) -> Result<Handle, HRESULT> {
        // ULONG MAGIC
        let key_kind = match u32::from_le_bytes(key_data[0..4].try_into().unwrap()) {
            BCRYPT_ECDH_PUBLIC_P256_MAGIC => KeyKind::Ecdh {
                curve_type: Some(EccCurve::P256),
            },
            BCRYPT_ECDH_PUBLIC_P384_MAGIC => KeyKind::Ecdh {
                curve_type: Some(EccCurve::P384),
            },
            BCRYPT_ECDH_PUBLIC_P521_MAGIC => KeyKind::Ecdh {
                curve_type: Some(EccCurve::P521),
            },
            _ => Err(HRESULT(NTE_INVALID_PARAMETER))?,
        };
        let key_handle = self.create_and_add_key(key_kind);

        let data_der = bcrypt_util::ecdh_bcrypt_to_der(key_data)?;

        let mut ecdh_key = self
            .get_key(key_handle)
            .ok_or(HRESULT(NTE_INVALID_HANDLE))?
            .into_ecdh()
            .map_err(|_err| {
                tracing::error!("Failed to import key: not EcdhKey");
                HRESULT(E_UNEXPECTED)
            })?;

        ecdh_key.import_public_key(&data_der)?;
        Ok(key_handle)
    }

    /// Export a key in DER format
    ///
    /// # Arguments
    /// * `key_handle` - The key handle
    /// * `output` - The address of a buffer that receives the exported key BLOB.
    /// * `result` - The output size in bytes.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was exported successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_export_key")]
    pub fn export_key(
        &self,
        key_handle: Handle,
        output: &mut [u8],
        result: &mut u32,
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        match key {
            Key::Aes(_key) => {
                tracing::error!("Cannot export AES Keys");
                Err(HRESULT(NTE_BAD_TYPE))?
            }
            Key::Ecdsa(key) => key.export_public_key(app_session_ref!(self), output, result),
            Key::Rsa(key) => key.export_public_key(app_session_ref!(self), output, result),
            Key::Ecdh(key) => key.export_public_key(app_session_ref!(self), output, result),
        }
    }

    /// Export public key as a bcrypt blob
    ///
    /// # Arguments
    /// * `key_handle` - The key handle.
    /// * `blob_type` - The blob type.
    /// * `output` - The address of a buffer that receives the exported key BLOB.
    /// * `result` - The output size in bytes.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was exported successfully; otherwise, an error code.
    ///
    #[cfg_attr(
        feature = "expose-symbols",
        export_name = "provider_export_bcrypt_blob"
    )]
    pub fn export_bcrypt_blob(
        &self,
        key_handle: Handle,
        blob_type: KeyBlobType,
        output: &mut [u8],
        result: &mut u32,
    ) -> Result<(), HRESULT> {
        let key = match key_obj!(self, key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        match (blob_type, key) {
            (_, Key::Aes(_key)) => {
                tracing::error!("Cannot export AES Keys");
                Err(HRESULT(NTE_BAD_TYPE))?
            }
            (KeyBlobType::EccPublicBlob, Key::Ecdsa(key))
            | (KeyBlobType::PublicBlob, Key::Ecdsa(key)) => {
                key.export_bcrypt_blob(app_session_ref!(self), output, result)
            }
            (KeyBlobType::RsaPublicBlob, Key::Rsa(key))
            | (KeyBlobType::PublicBlob, Key::Rsa(key)) => {
                key.export_bcrypt_blob(app_session_ref!(self), output, result)
            }
            (KeyBlobType::EccPublicBlob, Key::Ecdh(key))
            | (KeyBlobType::PublicBlob, Key::Ecdh(key)) => {
                key.export_bcrypt_blob(app_session_ref!(self), output, result)
            }
            (_, _) => {
                tracing::error!("Cannot export blob type");
                Err(HRESULT(NTE_BAD_TYPE))?
            }
        }
    }

    /// Opens built-in AZIHSM unwrap key.
    /// # Returns
    /// `Ok(handle)` if the key was opened successfully; otherwise, an error code.
    /// # Remarks
    /// The built-in unwrap key is used to unwrap the keys that are wrapped using the AZIHSM
    /// unwrap key.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_open_key")]
    pub fn open_key(&self) -> Result<Handle, HRESULT> {
        let key_handle = self.create_and_add_key(KeyKind::Rsa { key_length: 0 });
        let mut azihsm_unwrapping_key = self
            .get_key(key_handle)
            .ok_or(HRESULT(NTE_INVALID_HANDLE))?
            .into_rsa()
            .map_err(|err| {
                tracing::error!(?err, "Unexpected: Builtin unwrap key should be RSA key");
                HRESULT(E_UNEXPECTED)
            })?;
        azihsm_unwrapping_key.open_key(app_session_ref!(self))?;
        Ok(key_handle)
    }

    /// Unwraps a PKCS#11 RSA AES wrap key and imports it into the HSM
    ///
    /// # Arguments
    /// * `kind` - The kind of key to create.
    /// * `import_key_handle` - The key handle with which the imported key is encrypted.
    /// * `wrapped_blob` - The wrapped key blob.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was imported successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_rsa_unwrap")]
    pub fn rsa_unwrap(
        &self,
        kind: KeyKind,
        import_key_handle: Handle,
        wrapped_blob: &[u8],
    ) -> Result<Handle, HRESULT> {
        if wrapped_blob.len() < std::mem::size_of::<BCRYPT_PKCS11_RSA_AES_WRAP_BLOB>() {
            Err(HRESULT(E_UNEXPECTED))?;
        }

        // Cast wrapped_blob to a pointer to BCRYPT_PKCS11_RSA_AES_WRAP_BLOB
        let wrapped_blob_struct = cast_ptr!(wrapped_blob, BCRYPT_PKCS11_RSA_AES_WRAP_BLOB);

        let dw_magic = wrapped_blob_struct.dw_magic;
        if dw_magic != BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC {
            tracing::error!(
                "Invalid magic number {}, expected BCRYPT_PKCS11_RSA_AES_WRAP_BLOB_MAGIC",
                dw_magic,
            );
            Err(HRESULT(E_UNEXPECTED))?;
        }

        let cb_key = wrapped_blob_struct.cb_key;
        let cb_padding_alg_id = wrapped_blob_struct.cb_padding_alg_id;

        let key_offset = std::mem::size_of::<BCRYPT_PKCS11_RSA_AES_WRAP_BLOB>();
        let hash_alg_offset = key_offset + cb_key as usize;
        tracing::debug!(
            "Key size: {}, Padding algorithm size: {}, Key offset: {}, Hash algorithm offset: {}",
            cb_key,
            cb_padding_alg_id,
            key_offset,
            hash_alg_offset
        );
        let wrapped_key_blob =
            create_slice_from_raw_parts!(wrapped_blob.as_ptr().add(key_offset), cb_key as usize);

        let hash_alg_slice = create_slice_from_raw_parts!(
            wrapped_blob.as_ptr().add(hash_alg_offset),
            cb_padding_alg_id as usize
        );

        let hash_alg = pcwstr::byte_slice_to_pcwstr(hash_alg_slice).ok_or_else(|| {
            tracing::error!("Hash algorithm slice size must be even, got odd");
            HRESULT(NTE_INVALID_PARAMETER)
        })?;
        let digest_kind = match pcwstr::digest_kind(hash_alg) {
            Some(digest_kind) => digest_kind,
            None => {
                tracing::error!("Unsupported hash algorithm");
                Err(HRESULT(NTE_NOT_SUPPORTED))?
            }
        };

        let import_key_handle = self
            .get_key(import_key_handle)
            .ok_or(HRESULT(NTE_INVALID_HANDLE))?
            .into_rsa()
            .map_err(|err| {
                tracing::error!("Failed to import key: {:?}", err);
                HRESULT(NTE_INVALID_PARAMETER)
            })?
            .hsm_key_handle()
            .ok_or(HRESULT(NTE_INVALID_HANDLE))?;
        let key = match kind {
            KeyKind::Rsa { key_length } => Key::Rsa(RsaKey::secure_key_import(
                self.handle(),
                key_length,
                wrapped_key_blob.to_vec(),
                digest_kind,
                import_key_handle,
            )),
            KeyKind::Ecdsa { curve_type } => Key::Ecdsa(EcdsaKey::secure_key_import(
                self.handle(),
                curve_type,
                wrapped_key_blob.to_vec(),
                digest_kind,
                import_key_handle,
            )),
            KeyKind::Aes {
                key_length,
                encryption_mode,
            } => Key::Aes(AesKey::secure_key_import(
                self.handle(),
                key_length,
                encryption_mode,
                wrapped_key_blob.to_vec(),
                digest_kind,
                import_key_handle,
            )),
            KeyKind::Ecdh { curve_type } => Key::Ecdh(EcdhKey::secure_key_import(
                self.handle(),
                curve_type,
                wrapped_key_blob.to_vec(),
                digest_kind,
                import_key_handle,
            )),
        };

        // Display the type of key that we're importing. Include key length,
        // curve type, and any other properties for each key type.
        tracing::debug!("Key type: {:?}", kind);

        let handle = self.add_key(key.clone());
        Ok(handle)
    }

    ///  Generates a secret agreement value from a private and a peer public key
    ///
    /// # Arguments
    /// * `priv_key`    - The handle of the private key to use to create the secret agreement value
    /// * `pub_key`     - The imported handle of the peers public key to use to create the secret agreement value
    /// # Returns
    /// ok(secret_handle) if the function succeeds, otherwise an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_generate_secret")]
    pub fn generate_secret(&self, priv_key: Handle, pub_key: Handle) -> Result<Handle, HRESULT> {
        let private_key = match self.get_key(priv_key) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        let peer_key = match self.get_key(pub_key) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        let (curve_type, priv_hsm_key) = match private_key {
            Key::Ecdh(ref private_key) => (
                private_key.ecc_curve_type(),
                private_key
                    .hsm_key_handle()
                    .ok_or(HRESULT(NTE_INVALID_HANDLE))?,
            ),
            _ => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        let peer_key_der = match peer_key {
            Key::Ecdh(peer_key) => peer_key.key_data(),
            _ => Err(HRESULT(NTE_INVALID_HANDLE))?,
        }
        .ok_or(HRESULT(NTE_INVALID_HANDLE))?;

        let secret_handle = self.create_secret();
        let mut secret = self
            .get_secret(secret_handle)
            .ok_or(HRESULT(NTE_INVALID_HANDLE))?;

        secret.generate_secret_agreement(
            app_session_ref!(self),
            priv_hsm_key,
            peer_key_der,
            curve_type,
        )?;
        Ok(secret_handle)
    }

    /// Get a provider property.
    ///
    /// # Arguments
    /// * `property` - The property to get.
    /// * `value` - The value of the property.
    /// * `result` - The size of the value.
    ///
    /// # Returns
    /// `Ok(())` if the property was retrieved successfully; otherwise, an error code.
    ///
    #[cfg_attr(
        feature = "expose-symbols",
        export_name = "provider_get_provider_property"
    )]
    pub fn get_provider_property(
        &self,
        property: &ProviderPropertyIdentifier,
        value: &mut [u8],
        result: &mut u32,
    ) -> Result<(), HRESULT> {
        tracing::debug!(?property, "Getting provider property");

        match property {
            ProviderPropertyIdentifier::AzIHsmDeviceCertChain => {
                let inner = self.inner.read();
                let app_session = inner.app_session.as_ref().ok_or_else(|| {
                    tracing::error!("Failed to get app session");
                    HRESULT(E_UNEXPECTED)
                })?;
                let certificate = match app_session.get_certificate() {
                    Ok(certificate) => certificate,
                    Err(err) => {
                        tracing::error!("Failed to get certificate: {:?}", err);
                        Err(HRESULT(E_UNEXPECTED))?
                    }
                };

                // Take physical AZIHSM's cert chain as certificate
                // Or take virtual AZIHSM's ak cert as certificate (TODO: till virtual AZIHSM certificate support is added)
                let certificate = match certificate {
                    ManticoreCertificate::PhysicalManticore(cert_chain) => cert_chain,
                    ManticoreCertificate::VirtualManticore { ak_cert, .. } => {
                        // TODO: for virtual AZIHSM, certificate support is pending
                        // Currently it only populates ak_cert
                        ak_cert
                    }
                };

                if value.is_empty() {
                    // If the output buffer is empty, return double the length of the certificate.
                    // This ensures that the caller allocates a sufficiently large buffer for subsequent calls,
                    // accounting for potential variations in the length of the certificate between calls.
                    *result = 2 * certificate.len() as u32;
                    tracing::warn!("Value is empty, returning certificate length: {}", *result);
                    return Ok(());
                } else if value.len() < certificate.len() {
                    tracing::error!(
                        "Buffer too small for certificate: expected: {}, actual: {}",
                        certificate.len(),
                        value.len()
                    );
                    Err(HRESULT(NTE_BUFFER_TOO_SMALL))?;
                }
                value[..certificate.len()].copy_from_slice(&certificate);
                *result = certificate.len() as u32;
            }
            ProviderPropertyIdentifier::AziHsmMaxKeyCount => {
                let size_u32 = std::mem::size_of::<u32>();

                // Buffer will be filled with ONE u32 value
                // Check if return buffer is smaller than required
                if value.is_empty() {
                    *result = size_u32 as u32;
                    return Ok(());
                } else if value.len() < size_u32 {
                    tracing::error!(
                        "Buffer too small for AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY: expected: {}, actual: {}",
                        size_u32,
                        value.len()
                    );
                    Err(HRESULT(NTE_BUFFER_TOO_SMALL))?;
                }

                // Get Device Info
                let inner = self.inner.read();
                let device = inner.device.as_ref().ok_or_else(|| {
                    tracing::error!("Failed to get HsmDevice");
                    HRESULT(E_UNEXPECTED)
                })?;

                let device_info = device.get_device_info();
                let tables = device_info.tables as u32;

                // Max number of keys this device can hold
                let max_key_count: u32 = tables * AZIHSM_MAX_TABLE_KEY_COUNT;

                // Fill buffer
                value[..size_u32].copy_from_slice(&max_key_count.to_le_bytes());
                *result = size_u32 as u32;
            }
            ProviderPropertyIdentifier::AziHsmMaxStorageSize => {
                let size_u32 = std::mem::size_of::<u32>();

                // Buffer will be filled with ONE u32 value
                // Check if return buffer is smaller than required
                if value.is_empty() {
                    *result = size_u32 as u32;
                    return Ok(());
                } else if value.len() < size_u32 {
                    tracing::error!(
                        "Buffer too small for AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY: expected: {}, actual: {}",
                        size_u32,
                        value.len()
                    );
                    Err(HRESULT(NTE_BUFFER_TOO_SMALL))?;
                }

                // Get Device Info
                let inner = self.inner.read();
                let device = inner.device.as_ref().ok_or_else(|| {
                    tracing::error!("Failed to get HsmDevice");
                    HRESULT(E_UNEXPECTED)
                })?;

                let device_info = device.get_device_info();
                let tables = device_info.tables as u32;

                // Max total size of keys this device can hold, in Kilo Bytes
                let max_total_key_sizes: u32 = tables * AZIHSM_MAX_TABLE_KILOBYTES;

                // Fill buffer
                value[..size_u32].copy_from_slice(&max_total_key_sizes.to_le_bytes());
                *result = size_u32 as u32;
            }
            ProviderPropertyIdentifier::Unknown => {
                tracing::error!("Unknown provider property identifier");
                Err(HRESULT(E_INVALIDARG))?;
            }
        }

        Ok(())
    }

    /// Creates a claim based on the key handle and report data.
    ///
    /// # Arguments
    /// * `key_handle` - The key handle for which the claim is requested.
    /// * `report_data` - A reference to a 128-byte array containing the report data.
    /// * `claim` - A mutable slice to store the claim data.
    /// * `result` - A mutable reference to a `u32` to store the size of the claim data in bytes.
    ///
    /// # Returns
    /// `Ok(())` if the claim was created successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_create_claim")]
    pub fn create_claim(
        &self,
        key_handle: Handle,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
        claim: &mut [u8],
        result: &mut u32,
    ) -> Result<(), HRESULT> {
        let key = match self.get_key(key_handle) {
            Some(key) => key,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };

        match key {
            Key::Aes(_) => {
                tracing::error!("Can't create claim for AES Keys");
                Err(HRESULT(NTE_BAD_TYPE))?
            }
            Key::Rsa(key) => key.create_claim(app_session_ref!(self), report_data, claim, result),
            Key::Ecdsa(key) => key.create_claim(app_session_ref!(self), report_data, claim, result),
            Key::Ecdh(key) => key.create_claim(app_session_ref!(self), report_data, claim, result),
        }
    }

    /// Derives a key from a secret key using the specified key derivation function (KDF).
    ///
    /// # Arguments
    /// * `secret_handle` - The handle of the secret to use for key derivation.
    /// * `kdf` - The key derivation function to use.
    /// * `buffer_desc` - A pointer to a `BCryptBufferDesc` structure that contains the KDF parameters.
    ///
    /// # Returns
    /// `Ok(handle)` if the key was derived successfully; otherwise, an error code.
    ///
    #[cfg_attr(feature = "expose-symbols", export_name = "provider_derive_key")]
    pub fn derive_key(
        &self,
        secret_handle: Handle,
        kdf: PCWSTR,
        buffer_desc: &BCryptBufferDesc,
    ) -> Result<Handle, HRESULT> {
        let kdf_type = if pcwstr::equals(kdf, BCRYPT_HKDF_ALGORITHM) {
            KdfType::HKDF
        } else if pcwstr::equals(kdf, BCRYPT_SP800108_CTR_HMAC_ALGORITHM) {
            KdfType::KBKDF
        } else {
            tracing::error!(
                "Unsupported KDF algorithm: {:?}. Use BCRYPT_HKDF_ALGORITHM or BCRYPT_SP800108_CTR_HMAC_ALGORITHM",
                kdf
            );
            Err(HRESULT(NTE_INVALID_PARAMETER))?
        };

        let mut secret = match self.get_secret(secret_handle) {
            Some(secret) => secret,
            None => Err(HRESULT(NTE_INVALID_HANDLE))?,
        };
        let target_key_type = secret.infer_target_key_type(kdf_type, buffer_desc)?;
        let key_type = match target_key_type {
            Some(KeyType::Aes128) => KeyKind::Aes {
                key_length: Some(AES_KEY_SIZE_128),
                encryption_mode: None,
            },
            Some(KeyType::Aes192) => KeyKind::Aes {
                key_length: Some(AES_KEY_SIZE_192),
                encryption_mode: None,
            },
            Some(KeyType::Aes256) => KeyKind::Aes {
                key_length: Some(AES_KEY_SIZE_256),
                encryption_mode: None,
            },
            // TODO: support Aes Bulk
            _ => {
                tracing::error!("Expect key type to be AES");
                Err(HRESULT(NTE_NOT_SUPPORTED))?
            }
        };

        // Create the key object.
        let key_handle = self.create_and_add_key(key_type);
        // Set KeyOrigin to Derive
        let mut aes_key = match self.get_key(key_handle) {
            Some(key) => match key.into_aes() {
                Ok(aes) => aes,
                Err(_) => {
                    tracing::error!("Failed to convert key to AES");
                    Err(HRESULT(E_UNEXPECTED))?
                }
            },
            None => {
                tracing::error!("Key not found for handle: {}", key_handle);
                Err(HRESULT(NTE_INVALID_HANDLE))?
            }
        };
        aes_key.set_key_origin(KeyOrigin::Derive);
        aes_key.set_secret_handle(secret);
        Ok(key_handle)
    }
}

#[derive(Default)]
struct ProviderInner {
    handle: Handle,
    keys: HandleTable<Key>,
    secrets: HandleTable<Secret>,
    app_session: Option<HsmSession>,
    device: Option<HsmDevice>,
}

impl ProviderInner {
    fn handle(&self) -> Handle {
        self.handle
    }

    fn set_handle(&mut self, handle: Handle) {
        self.handle = handle;
    }

    fn open_app_session(&mut self) -> Result<(), HRESULT> {
        debug_assert!(self.app_session.is_none() && self.device.is_none());

        let devices = HsmDevice::get_devices();
        if devices.is_empty() {
            tracing::error!("No HSM devices found");
            Err(HRESULT(NTE_PROVIDER_DLL_FAIL))?;
        }

        let selected_device = &devices[0];
        tracing::info!(
            "Connecting to device. firmware_ver={}, VF driver_ver={}, hardware_ver={}, path={}, CARGO_PKG_VERSION={}, SUPPORTED_API_REV_RANGE={:?}",
            selected_device.firmware_ver,
            selected_device.driver_ver,
            selected_device.hardware_ver,
            selected_device.path.as_str(),
            env!("CARGO_PKG_VERSION"),
            SUPPORTED_API_REV_RANGE,
        );

        let device = HsmDevice::open(selected_device.path.as_str()).map_err(|err| {
            tracing::error!(
                ?err,
                "Failed to open HSM device. path={}",
                selected_device.path.as_str()
            );
            HRESULT(NTE_PROVIDER_DLL_FAIL)
        })?;

        // Get access to the mutex.
        let mut app_credentials = APP_CREDENTIALS_MUTEX.lock().map_err(|err| {
            tracing::error!("Failed to acquire lock on APP_CREDENTIALS_MUTEX: {:?}", err);
            HRESULT::from_win32(ERROR_LOCK_FAILED)
        })?;

        // Determine target api revision
        let device_api_rev_range = device.get_api_revision_range();
        let api_rev = HsmApiRevision {
            major: cmp::min(
                device_api_rev_range.max.major,
                SUPPORTED_API_REV_RANGE.max.major,
            ),
            minor: cmp::min(
                device_api_rev_range.max.minor,
                SUPPORTED_API_REV_RANGE.max.minor,
            ),
        };
        if api_rev < device_api_rev_range.min || api_rev < SUPPORTED_API_REV_RANGE.min {
            tracing::error!("Could not find suitable target api rev. device_api_rev_range={:?}, SUPPORTED_API_REV_RANGE={:?}, api_rev={:?}", device_api_rev_range, SUPPORTED_API_REV_RANGE, api_rev);
            Err(HRESULT(NTE_PROVIDER_DLL_FAIL))?;
        }

        tracing::info!(
            "Connected to device. device_api_rev_range={:?}, SUPPORTED_API_REV_RANGE={:?}, target_api_rev={:?}, CARGO_PKG_VERSION={}",
            device_api_rev_range,
            SUPPORTED_API_REV_RANGE,
            api_rev,
            env!("CARGO_PKG_VERSION"),
        );

        // If app credentials haven't been initialized, create an app.
        if app_credentials.is_none() {
            let credentials = HsmAppCredentials {
                id: Uuid::from_bytes(TEST_CRED_ID),
                pin: TEST_CRED_PIN,
            };
            // Ignore establish credential error as credential
            // may have already been established by another process
            let _ = device.establish_credential(api_rev, credentials);

            *app_credentials = Some(credentials);
        }

        let app_credentials_inner = app_credentials.ok_or_else(|| {
            tracing::error!("Unexpected: App Credential is None");
            HRESULT(E_UNEXPECTED)
        })?;

        // Open a new app session.
        match device.open_session(api_rev, app_credentials_inner) {
            Ok(app_session) => {
                self.device = Some(device);
                self.app_session = Some(app_session);
                Self::inc_active_app_session_count();
                tracing::debug!(
                    "AZIHSM app session opened successfully, active app session count: {}",
                    Self::active_app_session_count()
                );
                Ok(())
            }
            Err(err) => {
                tracing::error!("Failed to open app session: {:?}", err);
                Err(HRESULT(E_UNEXPECTED))
            }
        }
    }

    fn close_app_session(&mut self) -> Result<(), HRESULT> {
        tracing::debug!("Closing AZIHSM app session");
        let mut app_credentials_opt = APP_CREDENTIALS_MUTEX.lock().map_err(|err| {
            tracing::error!("Failed to acquire lock on APP_CREDENTIALS_MUTEX: {:?}", err);
            HRESULT::from_win32(ERROR_LOCK_FAILED)
        })?;

        let app_session: &mut HsmSession = self.app_session.as_mut().ok_or_else(|| {
            tracing::error!("App session already closed");
            HRESULT(E_UNEXPECTED)
        })?;
        match app_session.close_session() {
            Ok(()) => {
                self.device = None;
                self.app_session = None;
                Self::dec_active_app_session_count();
                tracing::debug!(
                    "AZIHSM app session closed successfully, active app session count: {}",
                    Self::active_app_session_count()
                );
            }
            Err(err) => {
                tracing::error!("Failed to close app session: {:?}", err);
                Err(HRESULT(E_UNEXPECTED))?;
            }
        }

        // Check if this is the last provider instance.
        if Self::active_app_session_count() == 0 {
            tracing::debug!("Last app session closed");

            // Clear the app credentials.
            *app_credentials_opt = None;
        }

        Ok(())
    }

    fn active_app_session_count() -> u32 {
        ACTIVE_APP_SESSION_COUNT.load(Ordering::SeqCst)
    }

    fn inc_active_app_session_count() {
        ACTIVE_APP_SESSION_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    fn dec_active_app_session_count() {
        ACTIVE_APP_SESSION_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}
