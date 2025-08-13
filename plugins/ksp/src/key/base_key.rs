// Copyright (C) Microsoft Corporation. All rights reserved.

use enum_as_inner::EnumAsInner;
use mcr_api::DigestKind;
use mcr_api::EccCurve;
use mcr_api::HsmError;
use mcr_api::HsmKeyHandle;
use mcr_api::HsmSession;
use mcr_api::KeyAvailability;
use mcr_api::KeyClass;
use mcr_api::KeyProperties;
use mcr_api::KeyUsage;
use mcr_api::RsaCryptoPadding;
use mcr_api::RsaUnwrapParams;
use winapi::shared::winerror::*;
use windows::core::HRESULT;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;

use super::super::REPORT_DATA_SIZE;
use crate::handle_table::Handle;
use crate::key::aes_key::AesEncryptionMode;
use crate::key::aes_key::AesKey;
use crate::key::ecdh_key::EcdhKey;
use crate::key::ecdsa_key::EcdsaKey;
use crate::key::rsa_key::RsaKey;
use crate::utils::*;
use crate::AzIHsmHresult;

#[derive(Debug)]
pub(crate) enum KeyKind {
    Aes {
        key_length: Option<u32>,
        encryption_mode: Option<AesEncryptionMode>,
    },
    Ecdsa {
        curve_type: Option<EccCurve>,
    },
    Rsa {
        key_length: u32,
    },
    Ecdh {
        curve_type: Option<EccCurve>,
    },
}

const CLR_IS_EPHEMERAL: PCWSTR = w!("CLR IsEphemeral");

// A custom key property (exclusively for RSA keys) that determines if an RSA
// key should be imported as CRT-enabled or CRT-disabled.
//
// CRT-enabled RSA keys take up more space, but result in faster RSA operations.
// CRT-disabled keys take up less space, but result in slower RSA operations.
//
// By default, RSA keys are imported with CRT enabled.
const AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED: PCWSTR = w!("RsaCrtEnabled");

// The value that is returned from `NCryptGetProperty` for the `RsaCrtEnabled`
// property for an RSA key, when it has CRT enabled.
pub(crate) const AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_ENABLED: u32 = 1;

// The value that is returned from `NCryptGetProperty` for the `RsaCrtEnabled`
// property for an RSA key, when it has CRT disabled.
pub(crate) const AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED_VALUE_DISABLED: u32 = 0;

#[derive(Debug, PartialEq)]
pub(crate) enum KeyPropertyIdentifier {
    KeyLength,      // NCRYPT_LENGTH_PROPERTY
    ChainingMode,   // NCRYPT_CHAINING_MODE_PROPERTY
    CurveType,      // NCRYPT_ECC_CURVE_NAME_PROPERTY
    ClrEphemeral,   // CLR_IS_EPHEMERAL
    AlgorithmGroup, // NCRYPT_ALGORITHM_GROUP_PROPERTY
    AlgorithmName,  // NCRYPT_ALGORITHM_PROPERTY
    AuthTagLength,  // BCRYPT_AUTH_TAG_LENGTH
    KeyUsage,       // NCRYPT_KEY_USAGE_PROPERTY
    RsaCrtEnabled,  // AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED
    Unknown,
}

impl From<PCWSTR> for KeyPropertyIdentifier {
    fn from(id: PCWSTR) -> KeyPropertyIdentifier {
        if pcwstr::equals(id, NCRYPT_LENGTH_PROPERTY) {
            KeyPropertyIdentifier::KeyLength
        } else if pcwstr::equals(id, NCRYPT_CHAINING_MODE_PROPERTY) {
            KeyPropertyIdentifier::ChainingMode
        } else if pcwstr::equals(id, NCRYPT_ECC_CURVE_NAME_PROPERTY) {
            KeyPropertyIdentifier::CurveType
        } else if pcwstr::equals(id, CLR_IS_EPHEMERAL) {
            KeyPropertyIdentifier::ClrEphemeral
        } else if pcwstr::equals(id, NCRYPT_ALGORITHM_GROUP_PROPERTY) {
            KeyPropertyIdentifier::AlgorithmGroup
        } else if pcwstr::equals(id, NCRYPT_ALGORITHM_PROPERTY) {
            KeyPropertyIdentifier::AlgorithmName
        } else if pcwstr::equals(id, BCRYPT_AUTH_TAG_LENGTH) {
            KeyPropertyIdentifier::AuthTagLength
        } else if pcwstr::equals(id, NCRYPT_KEY_USAGE_PROPERTY) {
            KeyPropertyIdentifier::KeyUsage
        } else if pcwstr::equals(id, AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED) {
            KeyPropertyIdentifier::RsaCrtEnabled
        } else {
            KeyPropertyIdentifier::Unknown
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum KeyBlobType {
    EccPublicBlob,   // BCRYPT_ECCPUBLIC_BLOB
    RsaPublicBlob,   // BCRYPT_RSA_PUBLIC_BLOB
    PublicBlob,      // BCRYPT_PUBLIC_KEY_BLOB
    OpaqueTransport, // NCRYPT_OPAQUETRANSPORT_BLOB
    Unknown,
}

impl From<PCWSTR> for KeyBlobType {
    fn from(blob_type: PCWSTR) -> KeyBlobType {
        if pcwstr::equals(blob_type, BCRYPT_ECCPUBLIC_BLOB) {
            KeyBlobType::EccPublicBlob
        } else if pcwstr::equals(blob_type, BCRYPT_RSAPUBLIC_BLOB) {
            KeyBlobType::RsaPublicBlob
        } else if pcwstr::equals(blob_type, BCRYPT_PUBLIC_KEY_BLOB) {
            KeyBlobType::PublicBlob
        } else if pcwstr::equals(blob_type, NCRYPT_OPAQUETRANSPORT_BLOB) {
            KeyBlobType::OpaqueTransport
        } else {
            KeyBlobType::Unknown
        }
    }
}

#[derive(Clone, EnumAsInner, Debug)]
pub(crate) enum Key {
    Aes(AesKey),
    Ecdsa(EcdsaKey),
    Rsa(RsaKey),
    Ecdh(EcdhKey),
}

macro_rules! set_hsm_handle_call {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
			Key::Aes(aes_key) => aes_key.$method($($args),*),
            Key::Ecdsa(ecdsa_key) => ecdsa_key.$method($($args),*),
            Key::Rsa(rsa_key) => rsa_key.$method($($args),*),
            Key::Ecdh(ecdh_key) => ecdh_key.$method($($args),*),
        }
    };
}

impl Key {
    #[allow(dead_code)]
    pub fn set_hsm_handle(&mut self, hsm_handle: HsmKeyHandle) {
        set_hsm_handle_call!(self, set_hsm_handle, hsm_handle)
    }
}

#[derive(Clone, EnumAsInner, Debug, PartialEq)]
pub(crate) enum KeyOrigin {
    Import,
    Generate,
    Derive,
}

#[derive(Debug)]
pub struct KeyImportProperties {
    import_key_handle: Option<HsmKeyHandle>,
    key_usage: Option<KeyUsage>,
    key_class: Option<KeyClass>,
    key_data: Option<Vec<u8>>,
    digest_kind: Option<DigestKind>,
    private_key: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct BaseKey {
    pub key_origin: KeyOrigin,
    pub provider_handle: Handle,
    pub key_handle: Handle,
    pub hsm_handle: Option<HsmKeyHandle>,
    pub key_import_properties: KeyImportProperties,
}

impl BaseKey {
    pub fn get_key_origin(&self) -> KeyOrigin {
        self.key_origin.clone()
    }

    pub fn set_key_origin(&mut self, key_origin: KeyOrigin) {
        self.key_origin = key_origin;
    }

    pub fn get_key_usage(&self) -> Option<KeyUsage> {
        self.key_import_properties.key_usage
    }

    pub fn set_key_usage(&mut self, key_usage: KeyUsage) -> AzIHsmHresult<()> {
        self.key_import_properties.key_usage = Some(key_usage);
        Ok(())
    }

    pub fn get_key_data(&self) -> Option<Vec<u8>> {
        self.key_import_properties.key_data.clone()
    }

    pub fn set_key_data(&mut self, key_data: Vec<u8>) -> AzIHsmHresult<()> {
        self.key_import_properties.key_data = Some(key_data);
        Ok(())
    }

    pub fn private_key(&self) -> bool {
        self.key_import_properties.private_key
    }

    pub fn set_private_key(&mut self, is_private: bool) -> AzIHsmHresult<()> {
        self.key_import_properties.private_key = is_private;
        Ok(())
    }

    pub fn get_import_key_handle(&self) -> Option<HsmKeyHandle> {
        self.key_import_properties.import_key_handle.clone()
    }

    pub fn get_key_class(&self) -> Option<KeyClass> {
        self.key_import_properties.key_class
    }

    pub fn set_key_class(&mut self, key_class: KeyClass) -> AzIHsmHresult<()> {
        self.key_import_properties.key_class = Some(key_class);
        Ok(())
    }

    pub fn get_digest_kind(&self) -> Option<DigestKind> {
        self.key_import_properties.digest_kind
    }

    fn hsm_key_handle(&self) -> Option<HsmKeyHandle> {
        self.hsm_handle.clone()
    }

    pub fn new(provider_handle: Handle) -> Self {
        Self {
            key_origin: KeyOrigin::Generate,
            provider_handle,
            key_handle: 0,
            hsm_handle: None,
            key_import_properties: KeyImportProperties {
                import_key_handle: None,
                key_usage: None,
                key_class: None,
                key_data: Some(Vec::new()),
                digest_kind: None,
                private_key: true,
            },
        }
    }

    pub fn secure_key_import(
        provider_handle: Handle,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
        key_usage: Option<KeyUsage>,
        key_class: KeyClass,
    ) -> Self {
        Self {
            key_origin: KeyOrigin::Import,
            provider_handle,
            key_handle: 0,
            hsm_handle: None,
            key_import_properties: KeyImportProperties {
                import_key_handle: Some(import_key_handle),
                key_usage,
                key_class: Some(key_class),
                key_data: Some(key_data),
                digest_kind: Some(digest_kind),
                private_key: true,
            },
        }
    }
    pub fn delete_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        let hsm_handle = self.hsm_handle.as_ref().ok_or_else(|| {
            tracing::warn!("Hsm key is not found, nothing to delete.");
            Ok(())
        })?;

        match app_session.delete_key(hsm_handle) {
            Ok(_) => {
                self.hsm_handle = None;
                Ok(())
            }
            Err(err) => match err {
                HsmError::CannotDeleteInternalKeys => {
                    tracing::debug!("Cannot delete internal keys, but proceeding as success.");
                    self.hsm_handle = None;
                    Ok(())
                }
                _ => {
                    tracing::error!(?err, "Error during key deletion.",);
                    Err(HRESULT(NTE_NO_KEY))
                }
            },
        }
    }

    pub fn finalize_secure_import(
        &mut self,
        app_session: &HsmSession,
    ) -> AzIHsmHresult<HsmKeyHandle> {
        let key_data = self.get_key_data().ok_or_else(|| {
            tracing::error!("Failed to get key data.");
            HRESULT(NTE_BAD_KEY)
        })?;

        let digest_kind = self.get_digest_kind().ok_or_else(|| {
            tracing::error!("Failed to get digest kind.");
            HRESULT(NTE_BAD_KEY)
        })?;

        let key_usage = self.get_key_usage().ok_or_else(|| {
            tracing::error!("Failed to get key usage.");
            HRESULT(NTE_BAD_KEY)
        })?;

        let key_class = self.get_key_class().ok_or_else(|| {
            tracing::error!("Failed to get key class.");
            HRESULT(NTE_BAD_KEY)
        })?;

        let import_key_handle = self.get_import_key_handle().ok_or_else(|| {
            tracing::error!("Failed to get import key handle.");
            HRESULT(NTE_BAD_KEY)
        })?;

        let wrapped_blob_params = RsaUnwrapParams {
            key_class,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: digest_kind,
        };

        match app_session.rsa_unwrap(
            &import_key_handle,
            key_data.clone(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage,
                key_availability: KeyAvailability::Session,
            },
        ) {
            Ok(hsm_key_handle) => {
                self.hsm_handle = Some(hsm_key_handle.clone());
                Ok(hsm_key_handle)
            }
            Err(err) => {
                tracing::error!(?err, "Error during finalize_secure_import.",);
                Err(HRESULT(NTE_FAIL))
            }
        }
    }

    pub fn export_public_key(
        &self,
        app_session: &HsmSession,
        output: &mut [u8],
        output_size: &mut u32,
    ) -> AzIHsmHresult<()> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Invalid key handle...");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let pub_key = match app_session.export_public_key(&hsm_key_handle) {
            Ok(pub_key) => pub_key,
            Err(err) => {
                tracing::error!(?err, "Error in exporting public key.",);
                Err(HRESULT(NTE_BAD_KEY))?
            }
        };

        let buffer_size = pub_key.len() as u32;
        tracing::debug!(
            "buffer_size: {:?}, output_size: {:?}",
            buffer_size,
            *output_size
        );
        output[..buffer_size as usize].copy_from_slice(&pub_key);
        *output_size = buffer_size as u32;
        Ok(())
    }

    pub fn create_claim(
        &self,
        app_session: &HsmSession,
        report_data: &[u8; REPORT_DATA_SIZE as usize],
        claim: &mut [u8],
        result: &mut u32,
    ) -> AzIHsmHresult<()> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot create claim at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let attest_claim = match app_session.attest_key(&hsm_key_handle, report_data) {
            Ok(attest_claim) => attest_claim,
            Err(err) => {
                tracing::error!(?err, "HsmSession::attest_key failed.",);
                Err(HRESULT(NTE_FAIL))?
            }
        };

        if claim.is_empty() {
            // If the claim buffer is empty, return double the length of the attest_claim.
            // This ensures that the caller allocates a sufficiently large buffer for subsequent calls,
            // accounting for potential variations in the length of the attestation claim between calls.
            *result = 2 * attest_claim.len() as u32;
            tracing::warn!("Claim is empty. Returning attest_claim length: {}", *result);
            return Ok(());
        } else if claim.len() < attest_claim.len() {
            tracing::error!(
                "Buffer too small for attestation claim: expected: {}, actual: {}",
                attest_claim.len(),
                claim.len()
            );
            Err(HRESULT(NTE_BUFFER_TOO_SMALL))?;
        }
        claim[..attest_claim.len() as usize].copy_from_slice(&attest_claim);
        *result = attest_claim.len() as u32;
        Ok(())
    }
}
