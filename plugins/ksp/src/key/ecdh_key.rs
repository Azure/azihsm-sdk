// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use mcr_api::DigestKind;
use mcr_api::EccCurve;
use mcr_api::HsmKeyHandle;
use mcr_api::HsmSession;
use mcr_api::KeyAvailability;
use mcr_api::KeyClass;
use mcr_api::KeyProperties;
use mcr_api::KeyType;
use mcr_api::KeyUsage;
use parking_lot::RwLock;
use winapi::shared::winerror::ERROR_INVALID_DATA;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BAD_KEY_STATE;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use super::super::REPORT_DATA_SIZE;
use crate::handle_table::Handle;
use crate::helpers::validate_output_buffer;
use crate::key::base_key::BaseKey;
use crate::key::base_key::KeyOrigin;
use crate::key::base_key::KeyPropertyIdentifier;
use crate::utils::*;
use crate::AzIHsmHresult;

// Max size of a ECC Public Key
const ECC_PUBLIC_KEY_MAX_SIZE: usize = 192;
const ECC_256_KEY_SIZE: usize = 256;
const ECC_384_KEY_SIZE: usize = 384;
const ECC_521_KEY_SIZE: usize = 521;

/// EcdhKey
#[derive(Clone, Debug)]
pub struct EcdhKey(Arc<RwLock<EcdhKeyInner>>);

impl EcdhKey {
    pub fn new(provider_handle: Handle, curve_type: Option<EccCurve>) -> Self {
        Self(Arc::new(RwLock::new(EcdhKeyInner::new(
            provider_handle,
            curve_type,
        ))))
    }

    #[allow(dead_code)]
    pub fn set_hsm_handle(&self, hsm_handle: HsmKeyHandle) {
        self.0.write().base_key.hsm_handle = Some(hsm_handle);
    }

    pub fn hsm_key_handle(&self) -> Option<HsmKeyHandle> {
        self.0.read().base_key.hsm_handle.clone()
    }

    fn set_ecc_curve_type(&mut self, ecc_curve_type: EccCurve) {
        tracing::debug!(?ecc_curve_type, "set_ecc_curve_type");
        self.0.write().ecc_curve_type = Some(ecc_curve_type);
    }

    pub fn ecc_curve_type(&self) -> Option<EccCurve> {
        self.0.read().ecc_curve_type
    }

    pub fn key_origin(&self) -> KeyOrigin {
        self.0.read().base_key.get_key_origin()
    }

    pub fn private_key(&self) -> bool {
        self.0.read().base_key.private_key()
    }

    fn set_private_key(&self, is_private: bool) -> AzIHsmHresult<()> {
        self.0.write().base_key.set_private_key(is_private)
    }

    fn set_key_origin(&self, key_origin: KeyOrigin) {
        self.0.write().base_key.set_key_origin(key_origin);
    }

    pub fn secure_key_import(
        prov_handle: Handle,
        curve_type: Option<EccCurve>,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
    ) -> Self {
        Self(Arc::new(RwLock::new(EcdhKeyInner::secure_key_import(
            prov_handle,
            curve_type,
            key_data,
            digest_kind,
            import_key_handle,
        ))))
    }

    pub fn set_key_data(&mut self, key_data: &[u8]) -> AzIHsmHresult<()> {
        self.0.write().base_key.set_key_data(key_data.to_vec())
    }

    pub fn key_data(&self) -> Option<Vec<u8>> {
        self.0.read().base_key.get_key_data()
    }

    /// Assign default ECDH key properties.
    pub fn assign_default(&mut self, _app_session: &HsmSession) -> AzIHsmHresult<()> {
        tracing::debug!("Assigning default ECDH key properties");

        // We should set a default ECC Curve Type
        // But since during `finalize_key`, its set based on the key type returned by the HSM
        // So we don't set it here, let it be None so HSM set it for us

        Ok(())
    }

    /// Finalize the key. This function will create the key in the HSM.
    ///
    /// # Arguments
    /// * `app_session` - The HsmSession to use for finalizing the key.
    ///
    /// # Returns
    ///   `Ok(())` if the key was finalized successfully; otherwise, an error code.
    ///
    pub fn finalize_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.hsm_key_handle().is_some() {
            tracing::error!("Hsm Key is already created. Cannot finalize again.");
            Err(HRESULT(E_UNEXPECTED))?;
        }

        match self.key_origin() {
            KeyOrigin::Import => {
                if self.private_key() {
                    let hsm_key_handle = self
                        .0
                        .write()
                        .base_key
                        .finalize_secure_import(app_session)?;

                    let key_type = hsm_key_handle.kind();
                    let ecc_curve_type = self.ecc_curve_type();

                    match (ecc_curve_type, key_type) {
                        (None, KeyType::Ecc256Private) => self.set_ecc_curve_type(EccCurve::P256),
                        (None, KeyType::Ecc384Private) => self.set_ecc_curve_type(EccCurve::P384),
                        (None, KeyType::Ecc521Private) => self.set_ecc_curve_type(EccCurve::P521),
                        (Some(EccCurve::P256), KeyType::Ecc256Private) => (),
                        (Some(EccCurve::P384), KeyType::Ecc384Private) => (),
                        (Some(EccCurve::P521), KeyType::Ecc521Private) => (),
                        _ => {
                            tracing::error!(
                            "Mismatch between algorithm ID provided in import params and the key type returned by the HSM. \
                        Value supplied in import params: {:?}; Value returned by HSM: {:?}",
                            ecc_curve_type,
                            key_type
                        );
                            Err(HRESULT(E_UNEXPECTED))?;
                        }
                    }
                } else {
                    // Public Key Import
                    // Finalize call for public key import is dummy and
                    // does nothing as the key is cached locally within ksp during import
                    tracing::debug!("Finalize call for public key import is a dummy execution path returning success");
                }
                Ok(())
            }
            KeyOrigin::Generate => self.0.write().finalize_key(app_session),
            KeyOrigin::Derive => {
                tracing::error!("Finalizing ECDH Key, its origin cannot be Derive");
                Err(HRESULT(NTE_NOT_SUPPORTED))
            }
        }
    }

    /// Sets the property of the key.
    ///
    /// # Arguments
    /// * `property` - The property to set.
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
        tracing::debug!(?property, "Setting property of ECDH Key");

        match property {
            KeyPropertyIdentifier::CurveType => {
                let curve_type = PCWSTR::from_raw(value.as_ptr() as *mut u16);

                if pcwstr::equals(curve_type, BCRYPT_ECC_CURVE_NISTP256) {
                    self.set_ecc_curve_type(EccCurve::P256);
                } else if pcwstr::equals(curve_type, BCRYPT_ECC_CURVE_NISTP384) {
                    self.set_ecc_curve_type(EccCurve::P384);
                } else if pcwstr::equals(curve_type, BCRYPT_ECC_CURVE_NISTP521) {
                    self.set_ecc_curve_type(EccCurve::P521);
                } else {
                    Err(HRESULT(E_INVALIDARG))?;
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
    ///  * `property` - The property to get.
    ///  * `value` - The output buffer to store the property value.
    ///  * `value_size` - The size of the size of the value returned.
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
                if pcwstr::copy_pcwstr_to_slice(NCRYPT_ECDH_ALGORITHM_GROUP, value, value_size) == 0
                {
                    Err(HRESULT(NTE_INVALID_PARAMETER))?
                }
            }
            KeyPropertyIdentifier::AlgorithmName => {
                let algo = match self.ecc_curve_type() {
                    Some(EccCurve::P256) => NCRYPT_ECDH_P256_ALGORITHM,
                    Some(EccCurve::P384) => NCRYPT_ECDH_P384_ALGORITHM,
                    Some(EccCurve::P521) => NCRYPT_ECDH_P521_ALGORITHM,
                    None => {
                        tracing::error!("ECC Curve type is not set");
                        Err(HRESULT(E_UNEXPECTED))?
                    }
                };
                if pcwstr::copy_pcwstr_to_slice(algo, value, value_size) == 0 {
                    return Err(HRESULT(NTE_INVALID_PARAMETER));
                }
            }
            KeyPropertyIdentifier::KeyLength => {
                let key_length: u32 = match self.ecc_curve_type() {
                    Some(EccCurve::P256) => ECC_256_KEY_SIZE as u32,
                    Some(EccCurve::P384) => ECC_384_KEY_SIZE as u32,
                    Some(EccCurve::P521) => ECC_521_KEY_SIZE as u32,
                    None => {
                        tracing::error!("ECC Curve type is not set");
                        Err(HRESULT(E_UNEXPECTED))?
                    }
                };
                let output = key_length.to_le_bytes();
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
            KeyType::Ecc256Private | KeyType::Ecc384Private | KeyType::Ecc521Private => {
                ECC_PUBLIC_KEY_MAX_SIZE as u32
            }
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
        let _hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("Hsm Key is not created");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        // Get DER format key data
        let mut der_format_output = [0u8; ECC_PUBLIC_KEY_MAX_SIZE];
        let mut der_format_output_size = 0u32;
        self.0.write().base_key.export_public_key(
            app_session,
            &mut der_format_output,
            &mut der_format_output_size,
        )?;

        let magic_blob =
            bcrypt_util::ecdh_der_to_bcrypt(&der_format_output[..der_format_output_size as usize])?;

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

    /// Cache key data locally for later use.
    ///
    /// # Arguments
    /// * `key_data`    - The key data to import.
    ///
    /// # Returns
    /// `Ok(())` if the key was imported successfully; otherwise, an error code.
    ///
    pub fn import_public_key(&mut self, key_data: &[u8]) -> AzIHsmHresult<()> {
        if self.hsm_key_handle().is_some() {
            tracing::error!("Cannot import key as it already exists.");
            Err(HRESULT(E_UNEXPECTED))?
        }

        self.set_key_data(key_data)?;
        self.set_private_key(false)?;
        self.set_key_origin(KeyOrigin::Import);
        tracing::debug!(
            "Key data set successfully, length: {} bytes",
            key_data.len()
        );
        Ok(())
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
struct EcdhKeyInner {
    base_key: BaseKey,
    ecc_curve_type: Option<EccCurve>,
}

impl EcdhKeyInner {
    pub fn new(provider_handle: Handle, curve_type: Option<EccCurve>) -> Self {
        Self {
            base_key: BaseKey::new(provider_handle),
            ecc_curve_type: curve_type,
        }
    }

    pub fn secure_key_import(
        prov_handle: Handle,
        curve_type: Option<EccCurve>,
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
                Some(KeyUsage::Derive),
                KeyClass::Ecc,
            ),
            ecc_curve_type: curve_type,
        }
    }

    pub fn finalize_key(&mut self, app_session: &HsmSession) -> AzIHsmHresult<()> {
        if self.base_key.hsm_handle.is_some() {
            tracing::error!("Hsm Key is already created");
            Err(HRESULT(NTE_BAD_KEY_STATE))?
        }

        match app_session.ecc_generate(
            self.ecc_curve_type.ok_or_else(|| {
                tracing::error!("ECC Curve type is not set");
                HRESULT(NTE_BAD_KEY)
            })?,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        ) {
            Ok(hsm_handle) => {
                self.base_key.hsm_handle = Some(hsm_handle);
                Ok(())
            }
            Err(err) => {
                tracing::error!(?err, "HsmSession::ecc_generate failed",);
                Err(HRESULT(E_UNEXPECTED))
            }
        }
    }
}
