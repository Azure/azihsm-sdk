// Copyright (C) Microsoft Corporation. All rights reserved.

use std::mem;
use std::sync::Arc;

use mcr_api_resilient::DigestKind;
use mcr_api_resilient::EccCurve;
use mcr_api_resilient::HsmKeyHandle;
use mcr_api_resilient::HsmSession;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyClass;
use mcr_api_resilient::KeyProperties;
use mcr_api_resilient::KeyType;
use mcr_api_resilient::KeyUsage;
use parking_lot::RwLock;
use winapi::shared::winerror::ERROR_INVALID_DATA;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BAD_KEY_STATE;
use winapi::shared::winerror::NTE_BAD_SIGNATURE;
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

pub const SHA1_DIGEST_SIZE: usize = 20;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA384_DIGEST_SIZE: usize = 48;
pub const SHA512_DIGEST_SIZE: usize = 64;

pub const ECC_P256_SIGNATURE_SIZE: usize = 64;
pub const ECC_P384_SIGNATURE_SIZE: usize = 96;
pub const ECC_P521_SIGNATURE_SIZE: usize = 132;

/// Represents an ECDSA key.
#[derive(Clone, Debug)]
pub struct EcdsaKey(Arc<RwLock<EcdsaInnerKey>>);

impl EcdsaKey {
    pub fn new(provider_handle: Handle, curve_type: Option<EccCurve>) -> Self {
        Self(Arc::new(RwLock::new(EcdsaInnerKey::new(
            provider_handle,
            curve_type,
        ))))
    }

    // Securely import Ecdsa key
    pub fn secure_key_import(
        prov_handle: Handle,
        curve_type: Option<EccCurve>,
        key_data: Vec<u8>,
        digest_kind: DigestKind,
        import_key_handle: HsmKeyHandle,
    ) -> Self {
        Self(Arc::new(RwLock::new(EcdsaInnerKey::secure_key_import(
            prov_handle,
            curve_type,
            key_data,
            digest_kind,
            import_key_handle,
        ))))
    }

    fn set_ecc_curve_type(&mut self, ecc_curve_type: EccCurve) {
        tracing::debug!(?ecc_curve_type, "set_ecc_curve_type");

        self.0.write().ecc_curve_type = Some(ecc_curve_type);
    }

    fn ecc_curve_type(&self) -> Option<EccCurve> {
        self.0.read().ecc_curve_type
    }

    #[allow(dead_code)]
    pub fn set_hsm_handle(&self, hsm_handle: HsmKeyHandle) {
        self.0.write().base_key.hsm_handle = Some(hsm_handle);
    }

    fn hsm_key_handle(&self) -> Option<HsmKeyHandle> {
        self.0.read().base_key.hsm_handle.clone()
    }

    pub fn key_origin(&self) -> KeyOrigin {
        self.0.read().base_key.get_key_origin()
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
        tracing::debug!(?property, "Setting property of ECDSA Key");

        match property {
            KeyPropertyIdentifier::CurveType => {
                let chaining_mode = PCWSTR::from_raw(value.as_ptr() as *mut u16);

                if pcwstr::equals(chaining_mode, BCRYPT_ECC_CURVE_NISTP256) {
                    self.set_ecc_curve_type(EccCurve::P256);
                } else if pcwstr::equals(chaining_mode, BCRYPT_ECC_CURVE_NISTP384) {
                    self.set_ecc_curve_type(EccCurve::P384);
                } else if pcwstr::equals(chaining_mode, BCRYPT_ECC_CURVE_NISTP521) {
                    self.set_ecc_curve_type(EccCurve::P521);
                } else {
                    Err(HRESULT(E_INVALIDARG))?;
                }
            }
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
            KeyPropertyIdentifier::AlgorithmGroup => {
                if pcwstr::copy_pcwstr_to_slice(NCRYPT_ECDSA_ALGORITHM_GROUP, value, value_size)
                    == 0
                {
                    return Err(HRESULT(NTE_INVALID_PARAMETER));
                }
            }
            KeyPropertyIdentifier::AlgorithmName => {
                let algo = match self.0.read().ecc_curve_type {
                    Some(EccCurve::P256) => NCRYPT_ECDSA_P256_ALGORITHM,
                    Some(EccCurve::P384) => NCRYPT_ECDSA_P384_ALGORITHM,
                    Some(EccCurve::P521) => NCRYPT_ECDSA_P521_ALGORITHM,
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
                let key_length: u32 = match self.0.read().ecc_curve_type {
                    Some(EccCurve::P256) => 256,
                    Some(EccCurve::P384) => 384,
                    Some(EccCurve::P521) => 521,
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

    pub fn assign_default(&mut self, _app_session: &HsmSession) -> AzIHsmHresult<()> {
        tracing::debug!("Assigning default ECDSA key properties");

        // No need to set key length, it will be set by device

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

                Ok(())
            }
            KeyOrigin::Generate => self.0.write().finalize_key(app_session),
            KeyOrigin::Derive => {
                tracing::error!("Finalizing ECDSA Key, its origin cannot be Derive");
                Err(HRESULT(NTE_NOT_SUPPORTED))
            }
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
        self.0.write().base_key.delete_key(app_session)
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

        let magic_blob = bcrypt_util::ecdsa_der_to_bcrypt(
            &der_format_output[..der_format_output_size as usize],
        )?;

        validate_output_buffer!(output, output_size, magic_blob.len() as u32);

        output[..magic_blob.len()].copy_from_slice(&magic_blob);
        *output_size = magic_blob.len() as u32;

        Ok(())
    }

    /// Signs the input data.
    ///
    /// # Arguments
    ///  * `app_session` - The HsmSession to use for signing the data.
    ///  * `input` - The input data to sign.
    ///  * `output` - The output buffer to store the signature.
    ///  * `output_size` - The size of the output buffer.
    ///
    /// # Returns
    /// `Ok(())` if the data was signed successfully; otherwise, an error code.
    ///
    pub fn sign(
        &self,
        app_session: &HsmSession,
        input: &[u8],
        output: &mut [u8],
        output_size: &mut u32,
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot sign at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        let signature_size = self.signature_size(input.len())?;
        validate_output_buffer!(output, output_size, signature_size as u32);

        let signature = match app_session.ecc_sign(&hsm_key_handle, input.to_vec()) {
            Ok(signature) => signature,
            Err(err) => {
                tracing::error!(?err, "HsmSession::ecc_sign failed",);
                Err(HRESULT::from_win32(ERROR_INVALID_DATA))?
            }
        };

        output[..signature.len()].copy_from_slice(&signature);
        *output_size = signature.len() as u32;
        tracing::debug!("EcdsaKey::sign succeeded");
        Ok(())
    }

    /// Verifies the signature.
    ///
    /// # Arguments
    ///  * `app_session` - The HsmSession to use for verifying the signature.
    ///  * `hash_value` - The hash value to verify.
    ///  * `signature` - The signature to verify.
    ///
    /// # Returns
    /// `Ok(())` if the signature was verified successfully; otherwise, an error code.
    ///
    pub fn verify(
        &self,
        app_session: &HsmSession,
        hash_value: &[u8],
        signature: &[u8],
    ) -> Result<(), HRESULT> {
        let hsm_key_handle = match self.hsm_key_handle() {
            Some(hsm_key_handle) => hsm_key_handle,
            None => {
                tracing::error!("HSM Key is not created, cannot verify at this time.");
                Err(HRESULT(E_UNEXPECTED))?
            }
        };

        match app_session.ecc_verify(&hsm_key_handle, hash_value.to_vec(), signature.to_vec()) {
            Ok(_) => {
                tracing::debug!("EcdsaKey::verify succeeded");
                Ok(())
            }
            Err(err) => {
                tracing::error!(?err, "HsmSession::ecc_verify failed.",);
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

    fn signature_size(&self, digest_size: usize) -> Result<usize, HRESULT> {
        let ecc_curve_type = self.ecc_curve_type();
        match (ecc_curve_type, digest_size) {
            (Some(EccCurve::P256), SHA1_DIGEST_SIZE)
            | (Some(EccCurve::P256), SHA256_DIGEST_SIZE) => Ok(ECC_P256_SIGNATURE_SIZE),
            (Some(EccCurve::P384), SHA1_DIGEST_SIZE)
            | (Some(EccCurve::P384), SHA256_DIGEST_SIZE)
            | (Some(EccCurve::P384), SHA384_DIGEST_SIZE) => Ok(ECC_P384_SIGNATURE_SIZE),
            (Some(EccCurve::P521), SHA1_DIGEST_SIZE)
            | (Some(EccCurve::P521), SHA256_DIGEST_SIZE)
            | (Some(EccCurve::P521), SHA384_DIGEST_SIZE)
            | (Some(EccCurve::P521), SHA512_DIGEST_SIZE) => Ok(ECC_P521_SIGNATURE_SIZE),
            _ => {
                tracing::error!(
                    "Invalid ECC curve type '{:?}' or digest size '{}'",
                    ecc_curve_type,
                    digest_size
                );
                Err(HRESULT(E_INVALIDARG))
            }
        }
    }
}

#[derive(Debug)]
struct EcdsaInnerKey {
    base_key: BaseKey,
    ecc_curve_type: Option<EccCurve>,
}

impl EcdsaInnerKey {
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
                Some(KeyUsage::SignVerify), // Default KeyUsage for ECDSA
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
                key_usage: KeyUsage::SignVerify,
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
