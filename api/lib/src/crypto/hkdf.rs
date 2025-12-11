#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! HKDF cryptographic operations

use mcr_ddi_types::DdiHashAlgorithm;
use mcr_ddi_types::DdiKeyAvailability;
use mcr_ddi_types::DdiKeyType;
use mcr_ddi_types::DdiKeyUsage;

use crate::crypto::ecdh::SecretKey;
use crate::crypto::Algo;
use crate::crypto::AzihsmError;
use crate::crypto::DeriveOp;
use crate::crypto::KeyId;
use crate::ddi::HkdfKeyDeriveParams;
use crate::types::AlgoId;
use crate::types::KeyKind;
use crate::types::KeyProps;
use crate::AZIHSM_HKDF_DERIVE_FAILED;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;

#[derive(Debug, Clone)]
pub(crate) struct HkdfAlgoParams {
    pub hmac_algo_id: AlgoId,
    pub salt: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct HkdfAlgo {
    pub params: HkdfAlgoParams,
}

impl Algo for HkdfAlgo {}

impl HkdfAlgo {
    fn get_target_key_type(&self, target_key_props: &KeyProps) -> Result<DdiKeyType, AzihsmError> {
        // Get Key type first, and for aes+bit length will be target key,
        let target_key_type = target_key_props
            .kind()
            .ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?;

        match target_key_type {
            KeyKind::Aes => match target_key_props.bit_len() {
                Some(128) => Ok(DdiKeyType::Aes128),
                Some(192) => Ok(DdiKeyType::Aes192),
                Some(256) => Ok(DdiKeyType::Aes256),
                None => Err(AZIHSM_KEY_PROPERTY_NOT_PRESENT),
                _ => Err(AZIHSM_ILLEGAL_KEY_PROPERTY),
            },
            KeyKind::HmacSha256 => Ok(DdiKeyType::HmacSha256),
            KeyKind::HmacSha384 => Ok(DdiKeyType::HmacSha384),
            KeyKind::HmacSha512 => Ok(DdiKeyType::HmacSha512),
            _ => Err(AZIHSM_ILLEGAL_KEY_PROPERTY),
        }
    }
}

/// Implement Key Derive for HKDF
impl DeriveOp<SecretKey> for HkdfAlgo {
    fn key_derive(
        &self,
        session: &crate::Session,
        base_key: &SecretKey,
        derived_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError> {
        let ddi_hash_algo = match self.params.hmac_algo_id {
            AlgoId::HmacSha1 => DdiHashAlgorithm::Sha1,
            AlgoId::HmacSha256 => DdiHashAlgorithm::Sha256,
            AlgoId::HmacSha384 => DdiHashAlgorithm::Sha384,
            AlgoId::HmacSha512 => DdiHashAlgorithm::Sha512,
            _ => Err(crate::AZIHSM_ALGORITHM_NOT_SUPPORTED)?,
        };
        // check if basekey is properly initialized
        let base_key_id = base_key.id().ok_or(crate::AZIHSM_KEY_NOT_INITIALIZED)?.0;

        // Validate key properties - ensure conflicting usages are not specified
        let has_derive = derived_key_props.derive().unwrap_or(false);
        let has_encrypt_decrypt = derived_key_props.encrypt().unwrap_or(false)
            || derived_key_props.decrypt().unwrap_or(false);
        let has_sign_verify = derived_key_props.sign().unwrap_or(false)
            || derived_key_props.verify().unwrap_or(false);

        // Not allowed to have multiple conflicting usages
        if (has_sign_verify || has_encrypt_decrypt) && has_derive {
            Err(AZIHSM_ILLEGAL_KEY_PROPERTY)?;
        }
        // Determine key usage based on properties (prioritize derive for ECDH)
        let key_usage = if has_derive {
            DdiKeyUsage::Derive
        } else if has_encrypt_decrypt {
            DdiKeyUsage::EncryptDecrypt
        } else if has_sign_verify {
            DdiKeyUsage::SignVerify
        } else {
            // Default to derive for ECDH operations
            DdiKeyUsage::Derive
        };

        // get key availability
        let key_availability = match derived_key_props.session() {
            Some(true) => DdiKeyAvailability::Session,
            _ => DdiKeyAvailability::App,
        };

        let salt = self.params.salt.as_deref();
        let info = self.params.info.as_deref();

        // construct key label
        let key_label = derived_key_props.label().map(|e| e.as_bytes().to_vec());
        // get target key type
        let target_key_type = self.get_target_key_type(derived_key_props)?;

        // construct HKDF derive params
        let derive_params = HkdfKeyDeriveParams {
            hash_algo: ddi_hash_algo,
            target_key_type,
            key_usage,
            key_availability,
            key_label,
        };
        // call DDI hkdf
        let resp = crate::ddi::hkdf_key_derive(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            base_key_id,
            salt,
            info,
            derive_params,
        )
        .map_err(|_| AZIHSM_HKDF_DERIVE_FAILED)?;

        //return KeyId
        Ok(KeyId(resp.data.key_id))
    }
}
