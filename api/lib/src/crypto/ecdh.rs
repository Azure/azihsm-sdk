// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use std::sync::Arc;

use azihsm_ddi_types::DdiKeyAvailability;
use azihsm_ddi_types::DdiKeyType;
use azihsm_ddi_types::DdiKeyUsage;
use parking_lot::RwLock;

use crate::crypto::ec::EcdsaKeyPair;
use crate::crypto::Algo;
use crate::crypto::DeriveOp;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyId;
use crate::crypto::SafeInnerAccess;
use crate::ddi;
use crate::types::EcCurve;
use crate::types::KeyProps;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_DELETE_KEY_FAILED;
use crate::AZIHSM_ECDH_DERIVE_FAILED;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;
use crate::AZIHSM_KEY_NOT_INITIALIZED;

/// Define secret key params
#[derive(Clone, Debug)]
pub struct SecretKey(Arc<RwLock<SecretKeyInner>>);

#[derive(Debug)]
struct SecretKeyInner {
    id: Option<KeyId>,
    #[allow(unused)]
    props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl SecretKey {
    #[allow(unused)]
    pub fn new(props: KeyProps) -> Self {
        SecretKey(Arc::new(RwLock::new(SecretKeyInner {
            id: None,
            props,
            _masked_key: None,
        })))
    }
    pub fn new_with_id(props: KeyProps, key_id: KeyId) -> Self {
        SecretKey(Arc::new(RwLock::new(SecretKeyInner {
            id: Some(key_id),
            props,
            _masked_key: None,
        })))
    }
    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&SecretKeyInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut SecretKeyInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.id)
    }
}

impl Key for SecretKey {}

impl KeyDeleteOp for SecretKey {
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        let key_id = inner.id.ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0,
        )
        .map_err(|_| AZIHSM_DELETE_KEY_FAILED)?;

        // Clear the key ID to indicate it's deleted
        inner.id = None;

        Ok(())
    }
}

/// Ecdh Key Operations
// Ecdh Algo params
pub struct EcdhParams {
    pub pub_key: Vec<u8>,
}
pub struct EcdhAlgo {
    pub params: EcdhParams,
}
impl Algo for EcdhAlgo {}

/// Implement secret derive for ECDH
impl DeriveOp<EcdsaKeyPair> for EcdhAlgo {
    fn key_derive(
        &self,
        session: &Session,
        base_key: &EcdsaKeyPair,
        derived_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError> {
        // ensure private key ID exists
        let priv_key_id = base_key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // Determine the appropriate key type based on the curve
        let curve = base_key.curve().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let key_type = match curve {
            EcCurve::P256 => DdiKeyType::Secret256,
            EcCurve::P384 => DdiKeyType::Secret384,
            EcCurve::P521 => DdiKeyType::Secret521,
        };

        // Validate key properties - ensure conflicting usages are not specified
        let has_derive = derived_key_props.derive().unwrap_or(false);
        let has_encrypt_decrypt = derived_key_props.encrypt().unwrap_or(false)
            || derived_key_props.decrypt().unwrap_or(false);
        let has_sign_verify = derived_key_props.sign().unwrap_or(false)
            || derived_key_props.verify().unwrap_or(false);

        // Not allowed to have multiple conflicting key usages
        if (has_sign_verify || has_encrypt_decrypt) && has_derive {
            Err(AZIHSM_ILLEGAL_KEY_PROPERTY)?
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

        // Derive the secret using the ECDH algorithm
        let resp = ddi::ecdh_key_derive(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            priv_key_id.0,
            &self.params.pub_key,
            None,
            key_type,
            key_usage,
            DdiKeyAvailability::App,
            None,
        )
        .map_err(|_| AZIHSM_ECDH_DERIVE_FAILED)?;
        //return the keyid
        Ok(KeyId(resp.data.key_id))
    }
}
