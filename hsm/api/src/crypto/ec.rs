// Copyright (C) Microsoft Corporation. All rights reserved.

use std::sync::Arc;

use azihsm_crypto::EcCurveId;
use azihsm_crypto::EcPublicKey;
use azihsm_crypto::EcdsaCryptVerifyOp;
use azihsm_crypto::EckeyOps;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use mcr_ddi_types::DdiEccCurve;
use mcr_ddi_types::DdiKeyProperties;
use parking_lot::RwLock;

use crate::crypto::Algo;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyGenOp;
use crate::crypto::KeyId;
use crate::crypto::SafeInnerAccess;
use crate::crypto::SignOp;
use crate::crypto::StreamingSignOp;
use crate::crypto::StreamingSignVerifyAlgo;
use crate::crypto::StreamingVerifyOp;
use crate::crypto::VerifyOp;
use crate::ddi;
use crate::types::key_props::AzihsmKeyPropId;
use crate::types::key_props::KeyPairPropsOps;
use crate::types::key_props::KeyPropValue;
use crate::types::AlgoId;
use crate::types::EcCurve;
use crate::types::KeyProps;
use crate::AzihsmError;
use crate::Session;
use crate::AZIHSM_ECC_KEYGEN_FAILED;
use crate::AZIHSM_ECC_SIGN_FAILED;
use crate::AZIHSM_ECC_VERIFY_FAILED;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_ERROR_INVALID_ARGUMENT;
use crate::AZIHSM_ILLEGAL_KEY_PROPERTY;
use crate::AZIHSM_INTERNAL_ERROR;
use crate::AZIHSM_KEY_ALREADY_EXISTS;
use crate::AZIHSM_KEY_NOT_INITIALIZED;
use crate::AZIHSM_KEY_PROPERTY_NOT_PRESENT;

impl TryFrom<&KeyProps> for DdiEccCurve {
    type Error = AzihsmError;

    fn try_from(props: &KeyProps) -> Result<DdiEccCurve, Self::Error> {
        let curve = props.ecc_curve().ok_or(AZIHSM_KEY_PROPERTY_NOT_PRESENT)?;
        match curve {
            EcCurve::P256 => Ok(DdiEccCurve::P256),
            EcCurve::P384 => Ok(DdiEccCurve::P384),
            EcCurve::P521 => Ok(DdiEccCurve::P521),
        }
    }
}

impl TryFrom<u32> for EcCurve {
    type Error = AzihsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EcCurve::P256),
            2 => Ok(EcCurve::P384),
            3 => Ok(EcCurve::P521),
            _ => Err(AZIHSM_ERROR_INVALID_ARGUMENT),
        }
    }
}

impl From<EcCurve> for EcCurveId {
    fn from(curve: EcCurve) -> Self {
        match curve {
            EcCurve::P256 => EcCurveId::EccP256,
            EcCurve::P384 => EcCurveId::EccP384,
            EcCurve::P521 => EcCurveId::EccP521,
        }
    }
}

impl TryFrom<AlgoId> for HashAlgo {
    type Error = AzihsmError;

    fn try_from(algo_id: AlgoId) -> Result<Self, Self::Error> {
        match algo_id {
            AlgoId::EcdsaSha1 | AlgoId::RsaPkcsSha1 | AlgoId::RsaPkcsPssSha1 | AlgoId::Sha1 => {
                Ok(HashAlgo::Sha1)
            }
            AlgoId::EcdsaSha256
            | AlgoId::RsaPkcsSha256
            | AlgoId::RsaPkcsPssSha256
            | AlgoId::Sha256 => Ok(HashAlgo::Sha256),
            AlgoId::EcdsaSha384
            | AlgoId::RsaPkcsSha384
            | AlgoId::RsaPkcsPssSha384
            | AlgoId::Sha384 => Ok(HashAlgo::Sha384),
            AlgoId::EcdsaSha512
            | AlgoId::RsaPkcsSha512
            | AlgoId::RsaPkcsPssSha512
            | AlgoId::Sha512 => Ok(HashAlgo::Sha512),
            _ => Err(AZIHSM_ERROR_INVALID_ARGUMENT), // Not an ECDSA Hash algorithm
        }
    }
}

#[derive(Clone, Debug)]
pub struct EcdsaKeyPair(Arc<RwLock<EcdsaKeyPairInner>>);

#[derive(Debug)]
struct EcdsaKeyPairInner {
    priv_key_id: Option<KeyId>,
    #[allow(unused)]
    pub_key_props: KeyProps,
    priv_key_props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl EcdsaKeyPair {
    pub fn new(pub_key_props: KeyProps, priv_key_props: KeyProps) -> Self {
        EcdsaKeyPair(Arc::new(RwLock::new(EcdsaKeyPairInner {
            priv_key_id: None,
            pub_key_props,
            priv_key_props,
            _masked_key: None,
        })))
    }
    pub fn new_with_id(
        priv_key_id: KeyId,
        pub_key_props: KeyProps,
        priv_key_props: KeyProps,
    ) -> Self {
        EcdsaKeyPair(Arc::new(RwLock::new(EcdsaKeyPairInner {
            priv_key_id: Some(priv_key_id),
            pub_key_props,
            priv_key_props,
            _masked_key: None,
        })))
    }

    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&EcdsaKeyPairInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut EcdsaKeyPairInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn priv_key_id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.priv_key_id)
    }

    #[allow(unused)]
    pub fn pub_key(&self) -> Option<Vec<u8>> {
        self.with_inner(|inner| {
            match inner
                .pub_key_props
                .get_property(AzihsmKeyPropId::PubKeyInfo)
            {
                Ok(KeyPropValue::PubKeyInfo(data)) => Some(data),
                _ => None,
            }
        })
    }

    #[allow(unused)]
    pub fn with_pub_key<R>(&self, f: impl FnOnce(Option<&[u8]>) -> R) -> R {
        self.with_inner(|inner| {
            match inner
                .pub_key_props
                .get_property(AzihsmKeyPropId::PubKeyInfo)
            {
                Ok(KeyPropValue::PubKeyInfo(data)) => f(Some(&data)),
                _ => f(None),
            }
        })
    }

    /// Get the curve type for this key pair
    #[allow(unused)]
    pub(crate) fn curve(&self) -> Option<EcCurve> {
        self.with_inner(|inner| inner.priv_key_props.ecc_curve())
    }
}

impl Key for EcdsaKeyPair {}

impl KeyPairPropsOps for EcdsaKeyPair {
    fn get_pub_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.pub_key_props.get_property(id))
    }

    fn set_pub_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.pub_key_props.set_property(id, value))
    }

    fn get_priv_property(&self, id: AzihsmKeyPropId) -> Result<KeyPropValue, AzihsmError> {
        self.with_inner(|inner| inner.priv_key_props.get_property(id))
    }

    fn set_priv_property(
        &mut self,
        id: AzihsmKeyPropId,
        value: KeyPropValue,
    ) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| inner.priv_key_props.set_property(id, value))
    }
}

impl KeyGenOp for EcdsaKeyPair {
    fn generate_key_pair(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        // Check if already generated
        if inner.priv_key_id.is_some() {
            Err(AZIHSM_KEY_ALREADY_EXISTS)?;
        }

        // Use private key properties for generation.
        let ddi_curve = DdiEccCurve::try_from(&inner.priv_key_props)?;
        let ddi_key_props = DdiKeyProperties::try_from(&inner.priv_key_props)?;

        let resp = ddi::ecc_generate_key_pair(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            ddi_curve,
            None,
            ddi_key_props,
        )
        .map_err(|_| AZIHSM_ECC_KEYGEN_FAILED)?;

        // Copy private key ID
        inner.priv_key_id = Some(KeyId(resp.data.private_key_id));

        // Store public key DER as PubKeyInfo property
        if let Some(resp_pub_key) = resp.data.pub_key {
            let pub_key_der = resp_pub_key.der.data()[..resp_pub_key.der.len()].to_vec();
            inner.pub_key_props.set_pub_key_info(pub_key_der);
        }
        Ok(())
    }
}

impl KeyDeleteOp for EcdsaKeyPair {
    /// Delete the entire key pair (both public and private keys)
    fn delete_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut errors = Vec::new();

        // Try to delete private key first
        if let Err(e) = self.delete_priv_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Always try to delete public key
        if let Err(e) = self.delete_pub_key(session) {
            // Only consider it an error if the key was actually initialized
            if e != AZIHSM_KEY_NOT_INITIALIZED {
                errors.push(e);
            }
        }

        // Return the first error if any occurred during actual deletion
        if let Some(error) = errors.first() {
            Err(*error)
        } else {
            Ok(())
        }
    }

    /// Delete only the public key (local storage only)
    fn delete_pub_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        self.with_inner_mut(|inner| {
            // Check if public key exists in property
            match inner
                .pub_key_props
                .get_property(AzihsmKeyPropId::PubKeyInfo)
            {
                Ok(KeyPropValue::PubKeyInfo(_)) => {
                    // Clear the PubKeyInfo property
                    inner.pub_key_props.clear_pub_key_info();
                    Ok(())
                }
                _ => Err(AZIHSM_KEY_NOT_INITIALIZED),
            }
        })
    }

    /// Delete only the private key from the HSM
    fn delete_priv_key(&mut self, session: &Session) -> Result<(), AzihsmError> {
        let mut inner = self.0.write();

        let key_id = match inner.priv_key_id {
            Some(id) => id,
            None => Err(AZIHSM_KEY_NOT_INITIALIZED)?,
        };

        // Delete only the private key from HSM
        ddi::delete_key(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0,
        )
        .map_err(|_| AZIHSM_ILLEGAL_KEY_PROPERTY)?;

        // Clear only the private key - leave public key intact
        inner.priv_key_id = None;

        Ok(())
    }
}

pub struct EcdsaAlgo {
    algo: AlgoId,
}

impl EcdsaAlgo {
    #[allow(unused)]
    pub fn new(algo: AlgoId) -> Self {
        Self { algo }
    }
}

impl Algo for EcdsaAlgo {}

impl SignOp<EcdsaKeyPair> for EcdsaAlgo {
    fn signature_len(&self, key: &EcdsaKeyPair) -> Result<u32, AzihsmError> {
        let curve = key.curve().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        match curve {
            EcCurve::P256 => Ok(64),
            EcCurve::P384 => Ok(96),
            EcCurve::P521 => Ok(132),
        }
    }

    fn sign(
        &self,
        session: &Session,
        priv_key: &EcdsaKeyPair,
        data: &[u8],
        sig: &mut [u8],
    ) -> Result<(), AzihsmError> {
        // ensure private key ID exists
        if priv_key.priv_key_id().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        let digest_to_sign = if self.algo == AlgoId::Ecdsa {
            // Generic ECDSA - treat input as pre-computed digest
            data.to_vec()
        } else {
            // Specific ECDSA with hash algorithm - need to hash
            let hash_algo = HashAlgo::try_from(self.algo)?;

            let mut digest = vec![0u8; hash_algo.hash_length()];
            hash_algo
                .hash(data, &mut digest)
                .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

            digest
        };
        let priv_key_id = priv_key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        // Perform the actual signing with the digest
        let resp = ddi::ecc_sign(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            priv_key_id.0,
            &digest_to_sign,
        )
        .map_err(|_| AZIHSM_ECC_SIGN_FAILED)?;

        let sig_data = resp.data.signature.data();
        let sig_len = resp.data.signature.len() as usize;

        if sig.len() < sig_len {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        sig[..sig_len].copy_from_slice(&sig_data[..sig_len]);

        Ok(())
    }
}

impl VerifyOp<EcdsaKeyPair> for EcdsaAlgo {
    fn verify(
        &self,
        _session: &Session,
        key_pair: &EcdsaKeyPair,
        data: &[u8],
        sig: &[u8],
    ) -> Result<(), AzihsmError> {
        let curve = key_pair.curve().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        let ecc_public_key = key_pair.with_pub_key(|pub_key_opt| match pub_key_opt {
            Some(pub_key_bytes) => EcPublicKey::ec_key_from_der(pub_key_bytes, curve.into())
                .map_err(|_| AZIHSM_INTERNAL_ERROR),
            None => Err(AZIHSM_KEY_NOT_INITIALIZED),
        })?;

        let digest_to_verify = if self.algo == AlgoId::Ecdsa {
            // Generic ECDSA - treat input as pre-computed digest
            data.to_vec()
        } else {
            // Specific ECDSA with hash algorithm - need to hash
            let hash_algo = HashAlgo::try_from(self.algo)?;

            let mut digest = vec![0u8; hash_algo.hash_length()];
            hash_algo
                .hash(data, &mut digest)
                .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

            digest
        };

        ecc_public_key
            .ecdsa_crypt_verify_digest(&digest_to_verify, sig)
            .map_err(|_| AZIHSM_ECC_VERIFY_FAILED)
    }
}

/// Streaming ECDSA sign operation
pub struct EcdsaSignStream<'a> {
    algo: AlgoId,
    key: EcdsaKeyPair,
    buffered_data: Vec<u8>,
    session: &'a Session,
}

impl<'a> StreamingSignOp for EcdsaSignStream<'a> {
    fn signature_len(&self) -> Result<u32, AzihsmError> {
        let curve = self.key.curve().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        Ok(match curve {
            EcCurve::P256 => 64,
            EcCurve::P384 => 96,
            EcCurve::P521 => 132,
        })
    }

    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        // Accumulate data for hashing
        self.buffered_data.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self, signature: &mut [u8]) -> Result<usize, AzihsmError> {
        // Ensure private key ID exists
        if self.key.priv_key_id().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        let digest_to_sign = if self.algo == AlgoId::Ecdsa {
            // Generic ECDSA - treat accumulated data as pre-computed digest
            self.buffered_data
        } else {
            // Specific ECDSA with hash algorithm - hash the accumulated data
            let hash_algo = HashAlgo::try_from(self.algo)?;

            let mut digest = vec![0u8; hash_algo.hash_length()];
            hash_algo
                .hash(&self.buffered_data, &mut digest)
                .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

            digest
        };

        let priv_key_id = self.key.priv_key_id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        // Perform the actual signing with the digest
        let resp = ddi::ecc_sign(
            &self.session.partition().read().partition,
            Some(self.session.session_id()),
            Some(self.session.api_rev().into()),
            priv_key_id.0,
            &digest_to_sign,
        )
        .map_err(|_| AZIHSM_ECC_SIGN_FAILED)?;

        let sig_data = resp.data.signature.data();
        let sig_len = resp.data.signature.len() as usize;

        if signature.len() < sig_len {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }

        signature[..sig_len].copy_from_slice(&sig_data[..sig_len]);

        Ok(sig_len)
    }
}

/// Streaming ECDSA verify operation
pub struct EcdsaVerifyStream {
    algo: AlgoId,
    key: EcdsaKeyPair,
    buffered_data: Vec<u8>,
}

impl StreamingVerifyOp for EcdsaVerifyStream {
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        // Accumulate data for hashing
        self.buffered_data.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self, signature: &[u8]) -> Result<(), AzihsmError> {
        let curve = self.key.curve().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;

        let ecc_public_key = self.key.with_pub_key(|pub_key_opt| match pub_key_opt {
            Some(pub_key_bytes) => EcPublicKey::ec_key_from_der(pub_key_bytes, curve.into())
                .map_err(|_| AZIHSM_INTERNAL_ERROR),
            None => Err(AZIHSM_KEY_NOT_INITIALIZED),
        })?;

        let digest_to_verify = if self.algo == AlgoId::Ecdsa {
            // Generic ECDSA - treat accumulated data as pre-computed digest
            self.buffered_data
        } else {
            // Specific ECDSA with hash algorithm - hash the accumulated data
            let hash_algo = HashAlgo::try_from(self.algo)?;

            let mut digest = vec![0u8; hash_algo.hash_length()];
            hash_algo
                .hash(&self.buffered_data, &mut digest)
                .map_err(|_| AZIHSM_INTERNAL_ERROR)?;

            digest
        };

        ecc_public_key
            .ecdsa_crypt_verify_digest(&digest_to_verify, signature)
            .map_err(|_| AZIHSM_ECC_VERIFY_FAILED)
    }
}

impl<'a> StreamingSignVerifyAlgo<'a, EcdsaKeyPair> for EcdsaAlgo {
    type SignStream = EcdsaSignStream<'a>;
    type VerifyStream = EcdsaVerifyStream;

    fn sign_init(
        &self,
        session: &'a Session,
        key: &EcdsaKeyPair,
    ) -> Result<Self::SignStream, AzihsmError> {
        // Ensure private key exists
        if key.priv_key_id().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        Ok(EcdsaSignStream {
            algo: self.algo,
            key: key.clone(),
            buffered_data: Vec::new(),
            session,
        })
    }

    fn verify_init(
        &self,
        _session: &'a Session,
        key: &EcdsaKeyPair,
    ) -> Result<Self::VerifyStream, AzihsmError> {
        // Ensure public key exists
        if key.pub_key().is_none() {
            Err(AZIHSM_KEY_NOT_INITIALIZED)?;
        }

        Ok(EcdsaVerifyStream {
            algo: self.algo,
            key: key.clone(),
            buffered_data: Vec::new(),
        })
    }
}
