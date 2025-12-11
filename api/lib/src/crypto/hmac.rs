#![warn(missing_docs)]
// Copyright (C) Microsoft Corporation. All rights reserved.

//! HMAC cryptographic operations

use std::sync::Arc;

use parking_lot::RwLock;

use crate::crypto::Algo;
use crate::crypto::AzihsmError;
use crate::crypto::Key;
use crate::crypto::KeyDeleteOp;
use crate::crypto::KeyId;
use crate::crypto::KeyProps;
use crate::crypto::SafeInnerAccess;
use crate::crypto::Session;
use crate::crypto::SignOp;
use crate::crypto::StreamingSignOp;
use crate::crypto::StreamingSignVerifyAlgo;
use crate::crypto::StreamingVerifyOp;
use crate::crypto::VerifyOp;
use crate::ddi;
use crate::types::AlgoId;
use crate::AZIHSM_ALGORITHM_NOT_SUPPORTED;
use crate::AZIHSM_DELETE_KEY_FAILED;
use crate::AZIHSM_ERROR_INSUFFICIENT_BUFFER;
use crate::AZIHSM_ERROR_MSG_TOO_LARGE;
use crate::AZIHSM_HMAC_SIGN_FAILED;
use crate::AZIHSM_HMAC_VERIFY_FAILED;
use crate::AZIHSM_KEY_NOT_INITIALIZED;

/// Maximum message size for HMAC streaming operations (in bytes)
const HMAC_MAX_MESSAGE_SIZE: usize = 1024;

/// Define HMAC Key type
#[derive(Clone, Debug)]
pub struct HmacKey(Arc<RwLock<HmacKeyInner>>);

#[derive(Debug)]
struct HmacKeyInner {
    id: Option<KeyId>,
    #[allow(unused)]
    props: KeyProps,
    _masked_key: Option<Vec<u8>>,
}

impl HmacKey {
    #[allow(unused)]
    pub fn new(props: KeyProps) -> Self {
        HmacKey(Arc::new(RwLock::new(HmacKeyInner {
            id: None,
            props,
            _masked_key: None,
        })))
    }
    pub fn new_with_id(props: KeyProps, key_id: KeyId) -> Self {
        HmacKey(Arc::new(RwLock::new(HmacKeyInner {
            id: Some(key_id),
            props,
            _masked_key: None,
        })))
    }
    #[allow(unused)]
    fn with_inner<R>(&self, f: impl FnOnce(&HmacKeyInner) -> R) -> R {
        self.0.with_inner(f)
    }

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut HmacKeyInner) -> R) -> R {
        self.0.with_inner_mut(f)
    }

    #[allow(unused)]
    pub fn id(&self) -> Option<KeyId> {
        self.with_inner(|inner| inner.id)
    }
}

impl Key for HmacKey {}

impl KeyDeleteOp for HmacKey {
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

/// HMAC Algo
pub struct HmacAlgo {
    pub id: AlgoId,
}

impl Algo for HmacAlgo {}

impl SignOp<HmacKey> for HmacAlgo {
    fn signature_len(&self, key: &HmacKey) -> Result<u32, AzihsmError> {
        let _key_id = key.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        match self.id {
            AlgoId::HmacSha1 => Ok(20),
            AlgoId::HmacSha256 => Ok(32),
            AlgoId::HmacSha384 => Ok(48),
            AlgoId::HmacSha512 => Ok(64),
            _ => Err(AZIHSM_ALGORITHM_NOT_SUPPORTED),
        }
    }

    fn sign(
        &self,
        session: &Session,
        priv_key_id: &HmacKey,
        data: &[u8],
        sig: &mut [u8],
    ) -> Result<(), AzihsmError> {
        // Retrieve key ID
        let key_id = priv_key_id.id().ok_or(AZIHSM_KEY_NOT_INITIALIZED)?;
        let resp = ddi::hmac_sign(
            &session.partition().read().partition,
            Some(session.session_id()),
            Some(session.api_rev().into()),
            key_id.0,
            data,
        )
        .map_err(|_| AZIHSM_HMAC_SIGN_FAILED)?;

        // make sure sig is the right length
        if sig.len() < resp.data.tag.len() {
            Err(AZIHSM_ERROR_INSUFFICIENT_BUFFER)?;
        }
        //copy only the tag portion
        sig[..resp.data.tag.len()].copy_from_slice(&resp.data.tag.data()[..resp.data.tag.len()]);
        Ok(())
    }
}

/// Implement verify op
impl VerifyOp<HmacKey> for HmacAlgo {
    fn verify(
        &self,
        session: &Session,
        key: &HmacKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AzihsmError> {
        //  DDI doesn't support HMAC verify, since both parties will derive same HMAC key, we should calculate
        // tag similar to sign then verify it with signature

        // buffer to recalculate tag
        let mut computed_tag = vec![0u8; self.signature_len(key)? as usize];

        self.sign(session, key, data, computed_tag.as_mut_slice())?;

        // compare computed tag with signature
        if computed_tag.as_slice() != signature {
            Err(AZIHSM_HMAC_VERIFY_FAILED)?;
        }

        Ok(())
    }
}

/// HMAC streaming sign operation
pub struct HmacSignStream<'a> {
    session: &'a Session,
    key: HmacKey,
    algo: HmacAlgo,
    buffer: Vec<u8>,
}

impl<'a> HmacSignStream<'a> {
    pub fn new(session: &'a Session, algo: &HmacAlgo, key: &HmacKey) -> Self {
        HmacSignStream {
            session,
            key: key.clone(),
            algo: HmacAlgo { id: algo.id },
            buffer: Vec::new(),
        }
    }

    pub fn signature_len(&self) -> Result<u32, AzihsmError> {
        self.algo.signature_len(&self.key)
    }
}

impl StreamingSignOp for HmacSignStream<'_> {
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        // Check if adding this data would exceed HMAC_MAX_MESSAGE_SIZE bytes
        if self.buffer.len() + data.len() > HMAC_MAX_MESSAGE_SIZE {
            Err(AZIHSM_ERROR_MSG_TOO_LARGE)?;
        }

        // Accumulate data
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self, signature: &mut [u8]) -> Result<usize, AzihsmError> {
        // Call the one-shot sign operation with accumulated data
        self.algo
            .sign(self.session, &self.key, &self.buffer, signature)?;
        Ok(self.signature_len()? as usize)
    }

    fn signature_len(&self) -> Result<u32, AzihsmError> {
        self.algo.signature_len(&self.key)
    }
}

/// HMAC streaming verify operation
pub struct HmacVerifyStream<'a> {
    session: &'a Session,
    key: HmacKey,
    algo: HmacAlgo,
    buffer: Vec<u8>,
}

impl<'a> HmacVerifyStream<'a> {
    pub fn new(session: &'a Session, algo: &HmacAlgo, key: &HmacKey) -> Self {
        HmacVerifyStream {
            session,
            key: key.clone(),
            algo: HmacAlgo { id: algo.id },
            buffer: Vec::new(),
        }
    }
}

impl StreamingVerifyOp for HmacVerifyStream<'_> {
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError> {
        // Check if adding this data would exceed HMAC_MAX_MESSAGE_SIZE bytes
        if self.buffer.len() + data.len() > HMAC_MAX_MESSAGE_SIZE {
            Err(AZIHSM_ERROR_MSG_TOO_LARGE)?;
        }

        // Accumulate data
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self, signature: &[u8]) -> Result<(), AzihsmError> {
        // Call the one-shot verify operation with accumulated data
        self.algo
            .verify(self.session, &self.key, &self.buffer, signature)
    }
}

/// Implement streaming sign/verify algo trait
impl<'a> StreamingSignVerifyAlgo<'a, HmacKey> for HmacAlgo {
    type SignStream = HmacSignStream<'a>;
    type VerifyStream = HmacVerifyStream<'a>;

    fn sign_init(
        &self,
        session: &'a Session,
        key: &HmacKey,
    ) -> Result<Self::SignStream, AzihsmError> {
        Ok(HmacSignStream::new(session, self, key))
    }

    fn verify_init(
        &self,
        session: &'a Session,
        key: &HmacKey,
    ) -> Result<Self::VerifyStream, AzihsmError> {
        Ok(HmacVerifyStream::new(session, self, key))
    }
}
