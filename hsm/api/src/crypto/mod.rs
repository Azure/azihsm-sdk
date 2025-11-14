// Copyright (C) Microsoft Corporation. All rights reserved.

pub mod aes;
pub mod ec;
pub mod rsa;
pub mod sha;

use std::sync::Arc;

use parking_lot::RwLock;

use crate::bindings::AzihsmError;
use crate::Session;
use crate::AZIHSM_OPERATION_NOT_SUPPORTED;

/// Common trait for all key types that need safe inner access
pub trait SafeInnerAccess<T> {
    fn with_inner<R>(&self, f: impl FnOnce(&T) -> R) -> R;

    #[allow(unused)]
    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R;
}

/// Blanket implementation for any Arc<RwLock<T>> using parking_lot
impl<T> SafeInnerAccess<T> for Arc<RwLock<T>> {
    fn with_inner<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let guard = self.read();
        f(&*guard)
    }

    fn with_inner_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let mut guard = self.write();
        f(&mut *guard)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u16);

pub trait Key {}

pub(crate) trait KeyGenOp {
    fn generate_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }

    fn generate_key_pair(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

pub(crate) trait KeyDeleteOp {
    /// Delete the secret key
    fn delete_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }

    /// Delete only the public key
    fn delete_pub_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }

    /// Delete only the private key
    fn delete_priv_key(&mut self, _session: &Session) -> Result<(), AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

pub trait Algo {}

pub(crate) trait EncryptOp {
    fn ciphertext_len(&self, pt_len: usize) -> usize;

    fn encrypt(
        &mut self,
        session: &Session,
        key: KeyId,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError>;
}

pub(crate) trait DecryptOp {
    #[allow(unused)]
    fn plaintext_len(&self, ct_len: usize) -> usize;

    fn decrypt(
        &mut self,
        session: &Session,
        key: KeyId,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError>;
}

#[allow(unused)]
pub(crate) trait SignOp<K: Key> {
    fn signature_len(&self, key: &K) -> Result<u32, AzihsmError>;

    fn sign(
        &self,
        session: &Session,
        priv_key_id: KeyId,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), AzihsmError>;
}

#[allow(unused)]
pub(crate) trait VerifyOp<K: Key> {
    fn verify(&self, key: &K, data: &[u8], signature: &[u8]) -> Result<(), AzihsmError>;
}
/// Digest operations
#[allow(unused)]
pub(crate) trait DigestOp {
    fn digest(
        &mut self,
        session: &Session,
        message: &[u8],
        digest: &mut [u8],
    ) -> Result<(), AzihsmError>;
    /// Get the required digest length for the algorithm
    fn digest_len(&self) -> Result<u32, AzihsmError>;
}
