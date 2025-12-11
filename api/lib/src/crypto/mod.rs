// Copyright (C) Microsoft Corporation. All rights reserved.

pub mod aes;
pub mod ec;
pub mod ecdh;
pub mod hkdf;
pub mod hmac;
pub mod rsa;
pub mod sha;
pub mod utils;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use parking_lot::RwLock;

use crate::bindings::AzihsmError;
use crate::types::key_props::KeyProps;
use crate::types::AlgoId;
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

pub(crate) trait KeyWrapOp<A: Algo> {
    fn wrap(
        &self,
        _session: &Session,
        _algo: &A,
        _user_data: &[u8],
        _wrapped_data: &mut [u8],
    ) -> Result<usize, AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }

    fn wrap_len(&self, _algo: &A, _user_data_len: usize) -> Result<usize, AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }
}

pub(crate) trait KeyUnwrapOp<A: Algo> {
    fn unwrap(
        &self,
        _session: &Session,
        _algo: &A,
        _wrapped_key: &[u8],
        _unwrapped_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError> {
        Err(AZIHSM_OPERATION_NOT_SUPPORTED)
    }

    fn unwrap_max_len(&self, _hash_algo_id: AlgoId) -> Result<usize, AzihsmError> {
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

pub(crate) trait EncryptOp<K: Key> {
    fn ciphertext_len(&self, pt_len: usize) -> usize;

    fn encrypt(
        &mut self,
        session: &Session,
        key: &K,
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, AzihsmError>;
}

pub(crate) trait DecryptOp<K: Key> {
    #[allow(unused)]
    fn plaintext_len(&self, ct_len: usize) -> usize;

    fn decrypt(
        &mut self,
        session: &Session,
        key: &K,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, AzihsmError>;
}

pub enum Stage {
    Update,   // For intermediate chunks
    Finalize, // For padding/tag emission
}

/// Trait for streaming encryption operations
#[allow(unused)]
pub trait StreamingEncryptOp {
    /// Calculate the required output buffer size for the given input size and stage.
    /// This accounts for data already buffered in the streaming context.
    /// - `Stage::Update`: Returns size needed for update() operation (only complete blocks)
    /// - `Stage::Finalize`: Returns size needed for finalize() operation (includes padding/final block)
    fn required_output_len(&self, input_len: usize, stage: Stage) -> usize;

    /// Update streaming encryption with more data
    fn update(&mut self, pt: &[u8], ct: &mut [u8]) -> Result<usize, AzihsmError>;

    /// Finalize streaming encryption
    fn finalize(self, ct: &mut [u8]) -> Result<usize, AzihsmError>;
}

/// Trait for streaming decryption operations
#[allow(unused)]
pub trait StreamingDecryptOp {
    /// Calculate the required output buffer size for the given input size and stage.
    /// This accounts for data already buffered in the streaming context.
    /// - `Stage::Update`: Returns size needed for update() operation (only complete blocks)
    /// - `Stage::Finalize`: Returns size needed for finalize() operation (includes padding removal)
    fn required_output_len(&self, input_len: usize, stage: Stage) -> usize;

    /// Update streaming decryption with more data
    fn update(&mut self, ct: &[u8], pt: &mut [u8]) -> Result<usize, AzihsmError>;

    /// Finalize streaming decryption
    fn finalize(self, pt: &mut [u8]) -> Result<usize, AzihsmError>;
}

/// Trait for algorithms that support streaming operations
#[allow(unused)]
pub trait StreamingEncDecAlgo<'a, K: Key> {
    type EncryptStream: StreamingEncryptOp;
    type DecryptStream: StreamingDecryptOp;

    /// Create a streaming encryption object
    fn encrypt_init(
        &self,
        session: &'a Session,
        key: &K,
    ) -> Result<Self::EncryptStream, AzihsmError>;

    /// Create a streaming decryption object
    fn decrypt_init(
        &self,
        session: &'a Session,
        key: &K,
    ) -> Result<Self::DecryptStream, AzihsmError>;
}

#[allow(unused)]
pub(crate) trait SignOp<K: Key> {
    fn signature_len(&self, key: &K) -> Result<u32, AzihsmError>;

    fn sign(
        &self,
        session: &Session,
        priv_key: &K,
        data: &[u8],
        signature: &mut [u8],
    ) -> Result<(), AzihsmError>;
}

#[allow(unused)]
pub(crate) trait VerifyOp<K: Key> {
    fn verify(
        &self,
        session: &Session,
        key: &K,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AzihsmError>;
}

/// Trait for algorithms that support streaming sign operations
#[allow(unused)]
pub trait StreamingSignOp {
    /// Calculate the required signature buffer size.
    fn signature_len(&self) -> Result<u32, AzihsmError>;

    /// Update streaming signature with more data
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError>;

    /// Finalize streaming signature operation and produce the signature.
    fn finalize(self, signature: &mut [u8]) -> Result<usize, AzihsmError>;
}

/// Trait for streaming verify operations
#[allow(unused)]
pub trait StreamingVerifyOp {
    /// Update streaming verification with more data
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError>;

    /// Finalize streaming verification operation and verify against the provided signature.
    fn finalize(self, signature: &[u8]) -> Result<(), AzihsmError>;
}

/// Trait for algorithms that support streaming sign/verify operations
#[allow(unused)]
pub trait StreamingSignVerifyAlgo<'a, K: Key> {
    type SignStream: StreamingSignOp;
    type VerifyStream: StreamingVerifyOp;

    /// Create a streaming sign object
    fn sign_init(&self, session: &'a Session, key: &K) -> Result<Self::SignStream, AzihsmError>;

    /// Create a streaming verify object
    fn verify_init(&self, session: &'a Session, key: &K)
        -> Result<Self::VerifyStream, AzihsmError>;
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

#[allow(unused)]
pub trait StreamingDigestOp {
    /// Get the required digest length for the algorithm
    fn digest_len(&self) -> usize;

    /// Update streaming digest with more data
    fn update(&mut self, data: &[u8]) -> Result<(), AzihsmError>;

    /// Finalize streaming digest operation and produce the digest.
    fn finalize(self, digest: &mut [u8]) -> Result<usize, AzihsmError>;
}

#[allow(unused)]
/// Trait for algorithms that support streaming digest operations
pub trait StreamingDigestAlgo<'a> {
    type DigestStream: StreamingDigestOp;

    /// Create a streaming digest object
    fn digest_init(&self, session: &'a Session) -> Result<Self::DigestStream, AzihsmError>;
}

/// Key derive operations
#[allow(unused)]
pub(crate) trait DeriveOp<K: Key> {
    fn key_derive(
        &self,
        sess_handle: &Session,
        base_key: &K,
        derived_key_props: &KeyProps,
    ) -> Result<KeyId, AzihsmError>;
}
