// Copyright (C) Microsoft Corporation. All rights reserved.

use engine_common::handle_table::Handle;
use engine_common::handle_table::HandleTable;
use enum_as_inner::EnumAsInner;
use lazy_static::lazy_static;
use openssl_rust::safeapi::error::*;

use crate::ciphers::key::AesKey;
use crate::common::secret_key::SecretKey;

#[derive(Clone, EnumAsInner, Debug)]
pub enum Key {
    Aes(AesKey),
    Secret(SecretKey),
}

pub struct EngineKeyTable(HandleTable<Key>);

impl EngineKeyTable {
    pub fn insert_key(&self, key: Key) -> Handle {
        match key {
            Key::Aes(aes_key) => self.0.insert(Key::Aes(aes_key)),
            Key::Secret(ecdh_key) => self.0.insert(Key::Secret(ecdh_key)),
        }
    }

    pub fn get_aes_key(&self, handle: usize) -> OpenSSLResult<AesKey> {
        if let Some(key) = self.0.get(handle) {
            key.into_aes()
                .map_err(|_| OpenSSLError::InvalidKeyHandle(handle))
        } else {
            Err(OpenSSLError::InvalidKeyHandle(handle))
        }
    }

    pub fn get_secret_key(&self, handle: usize) -> OpenSSLResult<SecretKey> {
        if let Some(key) = self.0.get(handle) {
            key.into_secret()
                .map_err(|_| OpenSSLError::InvalidKeyHandle(handle))
        } else {
            Err(OpenSSLError::InvalidKeyHandle(handle))
        }
    }

    pub fn remove_aes_key(&self, handle: usize) -> OpenSSLResult<AesKey> {
        if let Some(key) = self.0.remove(handle) {
            key.into_aes()
                .map_err(|_| OpenSSLError::InvalidKeyHandle(handle))
        } else {
            Err(OpenSSLError::InvalidKeyHandle(handle))
        }
    }

    pub fn remove_secret_key(&self, handle: usize) -> OpenSSLResult<SecretKey> {
        if let Some(key) = self.0.remove(handle) {
            key.into_secret()
                .map_err(|_| OpenSSLError::InvalidKeyHandle(handle))
        } else {
            Err(OpenSSLError::InvalidKeyHandle(handle))
        }
    }

    pub fn delete_keys(&self) {
        let keys = self.0.handles();

        for key in keys.iter() {
            _ = self.0.remove(*key);
        }
    }
}

lazy_static! {
    pub(crate) static ref ENGINE_KEY_HANDLE_TABLE: EngineKeyTable =
        EngineKeyTable(HandleTable::default());
}
