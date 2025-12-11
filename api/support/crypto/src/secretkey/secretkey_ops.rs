// Copyright (C) Microsoft Corporation. All rights reserved.
#![warn(missing_docs)]

use super::*;

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
            .field("kdk", &format!("[REDACTED {} bytes]", self.kdk.len()))
            .finish()
    }
}

impl SecretKeyOps for SecretKey {
    /// Creates a SecretKey from a slice of bytes.
    ///
    /// # Parameters
    /// - `key`: The key material as a byte slice.
    ///
    /// # Returns
    /// - `Ok(SecretKey)`: The constructed SecretKey instance.
    /// - `Err(CryptoError)`: If construction fails (e.g., key is empty).
    fn from_slice(key: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized,
    {
        if key.is_empty() {
            tracing::error!("Cannot create SecretKey: supplied key is empty");
            return Err(CryptoError::SecretCreationFailed);
        }
        Ok(SecretKey { kdk: key.to_vec() })
    }
}
