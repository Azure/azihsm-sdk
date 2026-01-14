// Copyright (C) Microsoft Corporation. All rights reserved.

//! HKDF (HMAC-based Extract-and-Expand Key Derivation Function) implementation.
//!
//! This module provides an [`HsmKeyDeriveOp`] implementation that derives an HSM-managed
//! symmetric key (currently [`HsmAesKey`]) from an HSM-managed shared secret
//! ([`HsmSharedSecretKey`]) using HKDF.

use super::*;

/// HKDF key-derivation algorithm configuration.
///
/// Instances of `HsmHkdfAlgo` store HKDF parameters (hash algorithm and optional `salt`/`info`)
/// and can be passed to [`HsmKeyManager::derive_key`] to derive a new key.
pub struct HsmHkdfAlgo {
    /// Hash algorithm used by HKDF (e.g. SHA-256).
    hash_algo: HsmHashAlgo,
    /// Optional HKDF salt.
    salt: Option<Vec<u8>>,
    /// Optional HKDF info/context string.
    info: Option<Vec<u8>>,
}

impl HsmHkdfAlgo {
    /// Creates a new HKDF algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - Hash algorithm used for the HKDF extract/expand steps.
    /// * `salt` - Optional salt value. If `None`, HKDF runs with an empty salt.
    /// * `info` - Optional info/context value. If `None`, HKDF runs with an empty info.
    ///
    /// # Errors
    ///
    /// Currently this constructor performs no validation and always returns `Ok`.
    pub fn new(
        hash_algo: HsmHashAlgo,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<Self, HsmError> {
        Ok(Self {
            hash_algo,
            salt: salt.map(|s| s.to_vec()),
            info: info.map(|i| i.to_vec()),
        })
    }
}

impl HsmKeyDeriveOp for HsmHkdfAlgo {
    /// Session type for this operation.
    type Session = HsmSession;

    /// The type of base key used by this operation.
    type BaseKey = HsmSharedSecretKey;

    /// The type of derived key produced by this operation.
    type DerivedKey = HsmAesKey; // Currently only AES keys are supported.

    /// The error type returned by this operation.
    type Error = HsmError;

    /// Derives key material using HKDF.
    ///
    /// This runs HKDF using `hash_algo` and the optional `salt`/`info` values configured on this
    /// algorithm instance. The input keying material is provided by `base_key`.
    ///
    /// # Arguments
    ///
    /// * `session` - Active session used to associate the returned derived key.
    /// * `base_key` - Input keying material for HKDF.
    /// * `props` - Properties for the derived key (usage flags, lifetime, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying DDI HKDF operation fails or if the provided properties
    /// are invalid/unsupported.
    fn derive_key(
        &mut self,
        session: &Self::Session,
        base_key: &Self::BaseKey,
        props: HsmKeyProps,
    ) -> Result<Self::DerivedKey, Self::Error> {
        let (handle, props) = ddi::hkdf_derive(
            base_key,
            self.hash_algo,
            self.salt.as_deref(),
            self.info.as_deref(),
            props,
        )?;
        Ok(HsmAesKey::new(session.clone(), props, handle))
    }
}
