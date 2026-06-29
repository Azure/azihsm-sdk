// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KBKDF (NIST SP 800-108 Counter Mode, HMAC PRF) key derivation implementation.
//!
//! This module provides an [`HsmKeyDeriveOp`] implementation that derives an HSM-managed
//! secret key from an HSM-managed shared secret ([`HsmGenericSecretKey`]) using the
//! SP 800-108 Counter Mode KDF. The result is returned as an [`HsmGenericSecretKey`]; the
//! concrete derived kind (AES or HMAC) is selected by the requested key properties.

use super::*;

/// KBKDF key-derivation algorithm configuration.
///
/// Instances of `HsmKbkdfAlgo` store KBKDF parameters (hash algorithm and optional
/// `label`/`context`) and can be passed to [`HsmKeyManager::derive_key`] to derive a new key.
pub struct HsmKbkdfAlgo {
    /// Hash algorithm used by the KBKDF HMAC PRF (e.g. SHA-256).
    hash_algo: HsmHashAlgo,
    /// Optional KBKDF label.
    label: Option<Vec<u8>>,
    /// Optional KBKDF context string.
    context: Option<Vec<u8>>,
}

impl HsmKbkdfAlgo {
    /// Creates a new KBKDF algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - Hash algorithm used by the KBKDF HMAC PRF.
    /// * `label` - Optional label value. If `None`, the label input is omitted.
    /// * `context` - Optional context value. If `None`, the context input is omitted.
    ///
    /// # Errors
    ///
    /// Currently this constructor performs no validation and always returns `Ok`.
    pub fn new(
        hash_algo: HsmHashAlgo,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
    ) -> Result<Self, HsmError> {
        Ok(Self {
            hash_algo,
            label: label.map(|l| l.to_vec()),
            context: context.map(|c| c.to_vec()),
        })
    }
}

impl HsmKeyDeriveOp for HsmKbkdfAlgo {
    /// Session type for this operation.
    type Session = HsmSession;

    /// The type of base key used by this operation.
    type BaseKey = HsmGenericSecretKey;

    /// The type of derived key produced by this operation.
    type DerivedKey = HsmGenericSecretKey;

    /// The error type returned by this operation.
    type Error = HsmError;

    /// Derives key material using KBKDF in Counter Mode (NIST SP 800-108).
    ///
    /// This runs KBKDF using `hash_algo` and the optional `label`/`context` values configured on
    /// this algorithm instance. The input keying material is provided by `base_key`.
    ///
    /// # Arguments
    ///
    /// * `session` - Active session used to associate the returned derived key.
    /// * `base_key` - Input keying material for KBKDF.
    /// * `props` - Properties for the derived key (usage flags, lifetime, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying DDI KBKDF operation fails or if the provided properties
    /// are invalid/unsupported.
    fn derive_key(
        &mut self,
        session: &Self::Session,
        base_key: &Self::BaseKey,
        props: HsmKeyProps,
    ) -> Result<Self::DerivedKey, Self::Error> {
        //check if base key can be used for derivation
        if !base_key.can_derive() {
            Err(HsmError::InvalidKey)?;
        }

        // Validate derived key properties early so callers get consistent failures
        // for unsupported key metadata (instead of leaking DDI-specific errors).
        HsmGenericSecretKey::validate_props(&props)?;

        let (handle, props) = ddi::kbkdf_derive(
            base_key,
            self.hash_algo,
            self.label.as_deref(),
            self.context.as_deref(),
            props,
        )?;
        Ok(Self::DerivedKey::new(session.clone(), props, handle))
    }
}
