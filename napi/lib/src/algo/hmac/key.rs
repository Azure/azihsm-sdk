// Copyright (C) Microsoft Corporation. All rights reserved.

//! HMAC key wrapper.
//!
//! This module defines [`HsmHmacKey`], an HSM-managed key handle used with HMAC
//! signing and verification operations.
//!
//! The key material is not exposed to the caller; operations are performed by
//! delegating to the device via DDI.

use super::*;

// HSM-backed HMAC key.
//
// This is a lightweight cloneable handle to a key stored in the HSM.
// It is used by HsmHmacAlgo for sign/verify operations.
//
// Note: output length is determined by the key's properties in this layer
// (see HsmKeyCommonProps::size).
define_hsm_key!(pub HsmHmacKey);

// Marker trait implementations.
//
// These are intentionally empty: they advertise the capabilities of `HsmHmacKey`
// to the generic operation traits (sign/verify) without exposing any key material.
impl HsmSecretKey for HsmHmacKey {}

// `HsmHmacKey` can be used to produce HMAC tags.
impl HsmSigningKey for HsmHmacKey {}

// `HsmHmacKey` can be used to verify HMAC tags by recomputing and comparing.
impl HsmVerificationKey for HsmHmacKey {}

/// Converts a generic secret-key handle into a typed HMAC key wrapper.
///
/// This conversion does not copy or expose key material. It simply re-wraps the
/// existing shared key state (handle + properties) after validating that the
/// underlying key is a secret HMAC key of a supported digest size.
impl TryFrom<HsmGenericSecretKey> for HsmHmacKey {
    type Error = HsmError;

    fn try_from(key: HsmGenericSecretKey) -> Result<Self, Self::Error> {
        // Validate both the key kind and class.
        //
        // NOTE: `HsmGenericSecretKey` is a broad wrapper; this ensures callers
        // can't accidentally pass (for example) an AES key or a non-secret key
        // into HMAC operations.
        if (key.kind() != HsmKeyKind::HmacSha256
            && key.kind() != HsmKeyKind::HmacSha384
            && key.kind() != HsmKeyKind::HmacSha512)
            || key.class() != HsmKeyClass::Secret
        {
            Err(HsmError::InvalidKey)?;
        }

        // Re-wrap the existing inner key state so typed wrappers share the same
        // underlying handle + drop semantics.
        Ok(HsmHmacKey::from_inner(key.inner()))
    }
}
