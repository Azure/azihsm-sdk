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

impl TryFrom<HsmGenericSecretKey> for HsmHmacKey {
    type Error = HsmError;

    fn try_from(gs_key: HsmGenericSecretKey) -> Result<Self, Self::Error> {
        // ensure the generic secret key is actually an HMAC key
        if gs_key.kind() != HsmKeyKind::HmacSha256
            && gs_key.kind() != HsmKeyKind::HmacSha384
            && gs_key.kind() != HsmKeyKind::HmacSha512
        {
            Err(HsmError::InvalidKey)?;
        }

        // construct HsmHmacKey from the generic secret key's properties
        Ok(HsmHmacKey::new(
            gs_key.session(),
            gs_key.props(),
            gs_key.handle(),
        ))
    }
}
