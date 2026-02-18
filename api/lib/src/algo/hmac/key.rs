// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

impl HsmHmacKey {
    /// Validates that these key properties describe a well-formed HMAC key.
    ///
    /// This helper is used to fail fast (before DDI calls) when the provided metadata is
    /// inconsistent with what the HMAC implementation supports.
    ///
    /// Requirements enforced here:
    /// - `class` must be [`HsmKeyClass::Secret`]
    /// - `kind` must be one of [`HsmKeyKind::HmacSha256`], [`HsmKeyKind::HmacSha384`],
    ///   or [`HsmKeyKind::HmacSha512`]
    /// - `ecc_curve` must be `None`
    /// - `bits` must be non-zero
    /// - usage flags must be limited to `SIGN | VERIFY` (and the global `SESSION` flag
    ///   permitted by [`HsmKeyProps::check_supported_flags`])
    pub fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        let supported_flags = HsmKeyFlags::SIGN | HsmKeyFlags::VERIFY;

        // Kind/class: ensure we're validating a secret HMAC key.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check key kind
        if props.kind() != HsmKeyKind::HmacSha256
            && props.kind() != HsmKeyKind::HmacSha384
            && props.kind() != HsmKeyKind::HmacSha512
        {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check key size matches kind
        let expected_bits = match props.kind() {
            HsmKeyKind::HmacSha256 => 256,
            HsmKeyKind::HmacSha384 => 384,
            HsmKeyKind::HmacSha512 => 512,
            _ => unreachable!(),
        };
        if props.bits() != expected_bits {
            Err(HsmError::InvalidKeyProps)?;
        }

        // Secret keys in this layer should not have an associated ECC curve.
        if props.ecc_curve().is_some() {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check if key size is non-zero
        if props.bits() == 0 {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check if only supported flags are set
        if !props.check_supported_flags(supported_flags) {
            Err(HsmError::InvalidKeyProps)?;
        }

        Ok(())
    }
}

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
        // Validate that the generic secret key is suitable for HMAC operations.
        HsmHmacKey::validate_props(&key.props())?;

        // Re-wrap the existing inner key state so typed wrappers share the same
        // underlying handle + drop semantics.
        Ok(HsmHmacKey::from_inner(key.inner()))
    }
}

/// Algorithm for unmasking an HMAC key.
#[derive(Default)]
pub struct HsmHmacKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmHmacKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmHmacKey;
    type Error = HsmError;

    /// Unmasks an HMAC key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked HMAC key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked HMAC key on success.
    fn unmask_key(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;

        //construct key guard first to ensure handles are released if validation fails
        let key_id = ddi::HsmKeyIdGuard::new(session, handle);

        //validate key props
        HsmHmacKey::validate_props(&props)?;

        let key = HsmHmacKey::new(session.clone(), props, key_id.release());
        Ok(key)
    }
}
