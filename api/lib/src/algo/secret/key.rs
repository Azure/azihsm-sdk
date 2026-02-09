// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generic secret key types.
//!
//! This module provides a generic secret key wrapper that represents key material stored in the
//! HSM but not tied to a specific algorithm type at the N-API layer.
//!
//! The primary use case is derived secrets (for example, an ECDH shared secret). The returned
//! value is still an HSM-managed key handle with associated properties; callers should set
//! appropriate usage flags and lifetimes via `HsmKeyProps` when creating/deriving the secret.

// Re-export shared algo/key types from the parent module.
pub use super::*;

// A generic secret key stored in the HSM.
//
// This type typically represents the output of key-derivation operations that yield raw secret
// material (e.g., ECDH). It intentionally does not encode an algorithm-specific key kind.
define_hsm_key!(pub HsmGenericSecretKey);

impl HsmGenericSecretKey {
    /// Returns whether `props.kind()` is a supported generic-secret kind and whether its
    /// usage flags are valid for that kind.
    ///
    /// Supported kinds in this layer:
    /// - [`HsmKeyKind::SharedSecret`] (allowed flags: `DERIVE`)
    /// - [`HsmKeyKind::Aes`] (allowed flags: `ENCRYPT | DECRYPT`)
    /// - [`HsmKeyKind::HmacSha256`]/[`HsmKeyKind::HmacSha384`]/[`HsmKeyKind::HmacSha512`]
    ///   (allowed flags: `SIGN | VERIFY`)
    ///
    /// Note: [`HsmKeyProps::check_supported_flags`] permits the global `SESSION` flag in
    /// addition to the per-kind flags listed above.
    fn check_key_kind(props: &HsmKeyProps) -> bool {
        let supported_flag = match props.kind() {
            HsmKeyKind::SharedSecret => HsmKeyFlags::DERIVE,
            HsmKeyKind::Aes => HsmKeyFlags::ENCRYPT | HsmKeyFlags::DECRYPT,
            HsmKeyKind::HmacSha256 | HsmKeyKind::HmacSha384 | HsmKeyKind::HmacSha512 => {
                HsmKeyFlags::SIGN | HsmKeyFlags::VERIFY
            }
            _ => return false,
        };
        props.check_supported_flags(supported_flag)
    }

    /// Validates that these key properties describe a well-formed generic secret key.
    ///
    /// This is used by higher-level operations (e.g. ECDH/HKDF) to fail fast before issuing
    /// DDI calls when the requested key metadata is inconsistent.
    ///
    /// Requirements enforced here:
    /// - `class` must be [`HsmKeyClass::Secret`]
    /// - `kind` must be one of the supported generic-secret kinds (see [`Self::check_key_kind`])
    /// - `ecc_curve` must be `None`
    /// - `bits` must be non-zero
    pub(crate) fn validate_props(props: &HsmKeyProps) -> HsmResult<()> {
        // Kind/class: ensure we're validating a secret key.
        if props.class() != HsmKeyClass::Secret {
            Err(HsmError::InvalidKeyProps)?;
        }

        //check key kind, GenericSecretKey can be of kind SharedSecret, AES or HMAC
        if !Self::check_key_kind(props) {
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

        Ok(())
    }
}

impl HsmDerivationKey for HsmGenericSecretKey {}

impl HsmSecretKey for HsmGenericSecretKey {}

/// Algorithm for unmasking a generic secret key.
#[derive(Default)]
pub struct HsmGenericSecretKeyUnmaskAlgo {}

impl HsmKeyUnmaskOp for HsmGenericSecretKeyUnmaskAlgo {
    type Session = HsmSession;
    type Key = HsmGenericSecretKey;
    type Error = HsmError;

    /// Unmasks a generic secret key using the provided masked key data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to use for the unmasking operation.
    /// * `masked_key` - The masked secret key data.
    ///
    /// # Returns
    ///
    /// Returns the unmasked generic secret key on success.
    fn unmask_key(
        &mut self,
        session: &HsmSession,
        masked_key: &[u8],
    ) -> Result<Self::Key, Self::Error> {
        let (handle, props) = ddi::unmask_key(session, masked_key)?;

        //construct key guard first to ensure handles are released if validation fails
        let key_id = ddi::HsmKeyIdGuard::new(session, handle);

        // Validate key props
        HsmGenericSecretKey::validate_props(&props)?;

        let key = HsmGenericSecretKey::new(session.clone(), props.clone(), key_id.release());

        Ok(key)
    }
}
