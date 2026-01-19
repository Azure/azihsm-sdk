// Copyright (C) Microsoft Corporation. All rights reserved.

//! HKDF key derivation operations at the DDI layer.
//!
//! This module constructs and dispatches low-level DDI HKDF requests. It is used by the
//! higher-level HKDF algorithm implementation to derive an HSM-managed symmetric key from an
//! HSM-managed shared secret.

use super::*;

/// Derives a new key using HKDF at the DDI layer.
///
/// This function builds a `DdiHkdfDerive` request using the provided shared secret key handle as
/// input keying material, and the HKDF parameters (`hash_algo`, optional `salt`, optional `info`).
///
/// On success, the returned `HsmKeyProps` contains the masked key material returned by the HSM
/// so the derived key can be re-imported/used by higher layers.
///
/// # Arguments
///
/// * `shared_secret` - Base key (IKM) for HKDF; also provides the session ID and API revision.
/// * `hash_algo` - Hash algorithm used for HKDF extract/expand.
/// * `salt` - Optional HKDF salt. If `None`, HKDF runs with an empty salt.
/// * `info` - Optional HKDF info/context string. If `None`, HKDF runs with an empty info.
/// * `derived_key_props` - Properties of the key to derive (type, size, usage flags, lifetime).
///
/// # Returns
///
/// Returns `(key_handle, updated_props)` where:
/// - `key_handle` is the DDI key identifier for subsequent operations.
/// - `updated_props` is the provided `derived_key_props` with `masked_key` set from the DDI
///   response.
///
/// # Errors
///
/// Returns an error if:
/// - `salt` or `info` cannot be encoded as an MBOR byte array.
/// - The derived key properties cannot be converted to DDI key type/properties.
/// - The underlying DDI HKDF command fails.
pub(crate) fn hkdf_derive(
    shared_secret: &HsmGenericSecretKey,
    hash_algo: HsmHashAlgo,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    mut derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    // Build the DDI HKDF derive key command request.
    let req = DdiHkdfDeriveCmdReq {
        hdr: DdiReqHdr {
            rev: Some(shared_secret.api_rev().into()),
            sess_id: Some(shared_secret.sess_id()),
            op: DdiOp::HkdfDerive,
        },
        data: DdiHkdfDeriveReq {
            key_id: shared_secret.handle(),
            hash_algorithm: hash_algo.into(),
            salt: salt
                .map(|salt| MborByteArray::from_slice(salt).map_hsm_err(HsmError::InternalError))
                .transpose()?,
            info: info
                .map(|info| MborByteArray::from_slice(info).map_hsm_err(HsmError::InternalError))
                .transpose()?,
            key_type: (&derived_key_props).try_into()?,
            key_tag: None,
            key_properties: (&derived_key_props).try_into()?,
        },
        ext: None,
    };
    let resp = shared_secret.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;
    let key_id = resp.data.key_id;
    derived_key_props.set_masked_key(resp.data.masked_key.as_slice());

    Ok((key_id, derived_key_props))
}

impl TryFrom<&HsmKeyProps> for DdiKeyType {
    type Error = HsmError;

    /// Converts derived key properties into the DDI key type.
    ///
    /// HKDF requires specifying the concrete output key type at the DDI layer.
    /// For AES keys, this is derived from `key_props.bits()`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if:
    /// - The key kind is not supported by HKDF in this layer.
    /// - The requested key size is invalid for the supported kind.
    fn try_from(key_props: &HsmKeyProps) -> Result<Self, Self::Error> {
        match key_props.kind() {
            // Supported AES key sizes
            HsmKeyKind::Aes => match key_props.bits() {
                128 => Ok(DdiKeyType::Aes128),
                192 => Ok(DdiKeyType::Aes192),
                256 => Ok(DdiKeyType::Aes256),
                _ => Err(HsmError::InvalidArgument),
            },
            //HMAC key types supported by HKDF
            HsmKeyKind::HmacSha256 => Ok(DdiKeyType::HmacSha256),
            HsmKeyKind::HmacSha384 => Ok(DdiKeyType::HmacSha384),
            HsmKeyKind::HmacSha512 => Ok(DdiKeyType::HmacSha512),
            // All other key kinds are unsupported
            _ => Err(HsmError::InvalidArgument),
        }
    }
}
