// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HKDF key derivation operations at the DDI layer.
//!
//! This module constructs and dispatches low-level DDI HKDF requests. It is used by the
//! higher-level HKDF algorithm implementation to derive an HSM-managed symmetric key from an
//! HSM-managed shared secret.

use azihsm_ddi_tbor_types::HASH_ALGO_SHA256;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA384;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA512;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES128;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES192;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA512;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::TborHkdfDeriveReq;
use resiliency_macro::resiliency_key_op;

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
#[resiliency_key_op(key = "shared_secret")]
pub(crate) fn hkdf_derive(
    shared_secret: &HsmGenericSecretKey,
    hash_algo: HsmHashAlgo,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    // Transport is selected by session type: a V2 (TBOR) session derives
    // from the caller-held masked shared secret; a V1 (MBOR) session from
    // the device-resident secret id.
    if shared_secret.session().is_ex() {
        hkdf_derive_tbor(shared_secret, hash_algo, salt, info, derived_key_props)
    } else {
        hkdf_derive_mbor(shared_secret, hash_algo, salt, info, derived_key_props)
    }
}

/// Derives a key via MBOR `HkdfDerive` using the device-resident shared
/// secret id.
fn hkdf_derive_mbor(
    shared_secret: &HsmGenericSecretKey,
    hash_algo: HsmHashAlgo,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    // Build the DDI HKDF derive key command request.
    let req = DdiHkdfDeriveCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::HkdfDerive, &shared_secret.session()),
        data: DdiHkdfDeriveReq {
            key_id: ddi::get_key_id(shared_secret.handle())?,
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
            key_length: u8::try_from(derived_key_props.bits() / 8).ok(),
        },
        ext: None,
    };
    let resp =
        shared_secret.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

    let session = shared_secret.session();
    let key_id = HsmKeyIdGuard::new(
        &session,
        to_key_handle(resp.data.key_id, resp.data.bulk_key_id),
    );

    let dev_key_props = HsmMaskedKey::to_key_props(resp.data.masked_key.as_slice())?;
    // Validate that the device returned properties match the requested properties.
    if !derived_key_props.validate_dev_props(&dev_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((key_id.release(), dev_key_props))
}

/// Derives a key via TBOR `HkdfDerive` using the caller-held masked ECDH
/// shared secret (unmask-on-use); the derived key is returned non-resident.
fn hkdf_derive_tbor(
    shared_secret: &HsmGenericSecretKey,
    hash_algo: HsmHashAlgo,
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let masked_secret = shared_secret.masked_key_vec()?;
    let key_type = tbor_hkdf_key_type(&derived_key_props)?;
    let key_label = derived_key_props.label();
    if key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        return Err(HsmError::InvalidKeyProps);
    }

    let req = TborHkdfDeriveReq {
        session_id: shared_secret.session().ex_session_id()?,
        scope: derived_key_props.tbor_scope(),
        hash_algo: tbor_hash_algo(hash_algo)?,
        key_type,
        // Fixed canonical AES / HMAC output; the variable-length HMAC
        // `key_length` is unused for these key types.
        key_length: 0,
        masked_secret,
        salt: salt.unwrap_or(&[]).to_vec(),
        info: info.unwrap_or(&[]).to_vec(),
        key_label: key_label.to_vec(),
    };
    let mut cookie = None;
    let resp = shared_secret.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    let dev_key_props = HsmMaskedKey::to_key_props(&resp.masked_key)?;
    // Validate that the device returned properties match the requested properties.
    if !derived_key_props.validate_dev_props(&dev_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((ddi::HsmKeyHandle::Unpinned, dev_key_props))
}

/// Maps the derived-key properties to the TBOR `KdfKeyType` discriminant.
/// HKDF output is a fixed canonical AES or HMAC key, so the request's
/// variable-length `key_length` is unused.
fn tbor_hkdf_key_type(props: &HsmKeyProps) -> HsmResult<u8> {
    match props.kind() {
        HsmKeyKind::Aes => match props.bits() {
            128 => Ok(KDF_KEY_TYPE_AES128),
            192 => Ok(KDF_KEY_TYPE_AES192),
            256 => Ok(KDF_KEY_TYPE_AES256),
            _ => Err(HsmError::InvalidArgument),
        },
        HsmKeyKind::HmacSha256 => Ok(KDF_KEY_TYPE_HMAC_SHA256),
        HsmKeyKind::HmacSha384 => Ok(KDF_KEY_TYPE_HMAC_SHA384),
        HsmKeyKind::HmacSha512 => Ok(KDF_KEY_TYPE_HMAC_SHA512),
        _ => Err(HsmError::InvalidArgument),
    }
}

/// Maps `HsmHashAlgo` to the 1-byte TBOR `HashAlgo` discriminant.
fn tbor_hash_algo(algo: HsmHashAlgo) -> HsmResult<u8> {
    match algo {
        HsmHashAlgo::Sha256 => Ok(HASH_ALGO_SHA256),
        HsmHashAlgo::Sha384 => Ok(HASH_ALGO_SHA384),
        HsmHashAlgo::Sha512 => Ok(HASH_ALGO_SHA512),
        _ => Err(HsmError::InvalidArgument),
    }
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
