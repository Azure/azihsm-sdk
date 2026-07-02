// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! KBKDF (NIST SP 800-108 Counter Mode) key derivation operations at the DDI layer.
//!
//! This module constructs and dispatches low-level DDI KBKDF requests. It is used by the
//! higher-level KBKDF algorithm implementation to derive an HSM-managed symmetric key from an
//! HSM-managed shared secret using the SP 800-108 Counter Mode KDF with an HMAC PRF.

use resiliency_macro::resiliency_key_op;

use super::*;

/// Derives a new key using KBKDF (SP 800-108 Counter Mode) at the DDI layer.
///
/// This function builds a `DdiKbkdfCounterHmacDerive` request using the provided shared secret
/// key handle as input keying material, and the KBKDF parameters (`hash_algo`, optional `label`,
/// optional `context`).
///
/// On success, the returned `HsmKeyProps` contains the masked key material returned by the HSM
/// so the derived key can be re-imported/used by higher layers.
///
/// # Arguments
///
/// * `shared_secret` - Base key (IKM) for KBKDF; also provides the session ID and API revision.
/// * `hash_algo` - Hash algorithm used by the HMAC PRF.
/// * `label` - Optional KBKDF label. If `None`, the label input is omitted.
/// * `context` - Optional KBKDF context string. If `None`, the context input is omitted.
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
/// - `label` or `context` cannot be encoded as an MBOR byte array.
/// - The derived key properties cannot be converted to DDI key type/properties.
/// - The underlying DDI KBKDF command fails.
///
/// Note: the underlying PRF requires at least one of `label` / `context` to be present; deriving
/// with both absent is rejected by the device.
#[resiliency_key_op(key = "shared_secret")]
pub(crate) fn kbkdf_derive(
    shared_secret: &HsmGenericSecretKey,
    hash_algo: HsmHashAlgo,
    label: Option<&[u8]>,
    context: Option<&[u8]>,
    derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    // Build the DDI KBKDF counter-mode derive key command request.
    let req = DdiKbkdfCounterHmacDeriveCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::KbkdfCounterHmacDerive, &shared_secret.session()),
        data: DdiKbkdfCounterHmacDeriveReq {
            key_id: ddi::get_key_id(shared_secret.handle()),
            hash_algorithm: hash_algo.into(),
            label: label
                .map(|label| MborByteArray::from_slice(label).map_hsm_err(HsmError::InternalError))
                .transpose()?,
            context: context
                .map(|ctx| MborByteArray::from_slice(ctx).map_hsm_err(HsmError::InternalError))
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
