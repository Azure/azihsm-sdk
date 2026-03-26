// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use resiliency_macro::*;

use super::*;

/// Retrieves an RSA unwrapping key pair from the HSM.
///
/// Wraps [`get_rsa_unwrapping_key_raw_no_res`] with `#[resiliency_key_gen]` for
/// use in the normal (non-Phase-3) path.
///
/// # Arguments
///
/// * `session` - The HSM session to use for key retrieval.
/// * `priv_key_props` - Expected private key properties for validation.
/// * `pub_key_props` - Expected public key properties for validation.
///
/// # Returns
///
/// Returns a tuple containing the key handle, private key properties, and public key properties.
#[resiliency_key_gen(session = "session")]
pub(crate) fn get_rsa_unwrapping_key(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    get_rsa_unwrapping_key_raw_no_res(session, priv_key_props, pub_key_props)
}

/// Raw RSA unwrapping key retrieval — no resiliency retry.
///
/// For use under the barrier write lock (Phase 3 key restoration) or
/// by the macro-wrapped [`get_rsa_unwrapping_key`].
///
/// On failure after a successful DDI call, the newly created key is
/// cleaned up via [`HsmKeyIdGuard`].
pub(crate) fn get_rsa_unwrapping_key_raw_no_res(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::GetUnwrappingKey, session),
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };

    let resp = session.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))?;

    let handle = to_key_handle(resp.data.key_id, None);
    let guard = HsmKeyIdGuard::new(session, handle);

    let masked_key = resp.data.masked_key.as_slice();
    let pub_key = resp.data.pub_key;
    let (dev_priv_key_props, dev_pub_key_props) =
        HsmMaskedKey::to_key_pair_props(masked_key, pub_key.der.as_slice())?;

    if !priv_key_props.validate_dev_props(&dev_priv_key_props)
        || !pub_key_props.validate_dev_props(&dev_pub_key_props)
    {
        return Err(HsmError::InvalidKeyProps);
    }

    Ok((guard.release(), dev_priv_key_props, dev_pub_key_props))
}

/// Performs RSA AES key unwrapping using the specified RSA private key.
///
/// # Arguments
///
/// * `key` - The RSA private key to use for unwrapping.
/// * `wrapped_key` - The wrapped AES key data.
/// * `key_props` - Properties for the unwrapped AES key.
///
/// # Returns
///
/// Returns a tuple containing the key handle and properties of the unwrapped AES key.
/// Wraps [`rsa_aes_unwrap_key_raw_no_res`] with `#[resiliency_key_op]` for
/// use in the normal (non-nested) path.
#[resiliency_key_op(key = "key")]
pub(crate) fn rsa_aes_unwrap_key(
    key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    rsa_aes_unwrap_key_raw_no_res(key, wrapped_key, hash_algo, key_props)
}

/// Raw RSA AES key unwrap — no resiliency retry.
///
/// For use under the barrier lock or by callers already inside a
/// resiliency retry loop (e.g. [`aes_xts_unwrap_key`] which has its
/// own `#[resiliency_key_op]`). On failure after a successful DDI
/// call, the handle is cleaned up via [`HsmKeyIdGuard`].
pub(crate) fn rsa_aes_unwrap_key_raw_no_res(
    key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::RsaUnwrap, &key.session()),
        data: DdiRsaUnwrapReq {
            key_id: ddi::get_key_id(key.handle()),
            wrapped_blob_key_class: key_props.kind().try_into()?,
            wrapped_blob_padding: DdiRsaCryptoPadding::Oaep,
            wrapped_blob_hash_algorithm: hash_algo.into(),
            wrapped_blob: MborByteArray::from_slice(wrapped_key)
                .map_hsm_err(HsmError::InternalError)?,
            key_tag: None,
            key_properties: (&key_props).try_into()?,
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))?;

    let handle = ddi::to_key_handle(resp.data.key_id, resp.data.bulk_key_id);
    let session = key.session();
    let guard = HsmKeyIdGuard::new(&session, handle);

    let masked_key = resp.data.masked_key.as_slice();
    let dev_key_props = HsmMaskedKey::to_key_props(masked_key)?;

    if !key_props.validate_dev_props(&dev_key_props) {
        return Err(HsmError::InvalidKeyProps);
    }

    Ok((guard.release(), dev_key_props))
}

/// Performs RSA AES key pair unwrapping using the specified RSA private key.
///
/// # Arguments
///
/// * `unwrapping_key` - The RSA private key used to unwrap the key pair.
/// * `wrapped_key` - The wrapped key pair data.
/// * `priv_key_props` - Properties for the unwrapped private key.
/// * `pub_key_props` - Properties for the unwrapped public key.
///
/// # Returns
///
/// Returns a tuple containing the key handle, private key properties, and public key properties.
#[resiliency_key_op(key = "unwrapping_key")]
pub(crate) fn rsa_aes_unwrap_key_pair(
    unwrapping_key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::RsaUnwrap, &unwrapping_key.session()),
        data: DdiRsaUnwrapReq {
            key_id: ddi::get_key_id(unwrapping_key.handle()),
            wrapped_blob_key_class: priv_key_props.kind().try_into()?,
            wrapped_blob_padding: DdiRsaCryptoPadding::Oaep,
            wrapped_blob_hash_algorithm: hash_algo.into(),
            wrapped_blob: MborByteArray::from_slice(wrapped_key)
                .map_hsm_err(HsmError::InternalError)?,
            key_tag: None,
            key_properties: (&priv_key_props).try_into()?,
        },
        ext: None,
    };

    let resp =
        unwrapping_key.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))?;

    let key_handle = resp.data.key_id;

    let session = unwrapping_key.session();

    //guard to delete key if error occurs before disarming
    let key_id = HsmKeyIdGuard::new(&session, to_key_handle(key_handle, None));

    let Some(pub_key) = resp.data.pub_key else {
        return Err(HsmError::InternalError);
    };
    let masked_key = resp.data.masked_key.as_slice();
    let (dev_priv_key_props, dev_pub_key_props) =
        HsmMaskedKey::to_key_pair_props(masked_key, pub_key.der.as_slice())?;

    //check key properties before returning
    if !priv_key_props.validate_dev_props(&dev_priv_key_props)
        || !pub_key_props.validate_dev_props(&dev_pub_key_props)
    {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((key_id.release(), dev_priv_key_props, dev_pub_key_props))
}

/// Performs RSA encryption using the specified RSA public key.
///
/// # Arguments
///
/// * `key` - The RSA public key to use for encryption.
/// * `input` - The data to encrypt.
/// * `output` - Optional output buffer. If `None`, returns the required ciphertext
///   size. If provided, must be large enough to hold the ciphertext.
///
/// # Returns
///
/// Returns the number of bytes written to the output buffer, or the required
/// buffer size if `output` is `None`.
#[resiliency_key_op(key = "key")]
pub(crate) fn rsa_decrypt(
    key: &HsmRsaPrivateKey,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    rsa_mod_exp(key, DdiRsaOpType::Decrypt, input, output)
}

/// Performs RSA signing using the specified RSA private key.
///
/// # Arguments
///
/// * `key` - The RSA private key to use for signing.
/// * `data` - The data to sign.
/// * `signature` - The buffer to receive the signature.
///
/// # Returns
///
/// Returns the number of bytes written to the signature buffer.
#[resiliency_key_op(key = "key")]
pub(crate) fn rsa_sign(
    key: &HsmRsaPrivateKey,
    data: &[u8],
    signature: &mut [u8],
) -> HsmResult<usize> {
    rsa_mod_exp(key, DdiRsaOpType::Sign, data, signature)
}

/// Generates a key report (attestation) for the specified RSA private key.
///
/// This is a typed wrapper around [`generate_key_report`] that enables the
/// `#[resiliency_key_op]` proc macro to automatically handle partition restore,
/// session reopen, and key refresh on retryable errors.
///
/// # Arguments
///
/// * `key` - The RSA private key to attest.
/// * `report_data` - Custom data to include in the attestation report.
/// * `report` - Optional mutable buffer to receive the attestation report.
///
/// # Returns
///
/// Returns the size of the attestation report on success.
#[resiliency_key_op(key = "key")]
pub(crate) fn rsa_generate_key_report(
    key: &HsmRsaPrivateKey,
    report_data: &[u8],
    report: Option<&mut [u8]>,
) -> HsmResult<usize> {
    generate_key_report(&key.session(), key.handle(), report_data, report)
}

/// Performs an RSA modular exponentiation operation.
///
/// # Arguments
///
/// * `key` - The RSA private key to use for the operation.
/// * `op` - The type of RSA operation to perform (e.g., Decrypt, Sign).
/// * `input` - The input data for the operation.
/// * `output` - Optional output buffer. If `None`, returns the required output size.
///
/// # Returns
///
/// Returns the number of bytes written to the output buffer, or the required
/// buffer size if `output` is `None`.
fn rsa_mod_exp(
    key: &HsmRsaPrivateKey,
    op: DdiRsaOpType,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    let req = DdiRsaModExpCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::RsaModExp, &key.session()),
        data: DdiRsaModExpReq {
            key_id: get_key_id(key.handle()),
            op_type: op,
            y: MborByteArray::from_slice(input).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| dev.exec_op(&req, &mut None).map_err(HsmError::from))?;

    output.copy_from_slice(resp.data.x.as_slice());

    Ok(resp.data.x.len())
}

impl TryFrom<HsmKeyKind> for DdiKeyClass {
    type Error = HsmError;

    /// Converts an HSM key kind to a DDI key class.
    fn try_from(kind: HsmKeyKind) -> Result<Self, Self::Error> {
        match kind {
            HsmKeyKind::Aes => Ok(DdiKeyClass::Aes),
            HsmKeyKind::AesGcm => Ok(DdiKeyClass::AesGcmBulkUnapproved),
            HsmKeyKind::AesXts => Ok(DdiKeyClass::AesXtsBulk),
            HsmKeyKind::Rsa => Ok(DdiKeyClass::Rsa),
            HsmKeyKind::Ecc => Ok(DdiKeyClass::Ecc),
            _ => Err(HsmError::UnsupportedKeyKind),
        }
    }
}
