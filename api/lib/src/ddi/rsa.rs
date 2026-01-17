// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// Retrieves an RSA unwrapping key pair from the HSM.
///
/// # Arguments
///
/// * `session` - The HSM session to use for key retrieval.
/// * `priv_key_props` - Properties for the private key to be retrieved.
/// * `pub_key_props` - Properties for the public key to be retrieved.
///
/// # Returns
///
/// Returns a tuple containing the key handle, private key properties, and public key properties.
pub(crate) fn get_rsa_unwrapping_key(
    session: &HsmSession,
    mut priv_key_props: HsmKeyProps,
    mut pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            rev: Some(session.api_rev().into()),
            sess_id: Some(session.id()),
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };

    let resp = session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let handle = resp.data.key_id;
    priv_key_props.set_masked_key(resp.data.masked_key.as_slice());
    priv_key_props.set_pub_key_der(resp.data.pub_key.der.as_slice());
    pub_key_props.set_pub_key_der(resp.data.pub_key.der.as_slice());

    Ok((handle, priv_key_props, pub_key_props))
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
pub(crate) fn rsa_aes_unwrap_key(
    key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    mut key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            rev: Some(key.api_rev().into()),
            sess_id: Some(key.sess_id()),
        },
        data: DdiRsaUnwrapReq {
            key_id: key.handle(),
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

    let resp = key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let handle = resp.data.key_id;
    key_props.set_masked_key(resp.data.masked_key.as_slice());

    Ok((handle, key_props))
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
pub(crate) fn rsa_aes_unwrap_key_pair(
    unwrapping_key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    mut priv_key_props: HsmKeyProps,
    mut pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::RsaUnwrap,
            rev: Some(unwrapping_key.api_rev().into()),
            sess_id: Some(unwrapping_key.sess_id()),
        },
        data: DdiRsaUnwrapReq {
            key_id: unwrapping_key.handle(),
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

    let resp = unwrapping_key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let key_handle = resp.data.key_id;
    let Some(pub_key) = resp.data.pub_key else {
        return Err(HsmError::InternalError);
    };
    let masked_key = resp.data.masked_key.as_slice();

    priv_key_props.set_masked_key(masked_key);
    priv_key_props.set_pub_key_der(pub_key.der.as_slice());
    pub_key_props.set_pub_key_der(pub_key.der.as_slice());
    Ok((key_handle, priv_key_props, pub_key_props))
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
pub(crate) fn rsa_sign(
    key: &HsmRsaPrivateKey,
    data: &[u8],
    signature: &mut [u8],
) -> HsmResult<usize> {
    rsa_mod_exp(key, DdiRsaOpType::Sign, data, signature)
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
        hdr: DdiReqHdr {
            op: DdiOp::RsaModExp,
            rev: Some(key.api_rev().into()),
            sess_id: Some(key.sess_id()),
        },
        data: DdiRsaModExpReq {
            key_id: key.handle(),
            op_type: op,
            y: MborByteArray::from_slice(input).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    output.copy_from_slice(resp.data.x.as_slice());

    Ok(resp.data.x.len())
}

impl TryFrom<HsmKeyKind> for DdiKeyClass {
    type Error = HsmError;

    /// Converts an HSM key kind to a DDI key class.
    fn try_from(kind: HsmKeyKind) -> Result<Self, Self::Error> {
        match kind {
            HsmKeyKind::Aes => Ok(DdiKeyClass::Aes),
            HsmKeyKind::Rsa => Ok(DdiKeyClass::Rsa),
            HsmKeyKind::Ecc => Ok(DdiKeyClass::Ecc),
            _ => Err(HsmError::UnsupportedKeyKind),
        }
    }
}
