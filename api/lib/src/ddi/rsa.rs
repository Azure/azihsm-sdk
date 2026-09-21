// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA256;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA384;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA512;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use azihsm_ddi_tbor_types::KEY_KIND_RSA2K_PRIVATE;
use azihsm_ddi_tbor_types::KEY_KIND_RSA2K_PRIVATE_CRT;
use azihsm_ddi_tbor_types::KEY_KIND_RSA3K_PRIVATE;
use azihsm_ddi_tbor_types::KEY_KIND_RSA3K_PRIVATE_CRT;
use azihsm_ddi_tbor_types::KEY_KIND_RSA4K_PRIVATE;
use azihsm_ddi_tbor_types::KEY_KIND_RSA4K_PRIVATE_CRT;
use azihsm_ddi_tbor_types::KEY_USAGE_DECRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::KEY_USAGE_VERIFY;
use azihsm_ddi_tbor_types::RSA_OP_DECRYPT;
use azihsm_ddi_tbor_types::RSA_OP_SIGN;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::TborRsaModExpReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyReq;
use crypto::ExportableKey;
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
    if session.is_ex() {
        get_rsa_unwrapping_key_tbor(session, priv_key_props, pub_key_props)
    } else {
        get_rsa_unwrapping_key_raw_no_res(session, priv_key_props, pub_key_props)
    }
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

    let resp = session.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

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
            key_id: ddi::get_key_id(key.handle())?,
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

    let resp = key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

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
    if unwrapping_key.session().is_ex() {
        rsa_aes_unwrap_key_pair_tbor(
            unwrapping_key,
            wrapped_key,
            hash_algo,
            priv_key_props,
            pub_key_props,
        )
    } else {
        rsa_aes_unwrap_key_pair_mbor(
            unwrapping_key,
            wrapped_key,
            hash_algo,
            priv_key_props,
            pub_key_props,
        )
    }
}

fn rsa_aes_unwrap_key_pair_mbor(
    unwrapping_key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    hash_algo: HsmHashAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = DdiRsaUnwrapCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::RsaUnwrap, &unwrapping_key.session()),
        data: DdiRsaUnwrapReq {
            key_id: ddi::get_key_id(unwrapping_key.handle())?,
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
        unwrapping_key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

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

/// Performs RSA decryption using the specified RSA private key.
///
/// # Arguments
///
/// * `key` - The RSA private key to use for decryption.
/// * `input` - The ciphertext to decrypt.
/// * `output` - Buffer that receives the decrypted padded block.
///
/// # Returns
///
/// Returns the number of bytes written to the output buffer.
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
/// * `output` - Buffer that receives the operation result.
///
/// # Returns
///
/// Returns the number of bytes written to the output buffer.
fn rsa_mod_exp(
    key: &HsmRsaPrivateKey,
    op: DdiRsaOpType,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    if key.session().is_ex() {
        rsa_mod_exp_tbor(key, op, input, output)
    } else {
        rsa_mod_exp_mbor(key, op, input, output)
    }
}

fn rsa_mod_exp_mbor(
    key: &HsmRsaPrivateKey,
    op: DdiRsaOpType,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    let req = DdiRsaModExpCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::RsaModExp, &key.session()),
        data: DdiRsaModExpReq {
            key_id: get_key_id(key.handle())?,
            op_type: op,
            y: MborByteArray::from_slice(input).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

    if output.len() < resp.data.x.len() {
        return Err(HsmError::BufferTooSmall);
    }
    output[..resp.data.x.len()].copy_from_slice(resp.data.x.as_slice());

    Ok(resp.data.x.len())
}

fn rsa_mod_exp_tbor(
    key: &HsmRsaPrivateKey,
    op: DdiRsaOpType,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    let op_type = match op {
        DdiRsaOpType::Sign => RSA_OP_SIGN,
        DdiRsaOpType::Decrypt => RSA_OP_DECRYPT,
        _ => return Err(HsmError::InvalidArgument),
    };

    // Host RSA operands are big-endian; the TBOR wire uses little-endian.
    let req = TborRsaModExpReq {
        session_id: key.session().ex_session_id()?,
        masked_key: key.masked_key_vec()?,
        op_type,
        y: input.iter().rev().copied().collect(),
    };
    let mut cookie = None;
    let resp = key.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    if resp.x.len() != key.size() {
        return Err(HsmError::InternalError);
    }
    if output.len() < resp.x.len() {
        return Err(HsmError::BufferTooSmall);
    }
    for (dst, src) in output[..resp.x.len()].iter_mut().zip(resp.x.iter().rev()) {
        *dst = *src;
    }
    Ok(resp.x.len())
}

fn get_rsa_unwrapping_key_tbor(
    session: &HsmSession,
    mut priv_key_props: HsmKeyProps,
    mut pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let req = TborGetUnwrappingKeyReq {
        session_id: session.ex_session_id()?,
    };
    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    let modulus_len =
        usize::try_from(priv_key_props.bits()).map_err(|_| HsmError::InvalidKeyProps)? / 8;
    if resp.pub_key.len() != modulus_len + 4 {
        return Err(HsmError::InvalidKeyProps);
    }
    let crypto_key = hsm_wire_pub_to_crypto(&resp.pub_key)?;
    let pub_key_der = crypto_key.to_vec().map_hsm_err(HsmError::InternalError)?;
    priv_key_props.set_pub_key_der(&pub_key_der);
    pub_key_props.set_pub_key_der(&pub_key_der);
    Ok((HsmKeyHandle::Unpinned, priv_key_props, pub_key_props))
}

fn rsa_aes_unwrap_key_pair_tbor(
    unwrapping_key: &HsmRsaPrivateKey,
    wrapped_key: &[u8],
    oaep_hash: HsmHashAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    if priv_key_props.label().len() > TBOR_KEY_LABEL_MAX_LEN {
        return Err(HsmError::InvalidKeyProps);
    }

    let (key_class, expected_key_kind) = tbor_rsa_key_class_and_kind(&priv_key_props)?;
    let unwrapping_modulus_len = unwrapping_key.size();
    if wrapped_key.len() < unwrapping_modulus_len {
        return Err(HsmError::InvalidArgument);
    }

    // The host wrapper emits the OAEP ciphertext big-endian; TBOR consumes
    // only that leading RSA segment in little-endian order.
    let mut wrapped_blob = wrapped_key.to_vec();
    wrapped_blob[..unwrapping_modulus_len].reverse();

    let req = TborUnwrapKeyReq {
        session_id: unwrapping_key.session().ex_session_id()?,
        scope: priv_key_props.tbor_scope(),
        key_class,
        key_usage: rsa_tbor_key_usage(&priv_key_props)?,
        oaep_hash_algo: oaep_hash_to_tbor(oaep_hash)?,
        wrapped_blob,
        key_label: priv_key_props.label().to_vec(),
    };
    let mut cookie = None;
    let resp = unwrapping_key.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    if resp.key_kind != expected_key_kind {
        return Err(HsmError::InvalidKeyProps);
    }
    let expected_modulus_len =
        usize::try_from(priv_key_props.bits()).map_err(|_| HsmError::InvalidKeyProps)? / 8;
    let modulus_len = resp.pub_key.len().saturating_sub(4);
    if modulus_len != expected_modulus_len {
        return Err(HsmError::InvalidKeyProps);
    }

    let crypto_key = hsm_wire_pub_to_crypto(&resp.pub_key)?;
    let pub_key_der = crypto_key.to_vec().map_hsm_err(HsmError::InternalError)?;
    let (dev_priv_key_props, dev_pub_key_props) =
        HsmMaskedKey::to_key_pair_props(&resp.masked_key, &pub_key_der)?;

    if !priv_key_props.validate_dev_props(&dev_priv_key_props)
        || !pub_key_props.validate_dev_props(&dev_pub_key_props)
    {
        return Err(HsmError::InvalidKeyProps);
    }

    Ok((
        HsmKeyHandle::Unpinned,
        dev_priv_key_props,
        dev_pub_key_props,
    ))
}

fn hsm_wire_pub_to_crypto(wire: &[u8]) -> HsmResult<crypto::RsaPublicKey> {
    if wire.len() <= 4 {
        return Err(HsmError::InternalError);
    }

    let modulus_len = wire.len() - 4;
    let mut big_endian = Vec::with_capacity(wire.len());
    big_endian.extend(wire[..modulus_len].iter().rev());
    big_endian.extend(wire[modulus_len..].iter().rev());
    crypto::RsaPublicKey::from_hsm_bytes(&big_endian).map_hsm_err(HsmError::InternalError)
}

fn rsa_tbor_key_usage(props: &HsmKeyProps) -> HsmResult<u64> {
    if props.can_sign() {
        Ok(KEY_USAGE_SIGN | KEY_USAGE_VERIFY)
    } else if props.can_decrypt() {
        Ok(KEY_USAGE_DECRYPT | KEY_USAGE_ENCRYPT)
    } else {
        Err(HsmError::InvalidKeyProps)
    }
}

fn oaep_hash_to_tbor(algo: HsmHashAlgo) -> HsmResult<u8> {
    match algo {
        HsmHashAlgo::Sha256 => Ok(HASH_ALGO_SHA256),
        HsmHashAlgo::Sha384 => Ok(HASH_ALGO_SHA384),
        HsmHashAlgo::Sha512 => Ok(HASH_ALGO_SHA512),
        _ => Err(HsmError::InvalidArgument),
    }
}

fn tbor_rsa_key_class_and_kind(props: &HsmKeyProps) -> HsmResult<(u8, u8)> {
    match (props.kind(), props.bits()) {
        (HsmKeyKind::Rsa, 2048) => Ok((KEY_CLASS_RSA, KEY_KIND_RSA2K_PRIVATE)),
        (HsmKeyKind::Rsa, 3072) => Ok((KEY_CLASS_RSA, KEY_KIND_RSA3K_PRIVATE)),
        (HsmKeyKind::Rsa, 4096) => Ok((KEY_CLASS_RSA, KEY_KIND_RSA4K_PRIVATE)),
        (HsmKeyKind::RsaCrt, 2048) => Ok((KEY_CLASS_RSA_CRT, KEY_KIND_RSA2K_PRIVATE_CRT)),
        (HsmKeyKind::RsaCrt, 3072) => Ok((KEY_CLASS_RSA_CRT, KEY_KIND_RSA3K_PRIVATE_CRT)),
        (HsmKeyKind::RsaCrt, 4096) => Ok((KEY_CLASS_RSA_CRT, KEY_KIND_RSA4K_PRIVATE_CRT)),
        _ => Err(HsmError::InvalidKeyProps),
    }
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
            HsmKeyKind::RsaCrt => Ok(DdiKeyClass::RsaCrt),
            HsmKeyKind::Ecc => Ok(DdiKeyClass::Ecc),
            _ => Err(HsmError::UnsupportedKeyKind),
        }
    }
}
