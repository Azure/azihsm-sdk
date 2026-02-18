// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC (Elliptic Curve Cryptography) operations through the Device Driver Interface (DDI).
//!
//! This module provides low-level functions for ECC key operations including key pair
//! generation. It serves as a bridge between the HSM session layer and the underlying
//! DDI protocol, handling the translation of HSM key properties to DDI-specific
//! structures and command execution.

use super::*;

/// Generates an ECC key pair in the HSM.
///
/// This function creates a new ECC key pair using the specified curve and key properties.
/// The private key is securely stored within the HSM and identified by a key handle,
/// while the public key is returned in DER-encoded format. Additionally, a masked
/// (encrypted) version of the private key is returned for backup or migration purposes.
///
/// # Arguments
///
/// * `session` - Active HSM session used to execute the key generation operation
/// * `props` - Key properties specifying the ECC curve (P-256, P-384, or P-521) and
///   other attributes like key usage, exportability, and persistence
///
/// # Returns
///
/// Returns a tuple containing:
/// - `HsmKeyHandle` - Unique identifier for the private key within the HSM. Used for
///   subsequent cryptographic operations like signing.
/// - `Vec<u8>` - DER-encoded public key that can be shared with other parties for
///   signature verification or key agreement.
/// - `HsmMaskedKey` - Encrypted (masked) representation of the private key. Can be used
///   for backup, migration, or key wrapping operations while maintaining security.
///
/// # Errors
///
/// Returns an error if:
/// - The ECC curve is not specified in the key properties
/// - The specified curve is not supported by the HSM
/// - Key generation fails in the HSM (insufficient entropy, resource constraints)
/// - The DDI command execution fails
/// - The response from the HSM is malformed or missing required fields
/// - Session credentials are invalid or the session has expired
pub(crate) fn ecc_generate_key(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    let Some(curve) = priv_key_props.ecc_curve() else {
        return Err(HsmError::PropertyNotPresent);
    };

    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::EccGenerateKeyPair, session),
        data: DdiEccGenerateKeyPairReq {
            curve: curve.into(),
            key_tag: None,
            key_properties: (&priv_key_props).try_into()?,
        },
        ext: None,
    };

    let resp = session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;
    let key_handle = HsmKeyHandle {
        key_id: resp.data.private_key_id,
        bulk_key_id: None,
    };
    // Create a key guard to ensure the generated key is deleted if any errors occur before returning.
    let key_handle_guard = HsmKeyHandleGuard::new(session, key_handle);

    let pub_key_der = resp.data.pub_key.der.as_slice();
    let masked_key = resp.data.masked_key.as_slice();
    let (dev_priv_key_props, dev_pub_key_props) =
        HsmMaskedKey::to_key_pair_props(masked_key, pub_key_der)?;

    // Validate that the device returned properties match the requested properties.
    if !priv_key_props.validate_dev_props(&dev_priv_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((
        key_handle_guard.release(),
        dev_priv_key_props,
        dev_pub_key_props,
    ))
}

/// Performs an ECC signature operation using a pre-computed hash.
///
/// This function creates an ECC signature over a provided hash digest using the specified
/// private key. The hash must be pre-computed by the caller - this function does not
/// perform any hashing. It sends the hash to the HSM which performs the signature
/// operation and returns the signature bytes.
///
/// # Arguments
///
/// * `key` - The ECC private key to use for signing. The key must already exist in the
///   HSM and be accessible through the current session.
/// * `hash` - The pre-computed message digest. The caller is responsible for hashing
///   the message with an appropriate hash function for the key's curve (SHA-256 for
///   P-256, SHA-384 for P-384, SHA-512 for P-521).
/// * `sig` - Output buffer to receive the signature bytes. Must be large enough to hold
///   the signature for the key's curve.
///
/// # Returns
///
/// Returns the number of bytes written to the signature buffer. The signature size
/// depends on the curve:
/// - P-256: 64 bytes
/// - P-384: 96 bytes
/// - P-521: 132 bytes
///
/// # Errors
///
/// Returns an error if:
/// - The signature buffer is too small for the curve's signature size
/// - The key handle is invalid or the key does not exist in the HSM
/// - The session credentials are invalid or expired
/// - The hash encoding to MBOR format fails
/// - The DDI command execution fails
/// - The HSM signature operation fails
pub(crate) fn ecc_sign(
    key: &HsmEccPrivateKey,
    hash: &[u8],
    hash_algo: HsmHashAlgo,
    sig: &mut [u8],
) -> HsmResult<usize> {
    let Some(curve) = key.ecc_curve() else {
        return Err(HsmError::PropertyNotPresent);
    };
    let req = DdiEccSignCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::EccSign, &key.session()),
        data: DdiEccSignReq {
            key_id: key.handle().key_id,
            digest: MborByteArray::from_slice(hash).map_hsm_err(HsmError::InternalError)?,
            digest_algo: hash_algo.into(),
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let sig_len = curve.signature_size();
    sig[..sig_len].copy_from_slice(&resp.data.signature.as_slice()[..sig_len]);

    Ok(sig_len)
}

/// Performs ECDH key agreement and creates a derived secret key in the HSM.
///
/// This is a low-level DDI wrapper that executes the `EcdhKeyExchange` operation using an
/// existing ECC private key (`base_key`) and a peer public key provided as DER bytes.
///
/// # Arguments
///
/// * `base_key` - The local ECC private key used as the ECDH base key.
/// * `peer_pub_der` - DER-encoded peer public key.
/// * `derived_key_props` - Properties for the derived key to be created in the HSM.
///
/// # Returns
///
/// Returns a tuple containing:
/// - `HsmKeyHandle` - Handle of the newly created derived key.
/// - `HsmKeyProps` - Properties for the derived key, updated with masked key material.
///
/// # Errors
///
/// Returns an error if:
/// - The base key is missing the ECC curve property.
/// - The peer public key DER cannot be encoded for the DDI request.
/// - The provided `derived_key_props` cannot be translated to DDI target key properties.
/// - The DDI command execution fails.
pub(crate) fn ecdh_derive(
    base_key: &HsmEccPrivateKey,
    peer_pub_der: &[u8],
    derived_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let Some(curve) = base_key.ecc_curve() else {
        return Err(HsmError::PropertyNotPresent);
    };
    // Build the DDI ECDH derive key command request.
    let req = DdiEcdhKeyExchangeCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::EcdhKeyExchange, &base_key.session()),
        data: DdiEcdhKeyExchangeReq {
            priv_key_id: base_key.handle().key_id,
            pub_key_der: MborByteArray::from_slice(peer_pub_der)
                .map_hsm_err(HsmError::InternalError)?,
            key_tag: None,
            key_type: curve.into(),
            key_properties: (&derived_key_props).try_into()?,
        },
        ext: None,
    };

    let resp = base_key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let session = base_key.session();
    let key_handle = HsmKeyHandle {
        key_id: resp.data.key_id,
        bulk_key_id: None,
    };
    let key_handle_guard = HsmKeyHandleGuard::new(&session, key_handle);
    let dev_key_props = HsmMaskedKey::to_key_props(resp.data.masked_key.as_slice())?;
    // Validate that the device returned properties match the requested properties.
    if !derived_key_props.validate_dev_props(&dev_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((key_handle_guard.release(), dev_key_props))
}

impl From<HsmEccCurve> for DdiEccCurve {
    /// Converts HSM key properties to a DDI ECC curve identifier.
    fn from(curve: HsmEccCurve) -> DdiEccCurve {
        match curve {
            HsmEccCurve::P256 => DdiEccCurve::P256,
            HsmEccCurve::P384 => DdiEccCurve::P384,
            HsmEccCurve::P521 => DdiEccCurve::P521,
        }
    }
}

impl From<HsmHashAlgo> for DdiHashAlgorithm {
    /// Converts HSM ECC curve to corresponding DDI hash algorithm.
    fn from(hash_algo: HsmHashAlgo) -> DdiHashAlgorithm {
        match hash_algo {
            HsmHashAlgo::Sha1 => DdiHashAlgorithm::Sha1,
            HsmHashAlgo::Sha256 => DdiHashAlgorithm::Sha256,
            HsmHashAlgo::Sha384 => DdiHashAlgorithm::Sha384,
            HsmHashAlgo::Sha512 => DdiHashAlgorithm::Sha512,
        }
    }
}

///Implement ECC Curve to Ddi Key Type
impl From<HsmEccCurve> for DdiKeyType {
    fn from(curve: HsmEccCurve) -> DdiKeyType {
        match curve {
            HsmEccCurve::P256 => DdiKeyType::Secret256,
            HsmEccCurve::P384 => DdiKeyType::Secret384,
            HsmEccCurve::P521 => DdiKeyType::Secret521,
        }
    }
}
