// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC (Elliptic Curve Cryptography) operations through the Device Driver Interface (DDI).
//!
//! This module provides low-level functions for ECC key operations including key pair
//! generation. It serves as a bridge between the HSM session layer and the underlying
//! DDI protocol, handling the translation of HSM key properties to DDI-specific
//! structures and command execution.

use azihsm_crypto::DerEccPublicKey;
use azihsm_crypto::EccCurve;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::TBOR_KEY_LABEL_MAX_LEN;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEccSignReq;
use resiliency_macro::*;

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
#[resiliency_key_gen(session = "session")]
pub(crate) fn ecc_generate_key(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps, HsmKeyProps)> {
    // A V2 (TBOR) session yields a non-resident `Unpinned` and a raw wire
    // public key; a V1 (MBOR) session yields a resident `Pinned` and a
    // DER public key.
    let (handle, masked_key, pub_key_der) = if session.is_ex() {
        ecc_generate_key_tbor(session, &priv_key_props)?
    } else {
        ecc_generate_key_mbor(session, &priv_key_props)?
    };

    let guard = HsmKeyIdGuard::new(session, handle);
    let (dev_priv_key_props, dev_pub_key_props) =
        HsmMaskedKey::to_key_pair_props(&masked_key, &pub_key_der)?;

    // The public key is a software object whose capabilities follow its
    // private counterpart. TBOR masked metadata only carries the private
    // usage (SIGN/DERIVE), so derive the public VERIFY/DERIVE from it.
    let dev_pub_key_props = ecc_public_props_for(&dev_pub_key_props, &dev_priv_key_props);

    // Validate that the device returned properties match the requested properties.
    if !priv_key_props.validate_dev_props(&dev_priv_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((guard.release(), dev_priv_key_props, dev_pub_key_props))
}

/// Runs MBOR `EccGenerateKeyPair`, returning the resident `Pinned`
/// handle, the device-returned masked blob, and the DER public key.
fn ecc_generate_key_mbor(
    session: &HsmSession,
    priv_key_props: &HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, Vec<u8>, Vec<u8>)> {
    let curve = priv_key_props
        .ecc_curve()
        .ok_or(HsmError::PropertyNotPresent)?;
    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::EccGenerateKeyPair, session),
        data: DdiEccGenerateKeyPairReq {
            curve: curve.into(),
            key_tag: None,
            key_properties: priv_key_props.try_into()?,
        },
        ext: None,
    };

    let resp = session.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;
    let handle = to_key_handle(resp.data.private_key_id, None);
    let masked_key = resp.data.masked_key.as_slice().to_vec();
    let pub_key_der = resp.data.pub_key.der.as_slice().to_vec();
    Ok((handle, masked_key, pub_key_der))
}

/// Runs TBOR `EccGenerateKey`, returning the non-resident `Unpinned`
/// handle, the device-returned masked blob, and a DER public key built
/// from the raw wire coordinates.
fn ecc_generate_key_tbor(
    session: &HsmSession,
    props: &HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, Vec<u8>, Vec<u8>)> {
    //check if curve is present or not
    let curve = props.ecc_curve().ok_or(HsmError::PropertyNotPresent)?;

    let key_label = props.label();
    if key_label.len() > TBOR_KEY_LABEL_MAX_LEN {
        return Err(HsmError::InvalidKeyProps);
    }

    let req = TborEccGenerateKeyReq {
        session_id: session.ex_session_id()?,
        scope: props.tbor_scope(),
        curve: ecc_curve_to_tbor(curve),
        key_usage: ecc_tbor_key_usage(props)?,
        key_label: key_label.to_vec(),
    };
    let mut cookie = None;
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    let pub_key_der = ecc_wire_pub_key_to_der(curve, &resp.pub_key)?;
    Ok((ddi::HsmKeyHandle::Unpinned, resp.masked_key, pub_key_der))
}

/// Maps the requested ECC private-key usage onto the TBOR `KeyUsage`
/// bitfield the firmware stamps into the masked metadata.  An ECC private
/// key is **either** a signing key (ECDSA) **or** a derivation key (ECDH)
/// — exactly one; both-set, neither-set, or any non-ECC usage (e.g.
/// encrypt/decrypt) is rejected here rather than silently mapped.
fn ecc_tbor_key_usage(props: &HsmKeyProps) -> HsmResult<u8> {
    // Exactly one of sign/derive is valid for an ECC private key; both-set,
    // neither-set, and non-ECC usage (encrypt/decrypt leave both false) are
    // rejected.
    if props.can_sign() != props.can_derive() {
        Ok(if props.can_sign() {
            KEY_USAGE_SIGN
        } else {
            KEY_USAGE_DERIVE
        })
    } else {
        Err(HsmError::InvalidKeyProps)
    }
}

/// Maps an [`HsmEccCurve`] to the 1-byte TBOR `EccCurve` discriminant.
fn ecc_curve_to_tbor(curve: HsmEccCurve) -> u8 {
    match curve {
        HsmEccCurve::P256 => ECC_CURVE_P256,
        HsmEccCurve::P384 => ECC_CURVE_P384,
        HsmEccCurve::P521 => ECC_CURVE_P521,
    }
}

/// Builds the public key's properties so its capabilities mirror the
/// private key's usage: a signing key's public half verifies, a
/// derivation key's public half derives.
fn ecc_public_props_for(dev_pub: &HsmKeyProps, priv_props: &HsmKeyProps) -> HsmKeyProps {
    let caps = HsmKeyFlags::VERIFY | HsmKeyFlags::DERIVE;
    let mut flags = dev_pub.flags() & !caps;
    if priv_props.can_sign() {
        flags |= HsmKeyFlags::VERIFY;
    }
    if priv_props.can_derive() {
        flags |= HsmKeyFlags::DERIVE;
    }

    let mut props = HsmKeyProps::new(
        dev_pub.class(),
        dev_pub.kind(),
        dev_pub.bits(),
        dev_pub.ecc_curve(),
        flags,
        dev_pub.label().to_vec(),
    );
    if let Some(pub_key_der) = dev_pub.pub_key_der() {
        props.set_pub_key_der(pub_key_der);
    }
    props
}

/// Builds a DER `SubjectPublicKeyInfo` from the TBOR wire public key.
///
/// The wire form is `x ‖ y` affine coordinates, little-endian per
/// coordinate and zero-padded above the curve's byte length (P-521 pads
/// 66 -> 68). DER SPKI expects big-endian coordinates of exactly the
/// curve's component length, so each half is reversed and its leading
/// zero padding removed.
fn ecc_wire_pub_key_to_der(curve: HsmEccCurve, wire: &[u8]) -> HsmResult<Vec<u8>> {
    if wire.is_empty() || wire.len() % 2 != 0 {
        return Err(HsmError::InternalError);
    }
    let coord = curve.component_size();
    let half = wire.len() / 2;
    if half < coord {
        return Err(HsmError::InternalError);
    }

    let mut x = wire[..half].to_vec();
    let mut y = wire[half..].to_vec();
    x.reverse();
    y.reverse();
    let x = strip_leading_zero_pad(&x, coord)?;
    let y = strip_leading_zero_pad(&y, coord)?;

    let crypto_curve = match curve {
        HsmEccCurve::P256 => EccCurve::P256,
        HsmEccCurve::P384 => EccCurve::P384,
        HsmEccCurve::P521 => EccCurve::P521,
    };
    let der = DerEccPublicKey::new(crypto_curve, x, y).map_err(|_| HsmError::InternalError)?;
    let der_len = der.to_der(None).map_err(|_| HsmError::InternalError)?;
    let mut out = vec![0u8; der_len];
    der.to_der(Some(&mut out))
        .map_err(|_| HsmError::InternalError)?;
    Ok(out)
}

/// Removes leading zero padding from a big-endian coordinate down to
/// `coord` bytes, rejecting any non-zero byte in the padding region.
fn strip_leading_zero_pad(be: &[u8], coord: usize) -> HsmResult<&[u8]> {
    let pad = be.len() - coord;
    if be[..pad].iter().any(|&byte| byte != 0) {
        return Err(HsmError::InternalError);
    }
    Ok(&be[pad..])
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
#[resiliency_key_op(key = "key")]
pub(crate) fn ecc_sign(
    key: &HsmEccPrivateKey,
    hash: &[u8],
    hash_algo: HsmHashAlgo,
    sig: &mut [u8],
) -> HsmResult<usize> {
    let Some(curve) = key.ecc_curve() else {
        return Err(HsmError::PropertyNotPresent);
    };

    // Transport is selected by session type: a V2 (TBOR) session signs with
    // the caller-held masked key; a V1 (MBOR) session signs with the
    // device-resident key id.
    if key.session().is_ex() {
        ecc_sign_tbor(key, curve, hash, sig)
    } else {
        ecc_sign_mbor(key, curve, hash, hash_algo, sig)
    }
}

/// Signs a pre-computed digest over MBOR `EccSign` using the resident key.
fn ecc_sign_mbor(
    key: &HsmEccPrivateKey,
    curve: HsmEccCurve,
    hash: &[u8],
    hash_algo: HsmHashAlgo,
    sig: &mut [u8],
) -> HsmResult<usize> {
    let req = DdiEccSignCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::EccSign, &key.session()),
        data: DdiEccSignReq {
            key_id: ddi::get_key_id(key.handle())?,
            digest: MborByteArray::from_slice(hash).map_hsm_err(HsmError::InternalError)?,
            digest_algo: hash_algo.into(),
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

    let sig_len = curve.signature_size();
    sig[..sig_len].copy_from_slice(&resp.data.signature.as_slice()[..sig_len]);

    Ok(sig_len)
}

/// Signs a pre-computed digest over TBOR `EccSign` using the caller-held
/// masked key (unmask-on-use). The digest is sent in wire little-endian
/// order and the returned `r ‖ s` is converted back to big-endian.
fn ecc_sign_tbor(
    key: &HsmEccPrivateKey,
    curve: HsmEccCurve,
    hash: &[u8],
    sig: &mut [u8],
) -> HsmResult<usize> {
    let masked = key.masked_key_vec()?;

    // Firmware reads the digest as a little-endian integer; the host holds
    // it big-endian.
    let mut digest = hash.to_vec();
    digest.reverse();

    let req = TborEccSignReq {
        session_id: key.session().ex_session_id()?,
        masked_key: masked,
        digest,
    };
    let mut cookie = None;
    let resp = key.with_dev(|dev| {
        dev.exec_op_tbor(&req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    tbor_sig_to_be(curve, &resp.signature, sig)
}

/// Converts the TBOR wire signature (`r ‖ s`, each component little-endian
/// and zero-padded to the wire coordinate length) into big-endian `r ‖ s`
/// of the curve's component length, matching the MBOR signature format.
fn tbor_sig_to_be(curve: HsmEccCurve, wire_sig: &[u8], out: &mut [u8]) -> HsmResult<usize> {
    if wire_sig.is_empty() || wire_sig.len() % 2 != 0 {
        return Err(HsmError::InternalError);
    }
    let coord = curve.component_size();
    let half = wire_sig.len() / 2;
    if half < coord {
        return Err(HsmError::InternalError);
    }
    let sig_len = coord * 2;
    if out.len() < sig_len {
        return Err(HsmError::BufferTooSmall);
    }

    let mut r = wire_sig[..half].to_vec();
    let mut s = wire_sig[half..].to_vec();
    r.reverse();
    s.reverse();
    let r = strip_leading_zero_pad(&r, coord)?;
    let s = strip_leading_zero_pad(&s, coord)?;

    out[..coord].copy_from_slice(r);
    out[coord..sig_len].copy_from_slice(s);
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
#[resiliency_key_op(key = "base_key")]
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
            priv_key_id: ddi::get_key_id(base_key.handle())?,
            pub_key_der: MborByteArray::from_slice(peer_pub_der)
                .map_hsm_err(HsmError::InternalError)?,
            key_tag: None,
            key_type: curve.into(),
            key_properties: (&derived_key_props).try_into()?,
        },
        ext: None,
    };

    let resp =
        base_key.with_dev(|dev| dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from))?;

    let session = base_key.session();
    let key_id = HsmKeyIdGuard::new(&session, to_key_handle(resp.data.key_id, None));
    let dev_key_props = HsmMaskedKey::to_key_props(resp.data.masked_key.as_slice())?;
    // Validate that the device returned properties match the requested properties.
    if !derived_key_props.validate_dev_props(&dev_key_props) {
        Err(HsmError::InvalidKeyProps)?;
    }

    Ok((key_id.release(), dev_key_props))
}

/// Generates a key report (attestation) for the specified ECC private key.
///
/// This is a typed wrapper around [`generate_key_report`] that enables the
/// `#[resiliency_key_op]` proc macro to automatically handle partition restore,
/// session reopen, and key refresh on retryable errors.
///
/// # Arguments
///
/// * `key` - The ECC private key to attest.
/// * `report_data` - Custom data to include in the attestation report.
/// * `report` - Optional mutable buffer to receive the attestation report.
///
/// # Returns
///
/// Returns the size of the attestation report on success.
#[resiliency_key_op(key = "key")]
pub(crate) fn ecc_generate_key_report(
    key: &HsmEccPrivateKey,
    report_data: &[u8],
    report: Option<&mut [u8]>,
) -> HsmResult<usize> {
    generate_key_report(&key.session(), key.handle(), report_data, report)
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
