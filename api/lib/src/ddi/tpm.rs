// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto::{DerEccPublicKey, EccCurve};
use azihsm_tpm::*;

use crate::HsmError;

/// SHA-384 digest size in bytes
const SHA384_DIGEST_SIZE: usize = 48;

/// ECC P-384 point size in bytes
const ECC_P384_POINT_SIZE: usize = 48;

/// Helper for TPM ECC signing operations.
///
/// This struct encapsulates TPM operations for creating transient ECC P-384
/// signing keys and signing SHA-384 digests using ECDSA.
struct TpmEccSigner {
    tpm: Tpm,
}

impl TpmEccSigner {
    /// Opens a connection to the TPM device.
    ///
    /// # Returns
    ///
    /// * `Ok(TpmEccSigner)` - Successfully opened TPM connection
    /// * `Err(HsmError)` - Failed to access TPM device
    fn open() -> Result<Self, HsmError> {
        let tpm = Tpm::open().map_err(|_| HsmError::InternalError)?;
        Ok(Self { tpm })
    }

    /// Signs a SHA-384 digest with TPM ECC P-384.
    ///
    /// This method creates a transient ECC P-384 signing key in the TPM Endorsement
    /// hierarchy and signs the provided digest using ECDSA. The transient key
    /// is flushed after signing.
    ///
    /// # Arguments
    ///
    /// * `digest` - A 48-byte SHA-384 digest to sign
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (raw ECDSA signature r||s, DER-encoded public key)
    /// * `Err(HsmError)` - If digest is not 48 bytes, or key creation/signing fails
    fn sign_digest(&self, digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        if digest.len() != SHA384_DIGEST_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // Create ECC P-384 signing key in Endorsement hierarchy
        let primary = self
            .tpm
            .create_primary_ecc(Hierarchy::Endorsement, ecc_unrestricted_signing_public())
            .map_err(|_| HsmError::InternalError)?;

        // Extract the ECC public key coordinates from the TPM public blob
        let ecc_point =
            parse_tpm_ecc_public_key(&primary.public).map_err(|_| HsmError::InternalError)?;

        // Sign the digest
        let signature = self.tpm.sign(primary.handle, digest).map_err(|_| {
            // Best-effort flush on error
            let _ = self.tpm.flush_context(primary.handle);
            HsmError::InternalError
        })?;

        // Best-effort flush after successful signing
        let _ = self.tpm.flush_context(primary.handle);

        // Convert TPM signature to raw r||s format
        let signature_raw = convert_tpm_signature_to_raw(&signature)?;

        // Convert public key coordinates to DER format
        let der_pub_key = DerEccPublicKey::new(EccCurve::P384, &ecc_point.x, &ecc_point.y)
            .map_err(|_| HsmError::InternalError)?;

        let der_len = der_pub_key
            .to_der(None)
            .map_err(|_| HsmError::InternalError)?;
        let mut public_key_der = vec![0u8; der_len];
        der_pub_key
            .to_der(Some(&mut public_key_der))
            .map_err(|_| HsmError::InternalError)?;

        Ok((signature_raw, public_key_der))
    }
}

/// Converts a TPM ECDSA signature to raw r||s format.
///
/// The TPM returns ECDSA signatures as separate r and s components in its native
/// format (`TpmtSignature::Ecdsa`). This function converts them to raw format
/// by concatenating r and s (each padded/normalized to the curve's point size).
///
/// # Arguments
///
/// * `signature` - The TPM signature structure
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Raw signature in r||s format (96 bytes for P-384)
/// * `Err(HsmError)` - If the signature is not ECDSA or conversion fails
fn convert_tpm_signature_to_raw(signature: &TpmtSignature) -> Result<Vec<u8>, HsmError> {
    match signature {
        TpmtSignature::Ecdsa(ecdsa) => {
            // Normalize r and s to fixed P-384 point size (48 bytes each)
            let r = normalize_signature_component(&ecdsa.signature_r, ECC_P384_POINT_SIZE)?;
            let s = normalize_signature_component(&ecdsa.signature_s, ECC_P384_POINT_SIZE)?;

            // Concatenate r || s
            let mut raw_sig = Vec::with_capacity(ECC_P384_POINT_SIZE * 2);
            raw_sig.extend_from_slice(&r);
            raw_sig.extend_from_slice(&s);

            Ok(raw_sig)
        }
        _ => Err(HsmError::InternalError),
    }
}

/// Normalizes a signature component to the expected fixed length.
///
/// TPM may return r/s components with leading zeros stripped or with extra
/// leading zeros. This function normalizes to the expected point size.
///
/// # Arguments
///
/// * `component` - The raw signature component bytes
/// * `expected_len` - The expected length (point size for the curve)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Normalized component of exactly `expected_len` bytes
/// * `Err(HsmError)` - If the component is too large
fn normalize_signature_component(
    component: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, HsmError> {
    if component.len() == expected_len {
        return Ok(component.to_vec());
    }

    if component.len() < expected_len {
        // Pad with leading zeros
        let mut result = vec![0u8; expected_len];
        let offset = expected_len - component.len();
        result[offset..].copy_from_slice(component);
        Ok(result)
    } else {
        // Component is too large - check if it has leading zeros we can strip
        let leading_zeros = component.iter().take_while(|&&b| b == 0).count();
        let significant_len = component.len() - leading_zeros;

        if significant_len <= expected_len {
            let mut result = vec![0u8; expected_len];
            let offset = expected_len - significant_len;
            result[offset..].copy_from_slice(&component[leading_zeros..]);
            Ok(result)
        } else {
            Err(HsmError::InternalError)
        }
    }
}

/// Parses a TPM2B_PUBLIC ECC blob and extracts the ECC point (X and Y coordinates).
///
/// Navigates through the TPM2B_PUBLIC structure to find the TPMS_ECC_POINT (unique)
/// field and uses `TpmsEccPoint::unmarshal` to extract the coordinates.
///
/// # Arguments
///
/// * `public_blob` - The raw TPM2B_PUBLIC bytes
///
/// # Returns
///
/// * `Ok(TpmsEccPoint)` - The ECC point containing x and y coordinates
/// * `Err` - If parsing fails
fn parse_tpm_ecc_public_key(public_blob: &[u8]) -> std::io::Result<TpmsEccPoint> {
    use std::io::{Error, ErrorKind};

    if public_blob.len() < 4 {
        return Err(Error::new(ErrorKind::InvalidData, "public blob too short"));
    }

    let mut cursor = 0usize;

    // Skip TPM2B_PUBLIC size prefix (2 bytes)
    cursor += 2;

    // Read type (should be 0x0023 for ECC)
    if cursor + 2 > public_blob.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "type_alg"));
    }
    let type_alg = u16::from_be_bytes([public_blob[cursor], public_blob[cursor + 1]]);
    cursor += 2;

    if type_alg != 0x0023 {
        return Err(Error::new(ErrorKind::InvalidData, "not an ECC key"));
    }

    // Skip nameAlg (2 bytes)
    cursor += 2;

    // Skip objectAttributes (4 bytes)
    cursor += 4;

    // Skip authPolicy (2 bytes size + data)
    if cursor + 2 > public_blob.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "authPolicy size"));
    }
    let auth_policy_size =
        u16::from_be_bytes([public_blob[cursor], public_blob[cursor + 1]]) as usize;
    cursor += 2 + auth_policy_size;

    // Skip symmetric algorithm (2 bytes for TPM_ALG_NULL)
    cursor += 2;

    // Skip scheme (2 bytes algorithm + optional hash)
    if cursor + 2 > public_blob.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "scheme"));
    }
    let scheme_alg = u16::from_be_bytes([public_blob[cursor], public_blob[cursor + 1]]);
    cursor += 2;
    if scheme_alg != 0x0010 {
        // If not NULL, skip hash algorithm (2 bytes)
        cursor += 2;
    }

    // Skip curveID (2 bytes)
    cursor += 2;

    // Skip kdfScheme (2 bytes)
    cursor += 2;

    // Now we're at TPMS_ECC_POINT - use TpmsEccPoint::unmarshal
    TpmsEccPoint::unmarshal(public_blob, &mut cursor)
}

/// Signs a SHA-384 digest with TPM ECC P-384.
///
/// This function creates a transient ECC P-384 signing key and signs the
/// provided digest using ECDSA. The signature is returned in raw r||s format
/// (96 bytes for P-384) and the public key is returned in DER format.
///
/// # Arguments
///
/// * `digest` - A 48-byte SHA-384 digest to sign
///
/// # Returns
///
/// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (raw ECDSA signature r||s, DER-encoded public key)
/// * `Err(HsmError)` - If TPM access or signing fails, or if digest is not 48 bytes
pub(crate) fn tpm_ecc_sign_digest(digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
    let signer = TpmEccSigner::open()?;
    signer.sign_digest(digest)
}
