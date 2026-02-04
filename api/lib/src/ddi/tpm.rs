// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_tpm::*;

use crate::HsmError;

/// SHA-384 digest size in bytes
const SHA384_DIGEST_SIZE: usize = 48;

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
    /// This method creates a transient ECC P-384 signing key in the TPM NULL
    /// hierarchy and signs the provided digest using ECDSA. The transient key
    /// is flushed after signing.
    ///
    /// # Arguments
    ///
    /// * `digest` - A 48-byte SHA-384 digest to sign
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (marshaled ECDSA signature, marshaled public key)
    /// * `Err(HsmError)` - If digest is not 48 bytes, or key creation/signing fails
    fn sign_digest(&self, digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
        if digest.len() != SHA384_DIGEST_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // Create ECC P-384 signing key in NULL hierarchy
        let primary = self
            .tpm
            .create_primary_ecc(Hierarchy::Null, ecc_unrestricted_signing_public())
            .map_err(|_| HsmError::InternalError)?;

        // Extract the public key
        let public_key = primary.public.clone();

        // Sign the digest
        let signature = self.tpm.sign(primary.handle, digest).map_err(|_| {
            // Best-effort flush on error
            let _ = self.tpm.flush_context(primary.handle);
            HsmError::InternalError
        })?;

        // Best-effort flush after successful signing
        let _ = self.tpm.flush_context(primary.handle);

        // Marshal the signature to bytes
        let mut sig_buf = Vec::new();
        signature.marshal(&mut sig_buf);

        Ok((sig_buf, public_key))
    }
}

/// Signs a SHA-384 digest with TPM ECC P-384.
///
/// This function creates a transient ECC P-384 signing key and signs the
/// provided digest using ECDSA.
///
/// # Arguments
///
/// * `digest` - A 48-byte SHA-384 digest to sign
///
/// # Returns
///
/// * `Ok((Vec<u8>, Vec<u8>))` - Tuple of (marshaled ECDSA signature, marshaled public key)
/// * `Err(HsmError)` - If TPM access or signing fails, or if digest is not 48 bytes
pub(crate) fn tpm_ecc_sign_digest(digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
    let signer = TpmEccSigner::open()?;
    signer.sign_digest(digest)
}
