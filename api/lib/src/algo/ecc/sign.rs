// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;

use super::*;

/// ECC signature algorithm implementation operating on pre-computed hashes.
///
/// Provides single-operation signing and verification using elliptic curve cryptography.
/// The caller is responsible for hashing message data before passing it to this algorithm.
#[derive(Default)]
pub struct HsmEccSignAlgo {}

impl HsmEccSignAlgo {
    /// Infers the hash algorithm from hash data length.
    ///
    /// # Parameters
    /// - `data`: Hash bytes to analyze.
    ///
    /// # Returns
    ///
    /// Corresponding `HsmHashAlgo` based on length (20=SHA1, 32=SHA256, 48=SHA384, 64=SHA512).
    ///
    /// # Errors
    ///
    /// Returns `HsmError::InvalidArgument` if the length doesn't match a known hash size.
    fn hash_algo(&self, data: &[u8]) -> HsmResult<HsmHashAlgo> {
        match data.len() {
            20 => Ok(HsmHashAlgo::Sha1),
            32 => Ok(HsmHashAlgo::Sha256),
            48 => Ok(HsmHashAlgo::Sha384),
            64 => Ok(HsmHashAlgo::Sha512),
            _ => Err(HsmError::InvalidArgument),
        }
    }
}

impl HsmSignOp for HsmEccSignAlgo {
    type Key = HsmEccPrivateKey;
    type Error = HsmError;

    /// Creates an ECC signature over the provided hash in a single operation.
    ///
    /// This method performs elliptic curve signature generation on a pre-computed hash
    /// by delegating to the HSM's signing operation. The caller must provide the hash
    /// of the message.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC private key to use for signing. Must be compatible with the
    ///   configured elliptic curve (e.g., P-256, P-384, P-521).
    /// * `data` - The pre-computed message hash. The caller is responsible for hashing
    ///   the original message. Hash size should match curve requirements (e.g., 32 bytes
    ///   for P-256, 48 bytes for P-384, 64+ bytes for P-521).
    /// * `signature` - Optional output buffer. If `None`, returns the required signature
    ///   size. If provided, must be large enough to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`. Typical sizes:
    /// - P-256: 64 bytes (raw) or ~70-72 bytes (DER)
    /// - P-384: 96 bytes (raw) or ~102-104 bytes (DER)
    /// - P-521: 132 bytes (raw) or ~137-139 bytes (DER)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The key is invalid or incompatible with the configured curve
    /// - The hash length is invalid for the configured curve
    /// - The HSM signature operation fails
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        if !key.can_sign() {
            return Err(HsmError::InvalidKey);
        }

        let Some(curve) = key.ecc_curve() else {
            return Err(HsmError::InvalidKey);
        };

        let expected_len = curve.signature_size();
        let Some(signature) = signature else {
            return Ok(expected_len);
        };
        if signature.len() != expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        ddi::ecc_sign(key, data, self.hash_algo(data)?, signature)
    }
}

impl HsmVerifyOp for HsmEccSignAlgo {
    type Key = HsmEccPublicKey;
    type Error = HsmError;

    /// Verifies an ECC signature over the provided hash in a single operation.
    ///
    /// This method performs elliptic curve signature verification on a pre-computed hash.
    /// The caller must provide the hash of the message that was signed.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC public key to use for verification. Must correspond to the
    ///   private key used for signing and match the configured curve.
    /// * `data` - The pre-computed message hash. Must be identical to the hash used
    ///   during signing. The caller is responsible for hashing the original message.
    /// * `signature` - The signature to verify. Expected format depends on the
    ///   implementation (raw concatenated r,s or DER-encoded).
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature is valid for the given hash and public key
    /// - `Ok(false)` - The signature is invalid (wrong key, modified hash, or incorrect signature)
    /// - `Err` - The verification operation itself failed (malformed input, system error)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key format is invalid or corrupted
    /// - The key is incompatible with the configured curve
    /// - The signature format is malformed or has incorrect length
    /// - The hash length is invalid for the configured curve
    /// - The HSM verification operation fails
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        if !key.can_verify() {
            return Err(HsmError::InvalidKey);
        }

        let mut algo = crypto::EccAlgo::default();

        key.with_crypto_key(|crypto_key| {
            crypto::Verifier::verify(&mut algo, crypto_key, data, signature)
                .map_hsm_err(HsmError::InternalError)
        })
    }
}
