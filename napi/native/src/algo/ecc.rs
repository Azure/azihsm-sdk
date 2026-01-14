// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::utils::validate_output_buffer;

impl TryFrom<&AzihsmAlgo> for HsmEccKeyGenAlgo {
    type Error = AzihsmError;

    /// Converts a C FFI algorithm specification to HsmEccKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmEccKeyGenAlgo::default())
    }
}

/// ECC algorithm variant for signing and verification operations
enum EccAlgoVariant {
    Direct(HsmEccSignAlgo),
    WithHash(HsmHashSignAlgo),
}

impl EccAlgoVariant {
    /// Create the appropriate algorithm based on the algorithm ID
    fn from_algo_id(algo_id: AzihsmAlgoId) -> Result<Self, AzihsmError> {
        match algo_id {
            AzihsmAlgoId::Ecdsa => Ok(Self::Direct(HsmEccSignAlgo::default())),
            AzihsmAlgoId::EcdsaSha1 => Ok(Self::WithHash(HsmHashSignAlgo::new(HsmHashAlgo::Sha1))),
            AzihsmAlgoId::EcdsaSha256 => {
                Ok(Self::WithHash(HsmHashSignAlgo::new(HsmHashAlgo::Sha256)))
            }
            AzihsmAlgoId::EcdsaSha384 => {
                Ok(Self::WithHash(HsmHashSignAlgo::new(HsmHashAlgo::Sha384)))
            }
            AzihsmAlgoId::EcdsaSha512 => {
                Ok(Self::WithHash(HsmHashSignAlgo::new(HsmHashAlgo::Sha512)))
            }
            _ => Err(AzihsmError::UnsupportedAlgorithm),
        }
    }
}

/// Helper function to perform ECC signing operation
fn perform_ecc_sign(
    algo_id: AzihsmAlgoId,
    key: &HsmEccPrivateKey,
    input: &[u8],
    output: Option<&mut [u8]>,
) -> Result<usize, AzihsmError> {
    let mut sign_algo = EccAlgoVariant::from_algo_id(algo_id)?;

    let result = match &mut sign_algo {
        EccAlgoVariant::Direct(algo) => HsmSigner::sign(algo, key, input, output),
        EccAlgoVariant::WithHash(algo) => HsmSigner::sign(algo, key, input, output),
    };

    Ok(result?)
}

pub(crate) fn ecc_sign(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get the key from handle
    let key: &HsmEccPrivateKey = &key_handle.try_into()?;

    // Determine the required signature size
    let required_size = perform_ecc_sign(algo.id, key, input, None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the actual signing operation
    let sig_len = perform_ecc_sign(algo.id, key, input, Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

pub(crate) fn ecc_verify(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    // Get the key from handle
    let key: &HsmEccPublicKey = &key_handle.try_into()?;

    // Create the appropriate verification algorithm
    let mut verify_algo = EccAlgoVariant::from_algo_id(algo.id)?;

    // Perform verification with the selected algorithm
    let result = match &mut verify_algo {
        EccAlgoVariant::Direct(algo) => HsmVerifier::verify(algo, key, data, sig),
        EccAlgoVariant::WithHash(algo) => HsmVerifier::verify(algo, key, data, sig),
    };

    Ok(result?)
}
