// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

use crate::AzihsmAlgo;
use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::algo::AzihsmAlgoId;
use crate::algo::rsa::AzihsmMgf1Id;
use crate::utils::*;

/// RSA PKCS PSS signature parameters matching C API.
///
/// Defines parameters for PSS (Probabilistic Signature Scheme) operations,
/// which provide probabilistic signature generation using a hash function,
/// mask generation function (MGF1), and salt for enhanced security.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaPkcsPssParams {
    /// Hash algorithm identifier used for PSS signature
    pub hash_algo_id: AzihsmAlgoId,

    /// MGF1 mask generation function identifier (typically matches hash_algo_id)
    pub mgf_id: AzihsmMgf1Id,

    /// Salt length in bytes (typically matches hash output size)
    pub salt_len: u32,
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoRsaPkcsPssParams {
    type Error = AzihsmError;

    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaPkcsPssParams>() as u32 {
            Err(AzihsmError::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaPkcsPssParams>(algo.params)?;

        Ok(params)
    }
}

/// Generic helper function to perform RSA signing operation
fn sign_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError>
where
    A: HsmSignOp<Key = HsmRsaPrivateKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmRsaPrivateKey::try_from(key_handle)?;

    // Determine required size
    let required_size = HsmSigner::sign(&mut algo, key, input, None)?;

    // Validate and get output buffer
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform actual signing
    let sig_len = HsmSigner::sign(&mut algo, key, input, Some(output_data))?;

    // Update output buffer length
    output.len = sig_len as u32;

    Ok(())
}

/// Helper function to perform RSA signing operation with hash algorithm
pub(crate) fn rsa_hash_sign(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    sign_with_algo(
        HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo),
        key_handle,
        input,
        output,
    )
}

/// Helper function to perform RSA PSS signing operation with direct (pre-hashed) algorithm
pub(crate) fn rsa_pss_sign(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Create PSS algorithm with parameters
    let pss_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    sign_with_algo(pss_algo, key_handle, input, output)
}

/// Helper function to perform RSA PSS signing operation with hash algorithm
/// Hashing is performed internally as part of signing
pub(crate) fn rsa_pss_hash_sign(
    hash_algo_from_id: AzihsmAlgoId,
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmError::InvalidArgument)?;
    }

    // Create PSS hash+sign algorithm with parameters
    let pss_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    sign_with_algo(pss_algo, key_handle, input, output)
}

/// Generic helper function to perform RSA verification operation
fn verify_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError>
where
    A: HsmVerifyOp<Key = HsmRsaPublicKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmRsaPublicKey::try_from(key_handle)?;

    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Helper function to perform RSA verification operation with hash algorithm
pub(crate) fn rsa_hash_verify(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    verify_with_algo(
        HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo),
        key_handle,
        data,
        sig,
    )
}

/// Helper function to perform RSA PSS verification operation with direct (pre-hashed) algorithm
pub(crate) fn rsa_pss_verify(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Create PSS algorithm with parameters
    let pss_algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    verify_with_algo(pss_algo, key_handle, data, sig)
}

/// Helper function to perform RSA PSS verification operation with hash algorithm
/// Hashing is performed internally as part of verification
pub(crate) fn rsa_pss_hash_verify(
    hash_algo_from_id: AzihsmAlgoId,
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmError::InvalidArgument)?;
    }

    // Create PSS hash+verify algorithm with parameters
    let pss_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    verify_with_algo(pss_algo, key_handle, data, sig)
}
