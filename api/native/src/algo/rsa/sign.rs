// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use crate::AzihsmAlgo;
use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::algo::AzihsmAlgoId;
use crate::algo::rsa::AzihsmMgf1Id;
use crate::handle_table::HandleType;
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
    type Error = AzihsmStatus;

    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaPkcsPssParams>() as u32 {
            Err(AzihsmStatus::InvalidArgument)?;
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
) -> Result<(), AzihsmStatus>
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
pub(crate) fn rsa_pkcs1_hash_sign(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
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
) -> Result<(), AzihsmStatus> {
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
) -> Result<(), AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmStatus::InvalidArgument)?;
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
) -> Result<bool, AzihsmStatus>
where
    A: HsmVerifyOp<Key = HsmRsaPublicKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmRsaPublicKey::try_from(key_handle)?;

    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Helper function to perform RSA verification operation with hash algorithm
pub(crate) fn rsa_pkcs1_hash_verify(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmStatus> {
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
) -> Result<bool, AzihsmStatus> {
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
) -> Result<bool, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmStatus::InvalidArgument)?;
    }

    // Create PSS hash+verify algorithm with parameters
    let pss_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    verify_with_algo(pss_algo, key_handle, data, sig)
}

/// Generic helper function to initialize RSA streaming signing
fn sign_init_with_algo<A>(
    sign_algo: A,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus>
where
    A: HsmSignStreamingOp<Key = HsmRsaPrivateKey, Error = HsmError>,
{
    // Get the key from handle
    let key = HsmRsaPrivateKey::try_from(key_handle)?;

    // Initialize the streaming signing context
    let ctx = HsmSigner::sign_init(sign_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaSignStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

pub(crate) fn rsa_pkcs1_hash_sign_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    sign_init_with_algo(sign_algo, key_handle)
}

pub(crate) fn rsa_pss_hash_sign_init(
    hash_algo_from_id: AzihsmAlgoId,
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm from params
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmStatus::InvalidArgument)?;
    }

    // Create the signing algorithm with PSS padding
    let sign_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    sign_init_with_algo(sign_algo, key_handle)
}

pub(crate) fn rsa_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmRsaSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaSignStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

pub(crate) fn rsa_sign_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get a reference to determine the required signature size
    let ctx_ref: &mut HsmRsaSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaSignStreamingCtx)?;
    let required_size = ctx_ref.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Take ownership of the context and finalize
    let mut ctx: Box<HsmRsaSignContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::RsaSignStreamingCtx)?;

    // Perform the final signing operation
    let sig_len = ctx.finish(Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

/// Generic helper function to initialize RSA streaming verification
fn verify_init_with_algo<A>(
    verify_algo: A,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus>
where
    A: HsmVerifyStreamingOp<Key = HsmRsaPublicKey, Error = HsmError>,
{
    // Get the key from handle
    let key = HsmRsaPublicKey::try_from(key_handle)?;

    // Initialize the streaming verification context
    let ctx = HsmVerifier::verify_init(verify_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaVerifyStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

pub(crate) fn rsa_pkcs1_hash_verify_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    verify_init_with_algo(verify_algo, key_handle)
}

pub(crate) fn rsa_pss_hash_verify_init(
    hash_algo_from_id: AzihsmAlgoId,
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo_from_id)?;

    // Extract PSS parameters
    let params = <&AzihsmAlgoRsaPkcsPssParams>::try_from(algo)?;

    // Convert hash algorithm from params
    let hash_algo_from_param = HsmHashAlgo::try_from(params.hash_algo_id)?;

    // Check that provided hash_algo matches the one in params
    if hash_algo != hash_algo_from_param {
        Err(AzihsmStatus::InvalidArgument)?;
    }

    // Create the verification algorithm with PSS padding
    let verify_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, params.salt_len as usize);

    verify_init_with_algo(verify_algo, key_handle)
}

pub(crate) fn rsa_verify_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmRsaVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaVerifyStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

pub(crate) fn rsa_verify_final(ctx_handle: AzihsmHandle, sig: &[u8]) -> Result<bool, AzihsmStatus> {
    // Take ownership of the context and finalize
    let mut ctx: Box<HsmRsaVerifyContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::RsaVerifyStreamingCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(sig)?;

    Ok(is_valid)
}
