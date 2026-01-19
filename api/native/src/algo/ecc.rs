// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmError;
use crate::AzihsmHandle;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::validate_output_buffer;

impl TryFrom<&AzihsmAlgo> for HsmEccKeyGenAlgo {
    type Error = AzihsmError;

    /// Converts a C FFI algorithm specification to HsmEccKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmEccKeyGenAlgo::default())
    }
}

/// Helper function to generate an ECC key pair
pub(crate) fn ecc_generate_key_pair(
    session: &HsmSession,
    algo: &AzihsmAlgo,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    let mut ecc_algo = HsmEccKeyGenAlgo::try_from(algo)?;
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut ecc_algo, priv_key_props, pub_key_props)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}

/// Generic helper function to perform ECC signing operation
fn sign_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError>
where
    A: HsmSignOp<Key = HsmEccPrivateKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmEccPrivateKey::try_from(key_handle)?;

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

/// Generic helper function to perform ECC verification operation
fn verify_with_algo<A>(
    mut algo: A,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError>
where
    A: HsmVerifyOp<Key = HsmEccPublicKey, Error = HsmError>,
{
    // Get the key from handle
    let key = &HsmEccPublicKey::try_from(key_handle)?;

    Ok(HsmVerifier::verify(&mut algo, key, data, sig)?)
}

/// Helper function to perform ECC signing operation with direct (pre-hashed) algorithm
pub(crate) fn ecc_sign(
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    sign_with_algo(HsmEccSignAlgo::default(), key_handle, input, output)
}

/// Helper function to perform ECC signing operation with hash algorithm
/// Hashing is performed internally as part of signing
pub(crate) fn ecc_hash_sign(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    sign_with_algo(HsmHashSignAlgo::new(hash_algo), key_handle, input, output)
}

/// Helper function to perform ECC verification operation with direct (pre-hashed) algorithm
pub(crate) fn ecc_verify(
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    verify_with_algo(HsmEccSignAlgo::default(), key_handle, data, sig)
}

/// Helper function to perform ECC verification operation with hash algorithm
pub(crate) fn ecc_hash_verify(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    verify_with_algo(HsmHashSignAlgo::new(hash_algo), key_handle, data, sig)
}

pub(crate) fn ecc_sign_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;

    // Get the key from handle
    let key = HsmEccPrivateKey::try_from(key_handle)?;

    // Create the signing algorithm
    let sign_algo = HsmHashSignAlgo::new(hash_algo);

    // Initialize the streaming signing context
    let ctx = HsmSigner::sign_init(sign_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::EccSignStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

pub(crate) fn ecc_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmError> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmEccSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccSignStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

pub(crate) fn ecc_sign_final(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmError> {
    // Get a reference to determine the required signature size
    let ctx_ref: &mut HsmEccSignContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccSignStreamingCtx)?;
    let required_size = ctx_ref.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Take ownership of the context and finalize
    let mut ctx: Box<HsmEccSignContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::EccSignStreamingCtx)?;

    // Perform the final signing operation
    let sig_len = ctx.finish(Some(output_data))?;

    // Update the output buffer length with actual signature length
    output.len = sig_len as u32;

    Ok(())
}

pub(crate) fn ecc_verify_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmError> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;

    // Get the key from handle
    let key = HsmEccPublicKey::try_from(key_handle)?;

    // Create the verification algorithm
    let verify_algo = HsmHashSignAlgo::new(hash_algo);

    // Initialize the streaming verification context
    let ctx = HsmVerifier::verify_init(verify_algo, key)?;

    // Allocate a handle for the context and return it
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::EccVerifyStreamingCtx, Box::new(ctx));

    Ok(ctx_handle)
}

pub(crate) fn ecc_verify_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmError> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmEccVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::EccVerifyStreamingCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

pub(crate) fn ecc_verify_final(
    ctx_handle: AzihsmHandle,
    signature: &[u8],
) -> Result<bool, AzihsmError> {
    // Take ownership of the context and finalize
    let mut ctx: Box<HsmEccVerifyContext> =
        HANDLE_TABLE.free_handle(ctx_handle, HandleType::EccVerifyStreamingCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(signature)?;

    Ok(is_valid)
}

/// Unmask a masked ECC key pair
pub(crate) fn ecc_unmask_key_pair(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<(AzihsmHandle, AzihsmHandle), AzihsmError> {
    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();

    // Unmask ECC key pair
    let (priv_key, pub_key): (HsmEccPrivateKey, HsmEccPublicKey) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, masked_key)?;

    let priv_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPrivKey, Box::new(priv_key));
    let pub_handle = HANDLE_TABLE.alloc_handle(HandleType::EccPubKey, Box::new(pub_key));

    Ok((priv_handle, pub_handle))
}
