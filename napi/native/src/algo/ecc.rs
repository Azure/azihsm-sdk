// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;

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

pub(crate) fn ecc_sign_init(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmError> {
    // Get the key from handle
    let key: HsmEccPrivateKey = key_handle.try_into()?;

    // Create the appropriate signing algorithm variant based on algorithm ID
    let sign_algo = match algo.id {
        AzihsmAlgoId::Ecdsa => {
            // Streaming pre-computed hash input is not supported
            Err(AzihsmError::UnsupportedAlgorithm)?
        }
        AzihsmAlgoId::EcdsaSha1 => HsmHashSignAlgo::new(HsmHashAlgo::Sha1),
        AzihsmAlgoId::EcdsaSha256 => HsmHashSignAlgo::new(HsmHashAlgo::Sha256),
        AzihsmAlgoId::EcdsaSha384 => HsmHashSignAlgo::new(HsmHashAlgo::Sha384),
        AzihsmAlgoId::EcdsaSha512 => HsmHashSignAlgo::new(HsmHashAlgo::Sha512),
        _ => return Err(AzihsmError::UnsupportedAlgorithm),
    };

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
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmError> {
    // Get the key from handle
    let key: HsmEccPublicKey = key_handle.try_into()?;

    // Create the appropriate verification algorithm variant based on algorithm ID
    let verify_algo = match algo.id {
        AzihsmAlgoId::Ecdsa => {
            // Streaming pre-computed hash input is not supported
            Err(AzihsmError::UnsupportedAlgorithm)?
        }
        AzihsmAlgoId::EcdsaSha1 => HsmHashSignAlgo::new(HsmHashAlgo::Sha1),
        AzihsmAlgoId::EcdsaSha256 => HsmHashSignAlgo::new(HsmHashAlgo::Sha256),
        AzihsmAlgoId::EcdsaSha384 => HsmHashSignAlgo::new(HsmHashAlgo::Sha384),
        AzihsmAlgoId::EcdsaSha512 => HsmHashSignAlgo::new(HsmHashAlgo::Sha512),
        _ => return Err(AzihsmError::UnsupportedAlgorithm),
    };

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
