// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

/// Signs a pre-hashed message using RSA PKCS#1 v1.5
///
/// Single-shot operation that signs already-hashed data.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm used for the digest
/// * `key_handle` - Handle to the RSA private key
/// * `hash` - Pre-computed hash of the message
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid key, buffer too small)
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

/// Signs data using RSA-PSS
///
/// Single-shot operation that signs pre-hashed data using PSS padding.
///
/// # Arguments
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA private key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
/// * `hash` - Pre-computed hash of the message
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure
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

/// Signs a message using RSA-PSS with automatic hashing
///
/// Single-shot operation that hashes the message and signs using PSS padding.
///
/// # Arguments
/// * `hash_algo_from_id` - Hash algorithm identifier
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA private key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
/// * `message` - Raw message to hash and sign
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure
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

/// Verifies a signature on pre-hashed data using RSA PKCS#1 v1.5
///
/// Single-shot operation that verifies a signature against already-hashed data.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm used for the digest
/// * `key_handle` - Handle to the RSA public key
/// * `hash` - Pre-computed hash of the message
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
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

/// Verifies a signature using RSA-PSS
///
/// Single-shot operation that verifies a PSS signature against pre-hashed data.
///
/// # Arguments
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA public key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
/// * `hash` - Pre-computed hash of the message
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
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

/// Verifies a signature on a message using RSA-PSS with automatic hashing
///
/// Single-shot operation that hashes the message and verifies the PSS signature.
///
/// # Arguments
/// * `hash_algo_from_id` - Hash algorithm identifier
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA public key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
/// * `message` - Raw message to hash and verify
/// * `signature` - Signature to verify
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
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
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaSignCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Initializes a streaming RSA PKCS#1 v1.5 signing operation
///
/// Creates a context for incrementally signing data.
/// Use with `rsa_sign_update` and `rsa_sign_finish`.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use
/// * `key_handle` - Handle to the RSA private key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the signing context
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_pkcs1_hash_sign_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    sign_init_with_algo(sign_algo, key_handle)
}

/// Initializes a streaming RSA-PSS signing operation
///
/// Creates a context for incrementally signing data with PSS padding.
/// Use with `rsa_sign_update` and `rsa_sign_finish`.
///
/// # Arguments
/// * `hash_algo_from_id` - Hash algorithm identifier
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA private key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the signing context
/// * `Err(AzihsmStatus)` - On failure
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

/// Updates a streaming RSA signing operation with additional data
///
/// Processes a chunk of data in an incremental signing operation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `data` - Data chunk to include in the signature
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_sign_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmRsaSignContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaSignCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming RSA signing operation
///
/// Completes the signature computation and returns the final signature.
///
/// # Arguments
/// * `ctx_handle` - Handle to the signing context
/// * `output` - Output buffer for the signature
///
/// # Returns
/// * `Ok(())` - On successful signature generation
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_sign_finish(
    ctx_handle: AzihsmHandle,
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    // Get a reference to determine the required signature size
    let ctx: &mut HsmRsaSignContext = HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaSignCtx)?;
    let required_size = ctx.finish(None)?;

    // Check if output buffer is large enough
    let output_data = validate_output_buffer(output, required_size)?;

    // Perform the final signing operation
    let sig_len = ctx_ref.finish(Some(output_data))?;

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
    let ctx_handle = HANDLE_TABLE.alloc_handle(HandleType::RsaVerifyCtx, Box::new(ctx));

    Ok(ctx_handle)
}

/// Initializes a streaming RSA PKCS#1 v1.5 verification operation
///
/// Creates a context for incrementally verifying a signature.
/// Use with `rsa_verify_update` and `rsa_verify_finish`.
///
/// # Arguments
/// * `hash_algo` - Hash algorithm to use
/// * `key_handle` - Handle to the RSA public key
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the verification context
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_pkcs1_hash_verify_init(
    hash_algo: AzihsmAlgoId,
    key_handle: AzihsmHandle,
) -> Result<AzihsmHandle, AzihsmStatus> {
    let hash_algo = HsmHashAlgo::try_from(hash_algo)?;
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    verify_init_with_algo(verify_algo, key_handle)
}

/// Initializes a streaming RSA-PSS verification operation
///
/// Creates a context for incrementally verifying a PSS signature.
/// Use with `rsa_verify_update` and `rsa_verify_finish`.
///
/// # Arguments
/// * `hash_algo_from_id` - Hash algorithm identifier
/// * `algo` - Algorithm specification containing PSS parameters
/// * `key_handle` - Handle to the RSA public key
/// * `pss_params` - PSS algorithm parameters (hash algorithm, MGF, salt length)
///
/// # Returns
/// * `Ok(AzihsmHandle)` - Handle to the verification context
/// * `Err(AzihsmStatus)` - On failure
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

/// Updates a streaming RSA verification operation with additional data
///
/// Processes a chunk of data in an incremental verification operation.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `data` - Data chunk to include in the verification
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_verify_update(ctx_handle: AzihsmHandle, data: &[u8]) -> Result<(), AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmRsaVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaVerifyCtx)?;

    // Update the context with the data chunk
    ctx.update(data)?;

    Ok(())
}

/// Finishes a streaming RSA verification operation
///
/// Completes the verification and checks if the signature is valid.
///
/// # Arguments
/// * `ctx_handle` - Handle to the verification context
/// * `sig` - Signature to verify against
///
/// # Returns
/// * `Ok(true)` - If signature is valid
/// * `Ok(false)` - If signature is invalid
/// * `Err(AzihsmStatus)` - On failure
pub(crate) fn rsa_verify_finish(
    ctx_handle: AzihsmHandle,
    sig: &[u8],
) -> Result<bool, AzihsmStatus> {
    // Get mutable reference to the context from handle table
    let ctx: &mut HsmRsaVerifyContext =
        HANDLE_TABLE.as_mut(ctx_handle, HandleType::RsaVerifyCtx)?;

    // Perform the final verification operation
    let is_valid = ctx.finish(sig)?;

    Ok(is_valid)
}
