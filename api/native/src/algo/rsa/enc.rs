// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;

use super::*;
use crate::AzihsmBuffer;
use crate::AzihsmHandle;
use crate::AzihsmStatus;
use crate::HANDLE_TABLE;
use crate::handle_table::HandleType;
use crate::utils::*;

impl TryFrom<&AzihsmAlgo> for HsmRsaKeyUnwrappingKeyGenAlgo {
    type Error = AzihsmStatus;

    /// Converts a C FFI algorithm specification to HsmRsaKeyUnwrappingKeyGenAlgo.
    fn try_from(_algo: &AzihsmAlgo) -> Result<Self, Self::Error> {
        Ok(HsmRsaKeyUnwrappingKeyGenAlgo::default())
    }
}

/// RSA-AES Wrap algorithm parameters structure matching C API
///
/// This structure specifies the parameters for RSA-AES generic wrapping,
/// which combines RSA-OAEP encryption with AES wrapping to securely
/// transport data.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaAesWrapParams {
    /// AES key bits
    pub aes_key_bits: u32,

    /// OAEP parameters
    pub oaep_params: *const AzihsmAlgoRsaPkcsOaepParams,
}

impl<'a> TryFrom<&'a AzihsmAlgo> for &'a AzihsmAlgoRsaAesWrapParams {
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(algo: &'a AzihsmAlgo) -> Result<Self, Self::Error> {
        if algo.len != std::mem::size_of::<AzihsmAlgoRsaAesWrapParams>() as u32 {
            Err(AzihsmStatus::InvalidArgument)?;
        }

        let params = cast_ptr::<AzihsmAlgoRsaAesWrapParams>(algo.params)?;

        // Validate OAEP parameters pointer
        validate_ptr(params.oaep_params)?;

        Ok(params)
    }
}

impl TryFrom<&AzihsmAlgoRsaAesWrapParams> for HsmRsaAesWrapAlgo {
    type Error = AzihsmStatus;

    #[allow(unsafe_code)]
    fn try_from(params: &AzihsmAlgoRsaAesWrapParams) -> Result<Self, Self::Error> {
        let oaep_params = deref_ptr(params.oaep_params)?;
        let hash_algo = HsmHashAlgo::try_from(oaep_params.hash_algo_id)?;
        Ok(HsmRsaAesWrapAlgo::new(
            hash_algo,
            (params.aes_key_bits / 8) as usize,
        ))
    }
}

/// MGF1 (Mask Generation Function 1) identifier enumeration.
///
/// This enum defines the supported mask generation functions used in RSA operations,
/// particularly for OAEP padding schemes. MGF1 is based on hash functions and provides
/// deterministic mask generation for cryptographic operations.
///
/// The enum is represented as a u32 to ensure compatibility with C APIs and consistent
/// memory layout across different platforms.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AzihsmMgf1Id {
    /// MGF1 with SHA-256 hash function
    Sha256 = 1,

    /// MGF1 with SHA-384 hash function
    Sha384 = 2,

    /// MGF1 with SHA-512 hash function
    Sha512 = 3,

    /// MGF1 with SHA-1 hash function
    Sha1 = 4,
}

/// RSA PKCS OAEP encryption/decryption parameters matching C API.
///
/// Defines parameters for OAEP (Optimal Asymmetric Encryption Padding) operations,
/// which provide secure probabilistic encryption using a hash function, mask
/// generation function (MGF1), and optional label for context binding.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AzihsmAlgoRsaPkcsOaepParams {
    /// Hash algorithm identifier used for OAEP padding
    pub hash_algo_id: AzihsmAlgoId,

    /// MGF1 mask generation function identifier
    pub mgf1_hash_algo_id: AzihsmMgf1Id,

    /// Optional label for encryption context (can be null)
    pub label: *const AzihsmBuffer,
}

impl TryFrom<AzihsmHandle> for HsmRsaPublicKey {
    type Error = AzihsmStatus;

    fn try_from(handle: AzihsmHandle) -> Result<Self, Self::Error> {
        let key: &HsmRsaPublicKey = HANDLE_TABLE.as_ref(handle, HandleType::RsaPubKey)?;
        Ok(key.clone())
    }
}

impl TryFrom<AzihsmHandle> for HsmRsaPrivateKey {
    type Error = AzihsmStatus;

    fn try_from(handle: AzihsmHandle) -> Result<Self, Self::Error> {
        let key: &HsmRsaPrivateKey = HANDLE_TABLE.as_ref(handle, HandleType::RsaPrivKey)?;
        Ok(key.clone())
    }
}

/// Generic helper function to perform RSA cryptographic operations (encrypt/decrypt)
fn perform_crypto<A, K, F>(
    crypto_algo: &mut A,
    key: &K,
    input: &[u8],
    output: &mut AzihsmBuffer,
    crypto_fn: F,
) -> Result<(), AzihsmStatus>
where
    F: Fn(&mut A, &K, &[u8], Option<&mut [u8]>) -> Result<usize, HsmError>,
{
    // Query the required output buffer size
    let required_len = crypto_fn(crypto_algo, key, input, None)?;

    // Check if output buffer is large enough
    let output_buf = validate_output_buffer(output, required_len)?;

    // Perform the cryptographic operation
    let written = crypto_fn(crypto_algo, key, input, Some(output_buf))?;

    // Update output buffer length with actual bytes written
    output.len = written as u32;

    Ok(())
}

/// Encrypts data using RSA public key encryption
///
/// Encrypts plaintext using RSA with the specified padding scheme.
///
/// # Arguments
/// * `algo` - RSA encryption algorithm (PKCS#1 v1.5 or OAEP)
/// * `key_handle` - Handle to the RSA public key
/// * `plaintext` - Data to encrypt
/// * `output` - Output buffer for the ciphertext
///
/// # Returns
/// * `Ok(())` - On successful encryption
/// * `Err(AzihsmStatus)` - On failure (e.g., plaintext too large, buffer too small)
pub(crate) fn rsa_encrypt(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let key: HsmRsaPublicKey = HsmRsaPublicKey::try_from(key_handle)?;

    match algo.id {
        AzihsmAlgoId::RsaPkcs => {
            let mut encrypt_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
            perform_crypto(
                &mut encrypt_algo,
                &key,
                input,
                output,
                HsmEncrypter::encrypt,
            )
        }
        AzihsmAlgoId::RsaPkcsOaep => {
            let params = <&AzihsmAlgoRsaPkcsOaepParams>::try_from(algo)?;
            let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;
            let mut encrypt_algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);
            perform_crypto(
                &mut encrypt_algo,
                &key,
                input,
                output,
                HsmEncrypter::encrypt,
            )
        }
        AzihsmAlgoId::RsaAesWrap => {
            let params = <&AzihsmAlgoRsaAesWrapParams>::try_from(algo)?;
            let mut wrap_algo = HsmRsaAesWrapAlgo::try_from(params)?;
            perform_crypto(&mut wrap_algo, &key, input, output, HsmEncrypter::encrypt)
        }
        _ => Err(AzihsmStatus::UnsupportedAlgorithm),
    }
}

/// Decrypts data using RSA private key decryption
///
/// Decrypts ciphertext using RSA with the specified padding scheme.
///
/// # Arguments
/// * `algo` - RSA decryption algorithm (PKCS#1 v1.5 or OAEP)
/// * `key_handle` - Handle to the RSA private key
/// * `ciphertext` - Data to decrypt
/// * `output` - Output buffer for the plaintext
///
/// # Returns
/// * `Ok(())` - On successful decryption
/// * `Err(AzihsmStatus)` - On failure (e.g., invalid ciphertext, buffer too small)
pub(crate) fn rsa_decrypt(
    algo: &AzihsmAlgo,
    key_handle: AzihsmHandle,
    input: &[u8],
    output: &mut AzihsmBuffer,
) -> Result<(), AzihsmStatus> {
    let key: HsmRsaPrivateKey = HsmRsaPrivateKey::try_from(key_handle)?;

    match algo.id {
        AzihsmAlgoId::RsaPkcs => {
            let mut decrypt_algo = HsmRsaEncryptAlgo::with_pkcs1_padding();
            perform_crypto(
                &mut decrypt_algo,
                &key,
                input,
                output,
                HsmDecrypter::decrypt,
            )
        }
        AzihsmAlgoId::RsaPkcsOaep => {
            let params = <&AzihsmAlgoRsaPkcsOaepParams>::try_from(algo)?;
            let hash_algo = HsmHashAlgo::try_from(params.hash_algo_id)?;
            let mut decrypt_algo = HsmRsaEncryptAlgo::with_oaep_padding(hash_algo, None);
            perform_crypto(
                &mut decrypt_algo,
                &key,
                input,
                output,
                HsmDecrypter::decrypt,
            )
        }
        _ => Err(AzihsmStatus::UnsupportedAlgorithm),
    }
}
