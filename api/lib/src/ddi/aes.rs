// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES key generation operations at the DDI layer.
//!
//! This module provides low-level AES key generation functionality that
//! interacts directly with the HSM device driver interface. It handles
//! the construction of DDI requests and processing of responses for AES
//! cryptographic operations.

use itertools::Itertools;

use super::*;

/// Generates an AES key within an HSM session.
///
/// Creates a new AES key using the specified key properties and returns both
/// the key handle for performing operations and the masked key material for
/// secure storage. This function constructs the appropriate DDI request and
/// executes it through the session's device connection.
///
/// # Arguments
///
/// * `session` - The HSM session in which to generate the key
/// * `props` - Key properties specifying size, usage permissions, and attributes
///
/// # Returns
///
/// Returns a tuple containing:
/// - `HsmKeyHandle` - Handle for performing cryptographic operations with the key
/// - `HsmMaskedKey` - Masked key material for secure storage and transport
///
/// # Errors
///
/// Returns an error if:
/// - The key size is not a valid AES size (128, 192, or 256 bits)
/// - Key properties cannot be converted to DDI format
/// - The DDI operation fails
/// - The session is invalid or closed
pub(crate) fn aes_generate_key(
    session: &HsmSession,
    props: HsmKeyProps,
) -> HsmResult<(HsmKeyHandle, HsmKeyProps)> {
    let req = DdiAesGenerateKeyCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::AesGenerateKey, session),
        data: DdiAesGenerateKeyReq {
            key_size: key_size_to_ddi(props.bits() as usize)?,
            key_tag: None,
            key_properties: (&props).try_into()?,
        },
        ext: None,
    };

    let resp = session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    let mut key_id = ddi::HsmKeyIdGuard::new(session, resp.data.key_id);
    let masked_key = resp.data.masked_key.as_slice();
    let key_props = HsmMaskedKey::to_key_props(masked_key)?;
    // Validate that the device returned properties match the requested properties.
    if !props.validate_dev_props(&key_props) {
        //return error
        Err(HsmError::InvalidKeyProps)?;
    }

    //make sure to disarm the key guard to avoid deletion before returning
    key_id.disarm();

    Ok((key_id.key_id(), key_props))
}

/// Encrypts data using AES-CBC mode at the DDI layer.
///
/// Performs AES encryption in CBC (Cipher Block Chaining) mode using the specified
/// key and initialization vector. This function interacts directly with the HSM
/// device driver interface to perform the cryptographic operation.
///
/// # Arguments
///
/// * `session` - The HSM session in which to perform the encryption
/// * `key` - The AES key to use for encryption
/// * `iv` - The initialization vector (modified in place for chaining)
/// * `plaintext` - The data to be encrypted
/// * `ciphertext` - Buffer to receive the encrypted output
///
/// # Returns
///
/// Returns the number of bytes written to the ciphertext buffer.
///
/// # Errors
///
/// Returns an error if:
/// - The session is invalid or closed
/// - The key is invalid or unsuitable for CBC encryption
/// - The IV size is incorrect (must be 16 bytes for AES)
/// - The plaintext size is invalid or not properly aligned
/// - The ciphertext buffer is too small
/// - The DDI operation fails
pub(crate) fn aes_cbc_encrypt(
    key: &HsmAesKey,
    iv: &mut [u8],
    plaintext: &[&[u8]],
    ciphertext: &mut [u8],
) -> HsmResult<usize> {
    let mut len = 0;
    let iter = plaintext.iter().flat_map(|s| s.iter());
    for chunk in &iter.chunks(DdiAesEncryptDecryptReq::MAX_MSG_SIZE) {
        let plaintext_chunk = chunk.copied().collect();
        let written = aes_cbc_encrypt_decrypt(
            key,
            DdiAesOp::Encrypt,
            iv,
            plaintext_chunk,
            &mut ciphertext[len..],
        )?;
        len += written;
    }
    Ok(len)
}

/// Decrypts data using AES-CBC mode at the DDI layer.
///
/// Performs AES decryption in CBC (Cipher Block Chaining) mode using the specified
/// key and initialization vector. This function interacts directly with the HSM
/// device driver interface to perform the cryptographic operation.
///
/// # Arguments
///
/// * `session` - The HSM session in which to perform the decryption
/// * `key` - The AES key to use for decryption
/// * `iv` - The initialization vector (modified in place for chaining)
/// * `ciphertext` - The data to be decrypted
/// * `plaintext` - Buffer to receive the decrypted output
///
/// # Returns
///
/// Returns the number of bytes written to the plaintext buffer.
///
/// # Errors
///
/// Returns an error if:
/// - The session is invalid or closed
/// - The key is invalid or unsuitable for CBC decryption
/// - The IV size is incorrect (must be 16 bytes for AES)
/// - The ciphertext size is invalid or not properly aligned
/// - The plaintext buffer is too small
/// - The DDI operation fails
pub(crate) fn aes_cbc_decrypt(
    key: &HsmAesKey,
    iv: &mut [u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> HsmResult<usize> {
    let mut len = 0;
    let chunks = ciphertext.chunks(DdiAesEncryptDecryptReq::MAX_MSG_SIZE);
    for chunk in chunks {
        let written = aes_cbc_encrypt_decrypt(
            key,
            DdiAesOp::Decrypt,
            iv,
            chunk.to_vec(),
            &mut plaintext[len..],
        )?;
        len += written;
    }
    Ok(len)
}

/// Internal helper function for AES-CBC encryption or decryption operations.
///
/// This function constructs and executes a single AES-CBC encryption or decryption
/// request at the DDI layer. It handles the low-level protocol details including
/// request formatting, execution, IV updating, and response processing.
///
/// # Arguments
///
/// * `key` - The AES key to use for the operation
/// * `op` - The operation type (encrypt or decrypt)
/// * `iv` - The initialization vector (modified in place to support chaining)
/// * `input` - The input data (plaintext for encryption, ciphertext for decryption)
/// * `output` - Buffer to receive the operation output
///
/// # Returns
///
/// Returns the number of bytes written to the output buffer.
///
/// # Errors
///
/// Returns an error if:
/// - The input data cannot be converted to DDI format
/// - The IV cannot be converted to DDI format
/// - The DDI command execution fails
/// - The session is invalid
///
/// # IV Chaining
///
/// The IV is updated after each operation by copying the last 16 bytes from the
/// response. This allows proper chaining of multiple CBC operations on the same
/// data stream.
///
/// # Internal Implementation
///
/// This function should not be called directly. Use `aes_cbc_encrypt` or
/// `aes_cbc_decrypt` instead, which handle chunking of large data.
fn aes_cbc_encrypt_decrypt(
    key: &HsmAesKey,
    op: DdiAesOp,
    iv: &mut [u8],
    input: Vec<u8>,
    output: &mut [u8],
) -> HsmResult<usize> {
    let req = DdiAesEncryptDecryptCmdReq {
        hdr: build_ddi_req_hdr_sess(DdiOp::AesEncryptDecrypt, &key.session()),
        data: DdiAesEncryptDecryptReq {
            key_id: key.handle(),
            op,
            msg: MborByteArray::from_slice(&input).map_hsm_err(HsmError::InternalError)?,
            iv: MborByteArray::from_slice(iv).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };

    let resp = key.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    // Update IV for chaining
    let resp_iv = resp.data.iv.as_slice();
    iv.copy_from_slice(&resp_iv[..16]);

    // Copy output data
    let resp_msg = resp.data.msg.as_slice();
    let to_copy = resp_msg.len().min(output.len());
    output[..to_copy].copy_from_slice(&resp_msg[..to_copy]);

    Ok(to_copy)
}

/// Converts a key size in bits to the corresponding DDI AES key size enum.
///
/// # Arguments
///
/// * `size` - Key size in bits
///
/// # Returns
///
/// Returns the corresponding `DdiAesKeySize` variant for valid AES key sizes.
///
/// # Errors
///
/// Returns `HsmError::AesInvalidKeySize` if the size is not 128, 192, or 256 bits.
fn key_size_to_ddi(size: usize) -> HsmResult<DdiAesKeySize> {
    match size {
        128 => Ok(DdiAesKeySize::Aes128),
        192 => Ok(DdiAesKeySize::Aes192),
        256 => Ok(DdiAesKeySize::Aes256),
        _ => Err(HsmError::InvalidKeySize),
    }
}

/// Encrypts data using AES-XTS mode at the DDI layer.
///
/// # Arguments
///
/// * `key` - AES-XTS key to use
/// * `tweak` - Initial tweak value (little-endian `u128`)
/// * `dul` - Data unit length in bytes
/// * `plaintext` - Data to encrypt (must be DUL-aligned)
/// * `ciphertext` - Output buffer to receive ciphertext
///
/// # Returns
///
/// Returns the number of bytes written to `ciphertext`.
///
/// # Errors
///
/// Returns an error if the underlying DDI operation fails.
pub(crate) fn aes_xts_encrypt(
    key: &HsmAesXtsKey,
    tweak: u128,
    dul: usize,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> HsmResult<usize> {
    aes_xts_encrypt_decrypt(key, DdiAesOp::Encrypt, tweak, dul, plaintext, ciphertext)
}

/// Decrypts data using AES-XTS mode at the DDI layer.
///
/// # Arguments
///
/// * `key` - AES-XTS key to use
/// * `tweak` - Initial tweak value (little-endian `u128`)
/// * `dul` - Data unit length in bytes
/// * `ciphertext` - Data to decrypt (must be DUL-aligned)
/// * `plaintext` - Output buffer to receive plaintext
///
/// # Returns
///
/// Returns the number of bytes written to `plaintext`.
///
/// # Errors
///
/// Returns an error if the underlying DDI operation fails.
pub(crate) fn aes_xts_decrypt(
    key: &HsmAesXtsKey,
    tweak: u128,
    dul: usize,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> HsmResult<usize> {
    aes_xts_encrypt_decrypt(key, DdiAesOp::Decrypt, tweak, dul, ciphertext, plaintext)
}

/// Internal helper for AES-XTS encryption or decryption.
///
/// Builds a DDI fast-path XTS request using the two underlying key handles,
/// the specified tweak and DUL, and copies the response bytes into `output`.
///
/// # Arguments
///
/// * `key` - AES-XTS key to use
/// * `op` - Encrypt or decrypt operation selector
/// * `tweak` - Initial tweak value (little-endian `u128`)
/// * `dul` - Data unit length in bytes
/// * `input` - Input buffer
/// * `output` - Output buffer
///
/// # Returns
///
/// Returns the number of bytes copied to `output`.
///
/// # Errors
///
/// Returns an error if the DDI fast-path command fails.
fn aes_xts_encrypt_decrypt(
    key: &HsmAesXtsKey,
    op: DdiAesOp,
    tweak: u128,
    dul: usize,
    input: &[u8],
    output: &mut [u8],
) -> HsmResult<usize> {
    // Setup DDI params for AES XTS encrypt/decrypt
    let xts_params = DdiAesXtsParams {
        key_id1: key.handle().0 as u32,
        key_id2: key.handle().1 as u32,
        data_unit_len: dul,
        tweak: tweak.to_le_bytes(),
        session_id: key.sess_id(),
        short_app_id: 0,
    };
    let mut is_fips_approved = false;

    let resp = key.with_dev(|dev| {
        dev.exec_op_fp_xts_slice(op, xts_params, input, output, &mut is_fips_approved)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;
    Ok(resp)
}
