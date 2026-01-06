// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for SHA.

#[cfg(target_os = "linux")]
use openssl;
#[cfg(target_os = "linux")]
use openssl::hash::MessageDigest;
#[cfg(target_os = "linux")]
use openssl::pkey::Id;
#[cfg(target_os = "linux")]
use openssl::pkey_ctx::PkeyCtx;
#[cfg(target_os = "windows")]
use symcrypt::hash;
#[cfg(target_os = "windows")]
use symcrypt::hkdf::hkdf;
#[cfg(target_os = "windows")]
use symcrypt::hmac::HmacAlgorithm;

use crate::errors::ManticoreError;

/// Supported hash algorithms (only SHA for now).
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-1
    Sha1,

    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,
}

impl HashAlgorithm {
    /// Returns the size of the hash in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Returns the block size of the hash algorithm.
    pub fn block_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 64,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha384 => 128,
            HashAlgorithm::Sha512 => 128,
        }
    }
}

///  SHA operation.
///
/// # Arguments
/// * `hash_algorithm` - The SHA algorithm (SHA-1/ SHA-256/ SHA-384/ SHA-512) to be used.
/// * `data` - The data to be hashed.
///
/// # Returns
/// * `Vec<u8>` - The resulting hash.
///
/// # Errors
/// * `ManticoreError::ShaError` - If the SHA operation fails.
#[cfg(target_os = "linux")]
pub(crate) fn sha(hash_algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, ManticoreError> {
    let hash_algorithm = match hash_algorithm {
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
        HashAlgorithm::Sha384 => MessageDigest::sha384(),
        HashAlgorithm::Sha512 => MessageDigest::sha512(),
    };

    let hash = openssl::hash::hash(hash_algorithm, data).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::ShaError
    })?;

    Ok((*hash).to_vec())
}

///  SHA operation.
///
/// # Arguments
/// * `hash_algorithm` - The SHA algorithm (SHA-1/ SHA-256/ SHA-384/ SHA-512) to be used.
/// * `data` - The data to be hashed.
///
/// # Returns
/// * `Vec<u8>` - The resulting hash.
///
/// # Errors
/// * `ManticoreError::ShaError` - If the SHA operation fails.
#[cfg(target_os = "windows")]
pub fn sha(hash_algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, ManticoreError> {
    let digest = match hash_algorithm {
        HashAlgorithm::Sha1 => hash::sha1(data).to_vec(),
        HashAlgorithm::Sha256 => hash::sha256(data).to_vec(),
        HashAlgorithm::Sha384 => hash::sha384(data).to_vec(),
        HashAlgorithm::Sha512 => hash::sha512(data).to_vec(),
    };
    Ok(digest)
}

/// Generic HMAC operation helper, OpenSSL implementation.
#[cfg(target_os = "linux")]
fn hmac_openssl<const N: usize>(
    key: &[u8],
    data: &[u8],
    expected_key_len: usize,
    md: &openssl::md::MdRef,
    algorithm_name: &str,
) -> Result<[u8; N], ManticoreError> {
    let handle_err = |openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        ManticoreError::HmacError
    };

    if key.len() != expected_key_len {
        tracing::error!(
            error=?ManticoreError::HmacError,
            key_len = key.len(),
            expected = expected_key_len,
            "Expected HMAC key size is {} bytes for {}",
            expected_key_len,
            algorithm_name
        );
        Err(ManticoreError::HmacError)?
    }

    let pkey = openssl::pkey::PKey::hmac(key).map_err(handle_err)?;
    let mut ctx = openssl::md_ctx::MdCtx::new().map_err(handle_err)?;

    ctx.digest_sign_init(Some(md), &pkey).map_err(handle_err)?;
    ctx.digest_sign_update(data).map_err(handle_err)?;

    let size = ctx.digest_sign_final(None).map_err(handle_err)?;
    if size != N {
        tracing::error!(
            error=?ManticoreError::HmacError,
            size,
            expected = N,
            "Expected HMAC size is {} for {}",
            N,
            algorithm_name
        );
        Err(ManticoreError::HmacError)?
    }

    let mut output = [0u8; N];
    ctx.digest_sign_final(Some(&mut output))
        .map_err(handle_err)?;

    Ok(output)
}

/// HMAC-SHA-384 operation, OpenSSL implementation.
#[cfg(target_os = "linux")]
pub fn hmac_sha_384(key: &[u8], data: &[u8]) -> Result<[u8; 48], ManticoreError> {
    hmac_openssl::<48>(key, data, 48, openssl::md::Md::sha384(), "HMAC-SHA-384")
}

/// HMAC-SHA-384 operation, SymCrypt implementation.
#[cfg(target_os = "windows")]
pub fn hmac_sha_384(key: &[u8], data: &[u8]) -> Result<[u8; 48], ManticoreError> {
    if key.len() != 48 {
        tracing::error!(error=?ManticoreError::HmacError, key_len = key.len(), "Expected HMAC key size is 48 bytes");
        Err(ManticoreError::HmacError)?
    }

    use symcrypt::hmac::hmac_sha384;
    hmac_sha384(key, data).map_err(|err| {
        tracing::error!(?err, "HMAC-SHA-384 operation failed");
        ManticoreError::HmacError
    })
}

/// HKDF-SHA-256 operation.
///
/// # Arguments
/// * `data` - Shared secret data to derive from
/// * `out_len` - Size of data to derive
///
/// # Returns
/// * `Vec<u8>` - The derivation result, with `out_len` length.
///
/// # Errors
/// * `ManticoreError::HkdfError` - If the HKDF operation fails.
pub fn hkdf_sha_256_derive(
    data: &[u8],
    _info: Option<&[u8]>,
    out_len: usize,
) -> Result<Vec<u8>, ManticoreError> {
    #[cfg(target_os = "linux")]
    {
        use openssl::md::Md;
        use openssl::pkey_ctx::HkdfMode;

        let info = _info.unwrap_or(&[]);

        let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::HkdfError
        })?;
        ctx.derive_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::HkdfError
        })?;

        ctx.set_hkdf_key(data).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::HkdfError
        })?;

        ctx.set_hkdf_md(Md::sha256())
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::HkdfError
            })?;

        ctx.add_hkdf_info(info).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            ManticoreError::HkdfError
        })?;

        ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::HkdfError
            })?;

        let mut out_vec = vec![0u8; out_len];
        ctx.derive(Some(&mut out_vec))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                ManticoreError::HkdfError
            })?;

        Ok(out_vec)
    }

    #[cfg(target_os = "windows")]
    {
        let result = hkdf(HmacAlgorithm::HmacSha256, data, &[], &[], out_len as u64).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                ManticoreError::HkdfError
            },
        )?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::*;

    #[test]
    fn test_sha() {
        const DATA: [u8; 1024] = [1u8; 1024];

        const EXPECTED_SHA1: [u8; 20] = [
            0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3,
            0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39,
        ];

        const EXPECTED_SHA256: [u8; 32] = [
            0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf,
            0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35,
            0x8e, 0xa5, 0x3a, 0x69,
        ];

        const EXPECTED_SHA384: [u8; 48] = [
            0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00,
            0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92,
            0xef, 0x9e, 0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a,
            0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7,
        ];

        const EXPECTED_SHA512: [u8; 64] = [
            0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9,
            0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d,
            0x94, 0x53, 0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda,
            0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb,
            0xde, 0x66, 0x15, 0x37, 0x5b, 0xab, 0x4a, 0xe8,
        ];

        let result = sha(HashAlgorithm::Sha1, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA1);

        let result = sha(HashAlgorithm::Sha256, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA256);

        let result = sha(HashAlgorithm::Sha384, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA384);

        let result = sha(HashAlgorithm::Sha512, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA512);
    }
}
