// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for SHA.

#[cfg(all(feature = "use-openssl", feature = "use-symcrypt"))]
compile_error!("OpenSSL and SymCrypt cannot be enabled at the same time.");

#[cfg(feature = "use-openssl")]
use openssl;
#[cfg(feature = "use-openssl")]
use openssl::error::ErrorStack;
#[cfg(feature = "use-openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "use-openssl")]
use openssl::pkey::Id;
#[cfg(feature = "use-openssl")]
use openssl::pkey_ctx::PkeyCtx;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hash;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hkdf::hkdf;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hmac::hmac_sha384;
#[cfg(feature = "use-symcrypt")]
use symcrypt::hmac::HmacAlgorithm;

use crate::CryptoError;

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
/// * `CryptoError::ShaError` - If the SHA operation fails.
#[cfg(feature = "use-openssl")]
pub fn sha(hash_algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let hash_algorithm = match hash_algorithm {
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
        HashAlgorithm::Sha384 => MessageDigest::sha384(),
        HashAlgorithm::Sha512 => MessageDigest::sha512(),
    };

    let hash = openssl::hash::hash(hash_algorithm, data).map_err(|openssl_error_stack| {
        tracing::error!(?openssl_error_stack);
        CryptoError::ShaError
    })?;

    Ok((*hash).to_vec())
}

#[cfg(feature = "use-symcrypt")]
pub fn sha(hash_algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest = match hash_algorithm {
        HashAlgorithm::Sha1 => hash::sha1(data).to_vec(),
        HashAlgorithm::Sha256 => hash::sha256(data).to_vec(),
        HashAlgorithm::Sha384 => hash::sha384(data).to_vec(),
        HashAlgorithm::Sha512 => hash::sha512(data).to_vec(),
    };
    Ok(digest)
}

/// HMAC-SHA-384 operation.
///
/// # Arguments
/// * `key` - A AES key or Secret of 48 bytes
/// * `data` - The data to be hashed.
///
/// # Returns
/// * `[u8; 48]` - The resulting hash.
///
/// # Errors
/// * `CryptoError::HmacError` - If the HMAC operation fails.
pub fn hmac_sha_384(key: &[u8], data: &[u8]) -> Result<[u8; 48], CryptoError> {
    #[cfg(feature = "use-openssl")]
    {
        let handle_err = |openssl_error_stack: ErrorStack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::HmacError
        };

        if key.len() != 48 {
            tracing::error!(error=?CryptoError::HmacError, key_len = key.len(), "Expected key size is 48 bytes");
            Err(CryptoError::HmacError)?
        }

        let pkey = openssl::pkey::PKey::hmac(key).map_err(handle_err)?;
        let mut ctx = openssl::md_ctx::MdCtx::new().map_err(handle_err)?;

        ctx.digest_sign_init(Some(openssl::md::Md::sha384()), &pkey)
            .map_err(handle_err)?;
        ctx.digest_sign_update(data).map_err(handle_err)?;

        let size = ctx.digest_sign_final(None).map_err(handle_err)?;
        if size != 48 {
            tracing::error!(error=?CryptoError::HmacError, size, "Expected HMAC size is 48");
            Err(CryptoError::HmacError)?
        }

        let mut output = [0u8; 48];
        ctx.digest_sign_final(Some(&mut output))
            .map_err(handle_err)?;

        Ok(output)
    }

    #[cfg(feature = "use-symcrypt")]
    {
        if key.len() != 48 {
            tracing::error!(error=?CryptoError::HmacError, key_len = key.len(), "Expected key size is 48 bytes");
            Err(CryptoError::HmacError)?
        }

        let result = hmac_sha384(key, data).map_err(|symcrypt_error_stack| {
            tracing::error!(?symcrypt_error_stack);
            CryptoError::HmacError
        })?;

        Ok(result)
    }
}

/// HKDF-SHA-384 operation.
///
/// # Arguments
/// * `data` - Shared secret data to derive from
/// * `out_len` - Size of data to derive
///
/// # Returns
/// * `Vec<u8>` - The derivation result, with `out_len` length.
///
/// # Errors
/// * `CryptoError::HkdfError` - If the HKDF operation fails.
pub fn hkdf_sha_384_derive(
    data: &[u8],
    info: Option<&[u8]>,
    out_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let info = info.unwrap_or(&[]);

    #[cfg(feature = "use-openssl")]
    {
        use openssl::md::Md;
        use openssl::pkey_ctx::HkdfMode;

        let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::HkdfError
        })?;
        ctx.derive_init().map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::HkdfError
        })?;

        ctx.set_hkdf_key(data).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::HkdfError
        })?;

        ctx.set_hkdf_md(Md::sha384())
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::HkdfError
            })?;

        ctx.add_hkdf_info(info).map_err(|openssl_error_stack| {
            tracing::error!(?openssl_error_stack);
            CryptoError::HkdfError
        })?;

        ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::HkdfError
            })?;

        let mut out_vec = vec![0u8; out_len];
        ctx.derive(Some(&mut out_vec))
            .map_err(|openssl_error_stack| {
                tracing::error!(?openssl_error_stack);
                CryptoError::HkdfError
            })?;

        Ok(out_vec)
    }

    #[cfg(feature = "use-symcrypt")]
    {
        if out_len == 0 {
            tracing::error!("Invalid output size.");
            Err(CryptoError::HkdfError)?
        }

        let result = hkdf(HmacAlgorithm::HmacSha384, data, &[], info, out_len as u64).map_err(
            |symcrypt_error_stack| {
                tracing::error!(?symcrypt_error_stack);
                CryptoError::HkdfError
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

    #[test]
    fn test_hmac_sha384() {
        const KEY: [u8; 48] = [1u8; 48];
        const DATA: [u8; 1024] = [1u8; 1024];
        const EXPECTED_HMAC: [u8; 48] = [
            173, 125, 173, 12, 111, 11, 155, 5, 125, 90, 139, 107, 53, 88, 105, 57, 252, 108, 30,
            67, 159, 132, 123, 115, 12, 79, 242, 183, 219, 134, 74, 165, 108, 187, 168, 103, 167,
            181, 239, 111, 127, 223, 95, 25, 79, 197, 164, 107,
        ];

        let result = hmac_sha_384(&KEY, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_HMAC);
    }

    #[test]
    fn test_hkdf_sha_384_derive() {
        const SHARED_SECRET: [u8; 48] = [1u8; 48];
        const INFO: [u8; 16] = [2u8; 16];
        const OUT_LEN: usize = 80;
        const EXPECTED_DERIVED: [u8; OUT_LEN] = [
            199, 203, 139, 203, 58, 62, 118, 93, 17, 98, 5, 53, 33, 105, 109, 91, 213, 8, 116, 119,
            77, 216, 104, 70, 62, 173, 208, 68, 214, 223, 36, 101, 228, 243, 65, 33, 233, 8, 61,
            236, 106, 52, 70, 121, 78, 164, 116, 84, 205, 254, 54, 201, 45, 186, 88, 57, 137, 69,
            40, 255, 127, 147, 97, 237, 35, 136, 123, 171, 10, 187, 66, 247, 204, 13, 45, 137, 215,
            239, 225, 76,
        ];

        let result = hkdf_sha_384_derive(&SHARED_SECRET[..], Some(&INFO[..]), OUT_LEN);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_DERIVED);
    }
}
