// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod sha_ossl;

#[cfg(target_os = "windows")]
mod sha_cng;

pub(crate) use crate::CryptoError;

/// Supported hash algorithms (only SHA for now).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum HashAlgo {
    /// SHA-1
    Sha1,

    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,
}

impl HashAlgo {
    /// Returns the digest length in bytes for the given hash algorithm.
    pub fn hash_length(&self) -> usize {
        match self {
            HashAlgo::Sha1 => 20,
            HashAlgo::Sha256 => 32,
            HashAlgo::Sha384 => 48,
            HashAlgo::Sha512 => 64,
        }
    }
}
/// Hash context to maintain the hasher life time until finish is called.
pub trait HashContext {
    /// * `Hasher` - The type representing the internal hasher context. This type must be `Sized`.
    type Hasher: Sized;

    ///  SHA update hash with data.
    ///
    /// # Arguments
    /// * `hasher` - Initialized hasher context.
    /// * `data` - The data to be use to update the hash.
    ///
    /// # Returns
    /// * * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    ///  SHA retrieve final computed hash and deletes hasher, a new hash context
    /// must be initialized after calling finish
    ///
    /// # Arguments
    /// * `hasher` - Initialized hasher context.
    /// * `hash` - Final computed hash value.
    ///
    /// # Returns
    /// * * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn finish(self, hash: &mut [u8]) -> Result<(), CryptoError>;
}

/// Hash operations trait, for init and single hash function
pub trait HashOp {
    ///  Calculates Hash of the data.
    ///
    /// # Arguments
    /// * `data` - The data to be hashed.
    /// * `hash` - computed hash of the `data`
    /// # Returns
    /// * OK on success
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn hash(&self, data: &[u8], hash: &mut [u8]) -> Result<(), CryptoError>;

    ///  Initializes SHA Hasher and returns hasher context to update the data.
    ///
    /// # Returns
    /// * Hasher initialized with provided `hash_Algorithm`
    ///
    /// # Errors
    /// * `CryptoError::ShaError` - If the SHA operation fails.
    fn init(&self) -> Result<DigestContext, CryptoError>;
}

/// DigestContext holds the  hasher.
pub struct DigestContext {
    hasher: <Self as HashContext>::Hasher,
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test_log::test]
    fn test_digestop_digest_sha1() {
        //write unit tests
        const DATA: [u8; 1024] = [1u8; 1024];
        let mut actual_digest: [u8; 20] = [0; 20];
        const EXPECTED_DIGEST: [u8; 20] = [
            0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3,
            0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39,
        ];

        let result = HashAlgo::Sha1.hash(&DATA, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_sha256() {
        //write unit tests
        const DATA: [u8; 1024] = [1u8; 1024];
        let mut actual_digest: [u8; 32] = [0; 32];
        const EXPECTED_DIGEST: [u8; 32] = [
            0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf,
            0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35,
            0x8e, 0xa5, 0x3a, 0x69,
        ];

        let result = HashAlgo::Sha256.hash(&DATA, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_sha384() {
        //write unit tests
        const DATA: [u8; 1024] = [1u8; 1024];

        let mut actual_digest: [u8; 48] = [0; 48];
        const EXPECTED_DIGEST: [u8; 48] = [
            0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00,
            0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92,
            0xef, 0x9e, 0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a,
            0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7,
        ];

        let result = HashAlgo::Sha384.hash(&DATA, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_sha512() {
        //write unit tests
        const DATA: [u8; 1024] = [1u8; 1024];

        let mut actual_digest: [u8; 64] = [0; 64];
        const EXPECTED_DIGEST: [u8; 64] = [
            0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9,
            0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d,
            0x94, 0x53, 0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda,
            0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb,
            0xde, 0x66, 0x15, 0x37, 0x5b, 0xab, 0x4a, 0xe8,
        ];

        let result = HashAlgo::Sha512.hash(&DATA, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }

    #[test_log::test]
    fn test_digestop_digest_init_update_final_sha1() {
        const DATA: [u8; 1024] = [1u8; 1024];

        // SHA1
        let mut hash_context = HashAlgo::Sha1.init().expect("init sha1");
        hash_context
            .update(&DATA[..512])
            .expect("update sha1 part1");
        hash_context
            .update(&DATA[512..])
            .expect("update sha1 part2");
        let mut out = [0u8; 20];
        hash_context.finish(&mut out).expect("final sha1");
        assert_eq!(
            out,
            [
                0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3,
                0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39,
            ]
        );
    }

    #[test_log::test]
    fn test_digestop_digest_init_update_final_sha256() {
        const DATA: [u8; 1024] = [1u8; 1024];

        // SHA256
        let mut hash_context = HashAlgo::Sha256.init().expect("init sha256");
        hash_context
            .update(&DATA[..700])
            .expect("update sha256 part1");
        hash_context
            .update(&DATA[700..])
            .expect("update sha256 part2");
        let mut out = [0u8; 32];
        hash_context.finish(&mut out).expect("final sha256");
        assert_eq!(
            out,
            [
                0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf,
                0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35,
                0x8e, 0xa5, 0x3a, 0x69,
            ]
        );
    }

    #[test_log::test]
    fn test_digestop_digest_init_update_final_sha384() {
        const DATA: [u8; 1024] = [1u8; 1024];

        // SHA384
        let mut hasher = HashAlgo::Sha384.init().expect("init sha384");
        hasher.update(&DATA[..1000]).expect("update sha384 part1");
        hasher.update(&DATA[1000..]).expect("update sha384 part2");
        let mut out = [0u8; 48];
        hasher.finish(&mut out).expect("final sha384");
        assert_eq!(
            out,
            [
                0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00,
                0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92,
                0xef, 0x9e, 0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a,
                0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7,
            ]
        );
    }

    #[test_log::test]
    fn test_digestop_digest_init_update_final_sha512() {
        const DATA: [u8; 1024] = [1u8; 1024];

        // SHA512
        let mut hasher = HashAlgo::Sha512.init().expect("init sha512");
        hasher.update(&DATA[..256]).expect("update sha512 part1");
        hasher.update(&DATA[256..768]).expect("update sha512 part2");
        hasher.update(&DATA[768..]).expect("update sha512 part3");
        let mut out = [0u8; 64];
        hasher.finish(&mut out).expect("final sha512");
        assert_eq!(
            out,
            [
                0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9,
                0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d,
                0x94, 0x53, 0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda,
                0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb,
                0xde, 0x66, 0x15, 0x37, 0x5b, 0xab, 0x4a, 0xe8,
            ]
        );
    }

    #[test_log::test]
    fn test_digestop_digest_big_endian_data_sha1() {
        // 1024 bytes, filled with repeated 0x11223344 in big endian
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        let mut actual_digest = [0u8; 20];
        const EXPECTED_DIGEST: [u8; 20] = [
            0xa3, 0xfb, 0x5e, 0x21, 0x19, 0x18, 0xea, 0x79, 0x4b, 0x65, 0x4d, 0x83, 0xaf, 0xa5,
            0x33, 0x9a, 0x91, 0x11, 0x0e, 0xb7,
        ];

        let result = HashAlgo::Sha1.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_big_endian_data_sha256() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        let mut actual_digest = [0u8; 32];
        const EXPECTED_DIGEST: [u8; 32] = [
            0x39, 0x65, 0x3b, 0xb8, 0x6f, 0xe6, 0xb8, 0x19, 0xc7, 0xef, 0x49, 0x65, 0xd0, 0x79,
            0x7e, 0x22, 0x38, 0x7c, 0x7e, 0xd5, 0x6b, 0x75, 0x74, 0x7d, 0x48, 0x67, 0x23, 0x21,
            0x50, 0xbb, 0xb1, 0x9f,
        ];

        let result = HashAlgo::Sha256.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_big_endian_data_sha384() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        let mut actual_digest = [0u8; 48];
        const EXPECTED_DIGEST: [u8; 48] = [
            0x37, 0xe8, 0xc1, 0xb7, 0x8b, 0x12, 0x98, 0x2f, 0xcd, 0xaa, 0xb3, 0xee, 0x3d, 0x47,
            0x49, 0xf5, 0x6c, 0xca, 0x9c, 0xc5, 0x89, 0x89, 0xa6, 0x78, 0x2a, 0x92, 0xa0, 0x07,
            0x78, 0x1e, 0x0f, 0x0a, 0x1c, 0xde, 0x3e, 0x57, 0xde, 0xbf, 0xf5, 0x63, 0x35, 0xc6,
            0x96, 0xb9, 0x13, 0x3e, 0x50, 0x78,
        ];

        let result = HashAlgo::Sha384.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_big_endian_data_sha512() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        let mut actual_digest = [0u8; 64];
        const EXPECTED_DIGEST: [u8; 64] = [
            0x3a, 0x03, 0x78, 0xaa, 0x87, 0xa5, 0x3f, 0xb1, 0xf5, 0x32, 0x54, 0x89, 0xa3, 0x39,
            0x8b, 0x66, 0x22, 0x7b, 0xf0, 0x22, 0x97, 0xe3, 0x77, 0x24, 0xc2, 0x0b, 0x56, 0xab,
            0x98, 0xf8, 0x94, 0x23, 0x1c, 0x16, 0xc4, 0x0b, 0xeb, 0x65, 0x92, 0x32, 0xf0, 0x9e,
            0x5c, 0x09, 0xfe, 0xd4, 0xfd, 0xd8, 0x4b, 0xbe, 0xf6, 0xfd, 0x66, 0x15, 0x6d, 0xda,
            0x35, 0x21, 0xd4, 0xfc, 0xd9, 0xe5, 0x7d, 0xd9,
        ];

        let result = HashAlgo::Sha512.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }

    #[test_log::test]
    fn test_digestop_digest_little_endian_data_sha1() {
        // 1024 bytes, filled with repeated 0x11223344 in little endian
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        let mut actual_digest = [0u8; 20];
        const EXPECTED_DIGEST: [u8; 20] = [
            0x26, 0xc8, 0x9b, 0x67, 0x45, 0x17, 0xa9, 0xbc, 0xba, 0xc1, 0xc8, 0x63, 0x03, 0x72,
            0x23, 0x09, 0x10, 0xde, 0xb1, 0x6b,
        ];

        let result = HashAlgo::Sha1.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_little_endian_data_sha256() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        let mut actual_digest = [0u8; 32];
        const EXPECTED_DIGEST: [u8; 32] = [
            0xb7, 0x18, 0x62, 0x40, 0x77, 0xcb, 0xfb, 0x48, 0xd9, 0x4b, 0x16, 0xf8, 0xf6, 0xcd,
            0xc0, 0x61, 0x36, 0xed, 0x40, 0xbb, 0xb6, 0x8f, 0x97, 0xac, 0x71, 0x66, 0x35, 0x79,
            0xff, 0xe4, 0x31, 0xc1,
        ];

        let result = HashAlgo::Sha256.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_little_endian_data_sha384() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        let mut actual_digest = [0u8; 48];
        const EXPECTED_DIGEST: [u8; 48] = [
            0xd0, 0x1c, 0x87, 0x85, 0x28, 0x38, 0x39, 0x68, 0xc5, 0xc4, 0xbb, 0x32, 0x5e, 0x37,
            0x46, 0x4d, 0x4d, 0xe7, 0xfe, 0x96, 0x3d, 0x6b, 0x68, 0x55, 0xa8, 0x9e, 0x6a, 0xc0,
            0x58, 0xe9, 0x24, 0x56, 0x92, 0x8e, 0x33, 0xf8, 0x6d, 0x50, 0xdb, 0x8d, 0x06, 0xaf,
            0xe6, 0x72, 0x3c, 0xe7, 0x4b, 0x51,
        ];

        let result = HashAlgo::Sha384.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_little_endian_data_sha512() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        let mut actual_digest = [0u8; 64];
        const EXPECTED_DIGEST: [u8; 64] = [
            0x21, 0x42, 0x55, 0x85, 0xd3, 0x70, 0x67, 0x4e, 0x46, 0xe3, 0xa0, 0x6a, 0x65, 0xf5,
            0xc9, 0x3d, 0xeb, 0x2f, 0x4b, 0xc3, 0xf7, 0x30, 0xb1, 0x7b, 0x7f, 0xe3, 0x13, 0xa2,
            0x28, 0xd1, 0xba, 0xb6, 0xcd, 0x71, 0xa1, 0xa7, 0xc7, 0xa7, 0x3e, 0x5a, 0xca, 0x67,
            0x35, 0xb4, 0x4d, 0x0f, 0x26, 0xb7, 0xc5, 0x96, 0x12, 0x7f, 0x20, 0x5c, 0x34, 0x2f,
            0x4c, 0x06, 0x95, 0x64, 0x89, 0xd9, 0xf3, 0x6a,
        ];

        let result = HashAlgo::Sha512.hash(&data, &mut actual_digest);
        assert!(result.is_ok());
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_big_endian_data_sha1() {
        // 1024 bytes, filled with repeated 0x11223344 in big endian
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        const EXPECTED_DIGEST: [u8; 20] = [
            0xa3, 0xfb, 0x5e, 0x21, 0x19, 0x18, 0xea, 0x79, 0x4b, 0x65, 0x4d, 0x83, 0xaf, 0xa5,
            0x33, 0x9a, 0x91, 0x11, 0x0e, 0xb7,
        ];

        let mut hasher = HashAlgo::Sha1.init().expect("init sha1");
        hasher.update(&data[..512]).expect("update sha1 part1");
        hasher.update(&data[512..]).expect("update sha1 part2");
        let mut actual_digest = [0u8; 20];
        hasher.finish(&mut actual_digest).expect("final sha1");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_big_endian_data_sha256() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        const EXPECTED_DIGEST: [u8; 32] = [
            0x39, 0x65, 0x3b, 0xb8, 0x6f, 0xe6, 0xb8, 0x19, 0xc7, 0xef, 0x49, 0x65, 0xd0, 0x79,
            0x7e, 0x22, 0x38, 0x7c, 0x7e, 0xd5, 0x6b, 0x75, 0x74, 0x7d, 0x48, 0x67, 0x23, 0x21,
            0x50, 0xbb, 0xb1, 0x9f,
        ];

        let mut hasher = HashAlgo::Sha256.init().expect("init sha256");
        hasher.update(&data[..700]).expect("update sha256 part1");
        hasher.update(&data[700..]).expect("update sha256 part2");
        let mut actual_digest = [0u8; 32];
        hasher.finish(&mut actual_digest).expect("final sha256");

        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_big_endian_data_sha384() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        const EXPECTED_DIGEST: [u8; 48] = [
            0x37, 0xe8, 0xc1, 0xb7, 0x8b, 0x12, 0x98, 0x2f, 0xcd, 0xaa, 0xb3, 0xee, 0x3d, 0x47,
            0x49, 0xf5, 0x6c, 0xca, 0x9c, 0xc5, 0x89, 0x89, 0xa6, 0x78, 0x2a, 0x92, 0xa0, 0x07,
            0x78, 0x1e, 0x0f, 0x0a, 0x1c, 0xde, 0x3e, 0x57, 0xde, 0xbf, 0xf5, 0x63, 0x35, 0xc6,
            0x96, 0xb9, 0x13, 0x3e, 0x50, 0x78,
        ];

        let mut hasher = HashAlgo::Sha384.init().expect("init sha384");
        hasher.update(&data[..1000]).expect("update sha384 part1");
        hasher.update(&data[1000..]).expect("update sha384 part2");
        let mut actual_digest = [0u8; 48];
        hasher.finish(&mut actual_digest).expect("final sha384");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_big_endian_data_sha512() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_be_bytes());
        }

        const EXPECTED_DIGEST: [u8; 64] = [
            0x3a, 0x03, 0x78, 0xaa, 0x87, 0xa5, 0x3f, 0xb1, 0xf5, 0x32, 0x54, 0x89, 0xa3, 0x39,
            0x8b, 0x66, 0x22, 0x7b, 0xf0, 0x22, 0x97, 0xe3, 0x77, 0x24, 0xc2, 0x0b, 0x56, 0xab,
            0x98, 0xf8, 0x94, 0x23, 0x1c, 0x16, 0xc4, 0x0b, 0xeb, 0x65, 0x92, 0x32, 0xf0, 0x9e,
            0x5c, 0x09, 0xfe, 0xd4, 0xfd, 0xd8, 0x4b, 0xbe, 0xf6, 0xfd, 0x66, 0x15, 0x6d, 0xda,
            0x35, 0x21, 0xd4, 0xfc, 0xd9, 0xe5, 0x7d, 0xd9,
        ];

        let mut hasher = HashAlgo::Sha512.init().expect("init sha512");
        hasher.update(&data[..256]).expect("update sha512 part1");
        hasher.update(&data[256..768]).expect("update sha512 part2");
        hasher.update(&data[768..]).expect("update sha512 part3");
        let mut actual_digest = [0u8; 64];
        hasher.finish(&mut actual_digest).expect("final sha512");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_little_endian_data_sha1() {
        // 1024 bytes, filled with repeated 0x11223344 in little endian
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        const EXPECTED_DIGEST: [u8; 20] = [
            0x26, 0xc8, 0x9b, 0x67, 0x45, 0x17, 0xa9, 0xbc, 0xba, 0xc1, 0xc8, 0x63, 0x03, 0x72,
            0x23, 0x09, 0x10, 0xde, 0xb1, 0x6b,
        ];

        let mut hasher = HashAlgo::Sha1.init().expect("init sha1");
        hasher.update(&data[..512]).expect("update sha1 part1");
        hasher.update(&data[512..]).expect("update sha1 part2");
        let mut actual_digest = [0u8; 20];
        hasher.finish(&mut actual_digest).expect("final sha1");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_little_endian_data_sha256() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        const EXPECTED_DIGEST: [u8; 32] = [
            0xb7, 0x18, 0x62, 0x40, 0x77, 0xcb, 0xfb, 0x48, 0xd9, 0x4b, 0x16, 0xf8, 0xf6, 0xcd,
            0xc0, 0x61, 0x36, 0xed, 0x40, 0xbb, 0xb6, 0x8f, 0x97, 0xac, 0x71, 0x66, 0x35, 0x79,
            0xff, 0xe4, 0x31, 0xc1,
        ];

        let mut hasher = HashAlgo::Sha256.init().expect("init sha256");
        hasher.update(&data[..700]).expect("update sha256 part1");
        hasher.update(&data[700..]).expect("update sha256 part2");
        let mut actual_digest = [0u8; 32];
        hasher.finish(&mut actual_digest).expect("final sha256");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_little_endian_data_sha384() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        const EXPECTED_DIGEST: [u8; 48] = [
            0xd0, 0x1c, 0x87, 0x85, 0x28, 0x38, 0x39, 0x68, 0xc5, 0xc4, 0xbb, 0x32, 0x5e, 0x37,
            0x46, 0x4d, 0x4d, 0xe7, 0xfe, 0x96, 0x3d, 0x6b, 0x68, 0x55, 0xa8, 0x9e, 0x6a, 0xc0,
            0x58, 0xe9, 0x24, 0x56, 0x92, 0x8e, 0x33, 0xf8, 0x6d, 0x50, 0xdb, 0x8d, 0x06, 0xaf,
            0xe6, 0x72, 0x3c, 0xe7, 0x4b, 0x51,
        ];

        let mut hasher = HashAlgo::Sha384.init().expect("init sha384");
        hasher.update(&data[..1000]).expect("update sha384 part1");
        hasher.update(&data[1000..]).expect("update sha384 part2");
        let mut actual_digest = [0u8; 48];
        hasher.finish(&mut actual_digest).expect("final sha384");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }
    #[test_log::test]
    fn test_digestop_digest_init_update_final_little_endian_data_sha512() {
        let mut data = [0u8; 1024];
        for i in 0..(1024 / 4) {
            data[i * 4..i * 4 + 4].copy_from_slice(&0x11223344u32.to_le_bytes());
        }

        const EXPECTED_DIGEST: [u8; 64] = [
            0x21, 0x42, 0x55, 0x85, 0xd3, 0x70, 0x67, 0x4e, 0x46, 0xe3, 0xa0, 0x6a, 0x65, 0xf5,
            0xc9, 0x3d, 0xeb, 0x2f, 0x4b, 0xc3, 0xf7, 0x30, 0xb1, 0x7b, 0x7f, 0xe3, 0x13, 0xa2,
            0x28, 0xd1, 0xba, 0xb6, 0xcd, 0x71, 0xa1, 0xa7, 0xc7, 0xa7, 0x3e, 0x5a, 0xca, 0x67,
            0x35, 0xb4, 0x4d, 0x0f, 0x26, 0xb7, 0xc5, 0x96, 0x12, 0x7f, 0x20, 0x5c, 0x34, 0x2f,
            0x4c, 0x06, 0x95, 0x64, 0x89, 0xd9, 0xf3, 0x6a,
        ];

        let mut hasher = HashAlgo::Sha512.init().expect("init sha512");
        hasher.update(&data[..256]).expect("update sha512 part1");
        hasher.update(&data[256..768]).expect("update sha512 part2");
        hasher.update(&data[768..]).expect("update sha512 part3");
        let mut actual_digest = [0u8; 64];
        hasher.finish(&mut actual_digest).expect("final sha512");
        assert_eq!(actual_digest, EXPECTED_DIGEST);
    }

    #[test_log::test]
    #[ignore = "This test simulates a stress testing, and takes more than 60 sec"]
    fn test_digestop_digest_init_update_final_little_endian_data_sha512_stress() {
        for i in 0..60000 {
            println!("Iteration: {}", i);
            let result = std::panic::catch_unwind(|| {
                test_digestop_digest_init_update_final_little_endian_data_sha512();
            });
            if result.is_err() {
                panic!("Failed at iteration 512sha {}", i);
            }
            let result = std::panic::catch_unwind(|| {
                test_digestop_digest_init_update_final_little_endian_data_sha1();
            });
            if result.is_err() {
                panic!("Failed at iteration sha1 {}", i);
            }
        }
    }
}
