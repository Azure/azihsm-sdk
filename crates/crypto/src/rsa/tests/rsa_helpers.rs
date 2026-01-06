// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::hash::HashAlgo;

/// Checks if the given RSA modulus size in bytes is supported.
pub(crate) fn is_supported_rsa_modulus_size_bytes(size: usize) -> bool {
    matches!(size, 256 | 384 | 512)
}

/// Converts test vector hash algorithm enum to runtime Hash object.
impl From<TestHashAlgo> for HashAlgo {
    fn from(hash_algo: TestHashAlgo) -> Self {
        match hash_algo {
            TestHashAlgo::Sha1 => HashAlgo::sha1(),
            TestHashAlgo::Sha256 => HashAlgo::sha256(),
            TestHashAlgo::Sha384 => HashAlgo::sha384(),
            TestHashAlgo::Sha512 => HashAlgo::sha512(),
        }
    }
}
