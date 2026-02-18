// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod testvectors;

mod sha1_tests;
mod sha256_tests;
mod sha384_tests;
mod sha512_tests;

pub(crate) use testvectors::*;

use super::*;

/// SHA NIST Test vector struct
pub struct ShaTestVector {
    pub msg_len_bytes: u32,
    pub msg: &'static [u8],
    pub md_len_bytes: u32,
    pub md: &'static [u8],
}

// SHA NIST Test vector for monte carlo tests
pub struct ShaMonteTestVector {
    pub expected_digest_len_bytes: usize,
    pub seed: &'static [u8],
    pub expected_digests: [&'static [u8]; 100],
}
