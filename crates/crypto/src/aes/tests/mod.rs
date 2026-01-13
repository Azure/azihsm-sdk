// Copyright (C) Microsoft Corporation. All rights reserved.

mod testvectors;

// mod cbc_tests;
mod cbc_tests_helper;
mod cbc_tests_nist_gf_sbox;
mod cbc_tests_nist_mct;
mod cbc_tests_nist_mmt;
mod cbc_tests_nist_sbox;
mod cbc_tests_nist_varkey;
mod cbc_tests_nist_vartxt;
mod ecb_tests;
mod gcm_tests;
mod kw_tests;
mod kwp_tests;
mod xts_tests;

use super::*;

/// Aes CBC Test vector struct
pub struct AesCbcTestVector {
    pub test_count_id: u32,
    pub encrypt: bool,
    pub key: &'static [u8],
    pub iv: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}
/// AES XTS Test vector struct
#[derive(Debug)]
pub struct AesXtsTestVector {
    pub test_count_id: u32,
    pub key: &'static [u8],
    pub tweak: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
    pub encrypt: bool, // true=encrypt, false=decrypt
}
