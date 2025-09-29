// Copyright (C) Microsoft Corporation. All rights reserved.

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        type DdiTest = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        type DdiTest = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        type DdiTest = mcr_ddi_win::DdiWin;
    }
}

mod aes;
mod aes_gcm;
mod aes_xts;
mod app_session;
mod attest_key;
mod cli;
mod common;
mod consts;
mod delete_key;
mod derive;
mod ecc;
mod get_certificate;
mod no_session;
mod open_key;
mod post_process;
mod rsa;
mod rsa_unwrap;

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use circular_queue::CircularQueue;
use clap::*;
use glob::glob;
use indicatif::ProgressBar;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use parking_lot::RwLock;
use quantogram::Quantogram;
use rand::distributions::Distribution;
use rand::prelude::*;
use rand_distr::WeightedAliasIndex;

use crate::aes::*;
use crate::aes_gcm::*;
use crate::aes_xts::*;
use crate::app_session::*;
use crate::attest_key::*;
use crate::cli::*;
use crate::common::*;
use crate::consts::*;
use crate::delete_key::*;
use crate::derive::*;
use crate::ecc::*;
use crate::get_certificate::*;
use crate::no_session::*;
use crate::open_key::*;
use crate::post_process::*;
use crate::rsa::*;
use crate::rsa_unwrap::*;

#[derive(Debug, Clone)]
struct DataBlob {
    data: [u8; 3072],
    len: usize,
}

#[derive(Debug, Clone)]
struct PerfMixRatios {
    /// Ratio of Get API Revision operations
    get_api_rev: u16,

    /// Ratio of ECC Sign 256 operations
    ecc_sign_256: u16,

    /// Ratio of ECC Sign 384 operations
    ecc_sign_384: u16,

    /// Ratio of ECC Sign 521 operations
    ecc_sign_521: u16,

    /// Ratio of RSA 2K Modular Exponentiation operations
    rsa_mod_exp_2k: u16,

    /// Ratio of RSA 3K Modular Exponentiation operations
    rsa_mod_exp_3k: u16,

    /// Ratio of RSA 4K Modular Exponentiation operations
    rsa_mod_exp_4k: u16,

    /// Ratio of RSA 2K CRT Modular Exponentiation operations
    rsa_mod_exp_crt_2k: u16,

    /// Ratio of RSA 3K CRT Modular Exponentiation operations
    rsa_mod_exp_crt_3k: u16,

    /// Ratio of RSA 4K CRT Modular Exponentiation operations
    rsa_mod_exp_crt_4k: u16,

    /// Ratio of AES-CBC 128 Encrypt operations
    aes_cbc_128_encrypt: u16,

    /// Ratio of AES-CBC 128 Decrypt operations
    aes_cbc_128_decrypt: u16,

    /// Ratio of AES-CBC 192 Encrypt operations
    aes_cbc_192_encrypt: u16,

    /// Ratio of AES-CBC 192 Decrypt operations
    aes_cbc_192_decrypt: u16,

    /// Ratio of AES-CBC 256 Encrypt operations
    aes_cbc_256_encrypt: u16,

    /// Ratio of AES-CBC 256 Decrypt operations
    aes_cbc_256_decrypt: u16,

    /// Ratio of AES GCM Encrypt operations for data size 4k
    aes_gcm_encrypt_4k: u16,

    /// Ratio of AES GCM Encrypt operations for data size 16m
    aes_gcm_encrypt_16m: u16,

    /// Ratio of AES XTS Encrypt operations for data size 4k
    aes_xts_encrypt_4k: u16,

    /// Ratio of AES XTS Encrypt operations for data size 16m
    aes_xts_encrypt_16m: u16,

    /// Ratio of AES GCM Decrypt operations for data size 4k
    aes_gcm_decrypt_4k: u16,

    /// Ratio of AES GCM Decrypt operations for data size 16m
    aes_gcm_decrypt_16m: u16,

    /// Ratio of AES XTS Decrypt operations for data size 4k
    aes_xts_decrypt_4k: u16,

    /// Ratio of AES XTS Decrypt operations for data size 16m
    aes_xts_decrypt_16m: u16,

    /// Ratio of AES-CBC 128 generate delete operations
    aes_cbc_128_generate_and_delete: u16,

    /// Ratio of AES-CBC 192 generate delete operations
    aes_cbc_192_generate_and_delete: u16,

    /// Ratio of AES-CBC 256 generate delete operations
    aes_cbc_256_generate_and_delete: u16,

    /// Ratio of ECDH 256 Derive operations
    ecdh_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    ecdh_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    ecdh_derive_521_and_delete: u16,

    /// Ratio of HKDF 256 Derive operations
    hkdf_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    hkdf_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    hkdf_derive_521_and_delete: u16,

    /// Ratio of HKDF 256 Derive operations
    kbkdf_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    kbkdf_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    kbkdf_derive_521_and_delete: u16,

    /// Ratio of ECC 256 generate delete operations
    ecc_256_generate_and_delete: u16,

    /// Ratio of ECC 384 generate delete operations
    ecc_384_generate_and_delete: u16,

    /// Ratio of ECC 521 generate delete operations
    ecc_521_generate_and_delete: u16,

    /// Ratio of RSA 2K rsa_unwrap delete operation
    rsa_unwrap_rsa_2k_and_delete: u16,

    /// Ratio of RSA 3K rsa_unwrap delete operation
    rsa_unwrap_rsa_3k_and_delete: u16,

    /// Ratio of RSA 4K rsa_unwrap delete operation
    rsa_unwrap_rsa_4k_and_delete: u16,

    /// Ratio of RSA 2K CRT rsa_unwrap delete operation
    rsa_unwrap_rsa_crt_2k_and_delete: u16,

    /// Ratio of RSA 3K CRT rsa_unwrap delete operation
    rsa_unwrap_rsa_crt_3k_and_delete: u16,

    /// Ratio of RSA 4K CRT rsa_unwrap delete operation
    rsa_unwrap_rsa_crt_4k_and_delete: u16,

    /// Ratio of AES CBC 128 rsa_unwrap delete operation
    rsa_unwrap_aes_cbc_128_and_delete: u16,

    /// Ratio of AES CBC 192 rsa_unwrap delete operation
    rsa_unwrap_aes_cbc_192_and_delete: u16,

    /// Ratio of AES CBC 256 rsa_unwrap delete operation
    rsa_unwrap_aes_cbc_256_and_delete: u16,

    /// Ratio of ECC 256 rsa_unwrap delete operation
    rsa_unwrap_ecc_256_and_delete: u16,

    /// Ratio of ECC 384 rsa_unwrap delete operation
    rsa_unwrap_ecc_384_and_delete: u16,

    /// Ratio of ECC 521 rsa_unwrap delete operation
    rsa_unwrap_ecc_521_and_delete: u16,

    /// Ratio of secret 256 rsa_unwrap delete operation
    rsa_unwrap_secret_256_and_delete: u16,

    /// Ratio of secret 384 rsa_unwrap delete operation
    rsa_unwrap_secret_384_and_delete: u16,

    /// Ratio of secret 521 rsa_unwrap delete operation
    rsa_unwrap_secret_521_and_delete: u16,

    /// Ratio of AES-CBC 192 OpenKey operations
    aes_cbc_192_open_key: u16,

    /// Ratio of AES XTS Bulk 256 OpenKey operations
    aes_xts_bulk_256_open_key: u16,

    /// Ratio of RSA 4K No CRT OpenKey operations
    rsa_4k_open_key: u16,

    /// Ratio of RSA 4K CRT OpenKey operations
    rsa_4k_crt_open_key: u16,

    /// Ratio of ECC 521 OpenKey operations
    ecc_521_open_key: u16,

    /// Ratio of ECC 521 Attest Key operations
    ecc_521_attest_key: u16,

    /// Ratio of RSA 4k Attest Key operations
    rsa_4k_attest_key: u16,

    /// Ratio of RSA 4k CRT Attest Key operations
    rsa_4k_crt_attest_key: u16,

    /// Ratio of Manager Session Open and Close operations
    open_manager_session_and_close: u16,

    /// Ratio of Application Session Open and Close operations
    open_app_session_and_close: u16,

    /// Ratio of App Create and Delete operations
    create_app_and_delete: u16,

    /// Ratio of Get Certificate Chain operations
    get_cert_chain: u16,

    /// Ratio of Get Unwrapping Key operations
    get_unwrapping_key: u16,

    /// Ratio of Get Device Info operations
    get_device_info: u16,
}

#[derive(Debug, Clone)]
struct PerfMixKeys {
    /// Key ID for ECC Sign 256
    key_id_ecc_sign_256: u16,

    /// Key ID for ECC Sign 384
    key_id_ecc_sign_384: u16,

    /// Key ID for ECC Sign 521
    key_id_ecc_sign_521: u16,

    /// Key ID for RSA 2K Modular Exponentiation
    key_id_rsa_mod_exp_2k: u16,

    /// Key ID for RSA 3K Modular Exponentiation
    key_id_rsa_mod_exp_3k: u16,

    /// Key ID for RSA 4K Modular Exponentiation
    key_id_rsa_mod_exp_4k: u16,

    /// Key ID for RSA 2K CRT Modular Exponentiation
    key_id_rsa_mod_exp_crt_2k: u16,

    /// Key ID for RSA 3K CRT Modular Exponentiation
    key_id_rsa_mod_exp_crt_3k: u16,

    /// Key ID for RSA 4K CRT Modular Exponentiation
    key_id_rsa_mod_exp_crt_4k: u16,

    /// Key ID for AES-CBC 128
    key_id_aes_cbc_128: u16,

    /// Key ID for AES-CBC 192
    key_id_aes_cbc_192: u16,

    /// Key ID for AES-CBC 256
    key_id_aes_cbc_256: u16,

    /// Key ID for AES GCM Bulk 256
    key_id_aes_gcm_bulk_256: u16,

    /// Key ID for first key of type AES XTS Bulk 256
    key_id_aes_xts_bulk_256: u16,

    /// Key ID for second key of type AES XTS Bulk 256
    key_id_aes_xts_bulk_256_2: u16,

    /// Key ID for ECDH 256
    key_id_ecc_derive_256: u16,

    /// Key ID for ECDH 384
    key_id_ecc_derive_384: u16,

    /// Key ID for ECDH 521
    key_id_ecc_derive_521: u16,

    /// Key ID for Secret 256
    key_id_secret_256: u16,

    /// Key ID for Secret 384
    key_id_secret_384: u16,

    /// Key ID for Secret 521
    key_id_secret_521: u16,

    /// Key ID for wrapping
    key_id_wrapping_key: u16,

    /// Encrypted data for GCM decrypt with 4k size
    encrypted_data_gcm_4k: Option<[u8; 1024 * 4]>,

    /// Tag for GCM encrypted data with 4k size
    tag_gcm_4k: Option<[u8; 16usize]>,

    /// Encrypted data for GCM decrypt with 16m size
    encrypted_data_gcm_16m: Option<Box<[u8]>>,

    /// Tag for GCM encrypted data with 16m size
    tag_gcm_16m: Option<[u8; 16usize]>,

    // Wrapped blobs
    /// Wrapped blob for ECC Sign 256
    wrapped_blob_ecc_sign_256: DataBlob,

    /// Wrapped blob for ECC Sign 384
    wrapped_blob_ecc_sign_384: DataBlob,

    /// Wrapped blob for ECC Sign 521
    wrapped_blob_ecc_sign_521: DataBlob,

    /// Wrapped blob for RSA 2K
    wrapped_blob_rsa_2k: DataBlob,

    /// Wrapped blob for RSA 3K
    wrapped_blob_rsa_3k: DataBlob,

    /// Wrapped blob for RSA 4K
    wrapped_blob_rsa_4k: DataBlob,

    /// Wrapped blob for RSA 2K CRT
    wrapped_blob_rsa_crt_2k: DataBlob,

    /// Wrapped blob for RSA 3K CRT
    wrapped_blob_rsa_crt_3k: DataBlob,

    /// Wrapped blob for RSA 4K CRT
    wrapped_blob_rsa_crt_4k: DataBlob,

    /// Wrapped blob for AES-CBC 128
    wrapped_blob_aes_cbc_128: DataBlob,

    /// Wrapped blob for AES-CBC 192
    wrapped_blob_aes_cbc_192: DataBlob,

    /// Wrapped blob for AES-CBC 256
    wrapped_blob_aes_cbc_256: DataBlob,

    /// Wrapped blob for Secret 256
    wrapped_blob_secret_256: DataBlob,

    /// Wrapped blob for Secret 384
    wrapped_blob_secret_384: DataBlob,

    /// Wrapped blob for Secret 521
    wrapped_blob_secret_521: DataBlob,
}

#[derive(Debug, Clone)]
struct PerfMixArguments {
    /// App Session ID
    app_sess_id: Option<u16>,

    /// Short App ID
    short_app_id: Option<u8>,

    /// Skip App Session Create (Useful for testing open app/ manager session commands)
    skip_app_session_create: bool,

    /// Stabilization time in seconds
    stabilize_seconds: u64,

    /// Number of seconds to run performance test
    test_seconds: u64,

    /// Per request time queue size
    prt_queue_length: usize,

    /// Keys for performance mix
    keys: PerfMixKeys,

    /// Ratio of operations
    ratios: PerfMixRatios,
}

impl From<PerfMix> for PerfMixRatios {
    fn from(mix: PerfMix) -> Self {
        match mix {
            PerfMix::Custom(args) => Self {
                get_api_rev: args.get_api_rev,
                ecc_sign_256: args.ecc_sign_256,
                ecc_sign_384: args.ecc_sign_384,
                ecc_sign_521: args.ecc_sign_521,
                rsa_mod_exp_2k: args.rsa_mod_exp_2k,
                rsa_mod_exp_3k: args.rsa_mod_exp_3k,
                rsa_mod_exp_4k: args.rsa_mod_exp_4k,
                rsa_mod_exp_crt_2k: args.rsa_mod_exp_crt_2k,
                rsa_mod_exp_crt_3k: args.rsa_mod_exp_crt_3k,
                rsa_mod_exp_crt_4k: args.rsa_mod_exp_crt_4k,
                aes_cbc_128_encrypt: args.aes_cbc_128_encrypt,
                aes_cbc_128_decrypt: args.aes_cbc_128_decrypt,
                aes_cbc_192_encrypt: args.aes_cbc_192_encrypt,
                aes_cbc_192_decrypt: args.aes_cbc_192_decrypt,
                aes_cbc_256_encrypt: args.aes_cbc_256_encrypt,
                aes_cbc_256_decrypt: args.aes_cbc_256_decrypt,
                aes_gcm_encrypt_4k: args.aes_gcm_encrypt_4k,
                aes_gcm_encrypt_16m: args.aes_gcm_encrypt_16m,
                aes_xts_encrypt_4k: args.aes_xts_encrypt_4k,
                aes_xts_encrypt_16m: args.aes_xts_encrypt_16m,
                aes_gcm_decrypt_4k: args.aes_gcm_decrypt_4k,
                aes_gcm_decrypt_16m: args.aes_gcm_decrypt_16m,
                aes_xts_decrypt_4k: args.aes_xts_decrypt_4k,
                aes_xts_decrypt_16m: args.aes_xts_decrypt_16m,
                aes_cbc_128_generate_and_delete: args.aes_cbc_128_generate_and_delete,
                aes_cbc_192_generate_and_delete: args.aes_cbc_192_generate_and_delete,
                aes_cbc_256_generate_and_delete: args.aes_cbc_256_generate_and_delete,
                ecdh_derive_256_and_delete: args.ecdh_derive_256_and_delete,
                ecdh_derive_384_and_delete: args.ecdh_derive_384_and_delete,
                ecdh_derive_521_and_delete: args.ecdh_derive_521_and_delete,
                hkdf_derive_256_and_delete: args.hkdf_derive_256_and_delete,
                hkdf_derive_384_and_delete: args.hkdf_derive_384_and_delete,
                hkdf_derive_521_and_delete: args.hkdf_derive_521_and_delete,
                kbkdf_derive_256_and_delete: args.kbkdf_derive_256_and_delete,
                kbkdf_derive_384_and_delete: args.kbkdf_derive_384_and_delete,
                kbkdf_derive_521_and_delete: args.kbkdf_derive_521_and_delete,
                ecc_256_generate_and_delete: args.ecc_256_generate_and_delete,
                ecc_384_generate_and_delete: args.ecc_384_generate_and_delete,
                ecc_521_generate_and_delete: args.ecc_521_generate_and_delete,
                rsa_unwrap_rsa_2k_and_delete: args.rsa_unwrap_rsa_2k_and_delete,
                rsa_unwrap_rsa_3k_and_delete: args.rsa_unwrap_rsa_3k_and_delete,
                rsa_unwrap_rsa_4k_and_delete: args.rsa_unwrap_rsa_4k_and_delete,
                rsa_unwrap_rsa_crt_2k_and_delete: args.rsa_unwrap_rsa_crt_2k_and_delete,
                rsa_unwrap_rsa_crt_3k_and_delete: args.rsa_unwrap_rsa_crt_3k_and_delete,
                rsa_unwrap_rsa_crt_4k_and_delete: args.rsa_unwrap_rsa_crt_4k_and_delete,
                rsa_unwrap_aes_cbc_128_and_delete: args.rsa_unwrap_aes_cbc_128_and_delete,
                rsa_unwrap_aes_cbc_192_and_delete: args.rsa_unwrap_aes_cbc_192_and_delete,
                rsa_unwrap_aes_cbc_256_and_delete: args.rsa_unwrap_aes_cbc_256_and_delete,
                rsa_unwrap_ecc_256_and_delete: args.rsa_unwrap_ecc_256_and_delete,
                rsa_unwrap_ecc_384_and_delete: args.rsa_unwrap_ecc_384_and_delete,
                rsa_unwrap_ecc_521_and_delete: args.rsa_unwrap_ecc_521_and_delete,
                rsa_unwrap_secret_256_and_delete: args.rsa_unwrap_secret_256_and_delete,
                rsa_unwrap_secret_384_and_delete: args.rsa_unwrap_secret_384_and_delete,
                rsa_unwrap_secret_521_and_delete: args.rsa_unwrap_secret_521_and_delete,
                aes_cbc_192_open_key: args.aes_cbc_192_open_key,
                aes_xts_bulk_256_open_key: args.aes_xts_bulk_256_open_key,
                rsa_4k_open_key: args.rsa_4k_open_key,
                rsa_4k_crt_open_key: args.rsa_4k_crt_open_key,
                ecc_521_open_key: args.ecc_521_open_key,
                ecc_521_attest_key: args.ecc_521_attest_key,
                rsa_4k_attest_key: args.rsa_4k_attest_key,
                rsa_4k_crt_attest_key: args.rsa_4k_crt_attest_key,
                open_manager_session_and_close: args.open_manager_session_and_close,
                open_app_session_and_close: args.open_app_session_and_close,
                create_app_and_delete: args.create_app_and_delete,
                get_cert_chain: args.get_cert_chain,
                get_unwrapping_key: args.get_unwrapping_key,
                get_device_info: args.get_device_info,
            },
            PerfMix::PreMix(args) => match args.pre_mix {
                PreMix::GetApiRevOnly => Self {
                    get_api_rev: 100,
                    ecc_sign_256: 0,
                    ecc_sign_384: 0,
                    ecc_sign_521: 0,
                    rsa_mod_exp_2k: 0,
                    rsa_mod_exp_3k: 0,
                    rsa_mod_exp_4k: 0,
                    rsa_mod_exp_crt_2k: 0,
                    rsa_mod_exp_crt_3k: 0,
                    rsa_mod_exp_crt_4k: 0,
                    aes_cbc_128_encrypt: 0,
                    aes_cbc_128_decrypt: 0,
                    aes_cbc_192_encrypt: 0,
                    aes_cbc_192_decrypt: 0,
                    aes_cbc_256_encrypt: 0,
                    aes_cbc_256_decrypt: 0,
                    aes_gcm_encrypt_4k: 0,
                    aes_gcm_encrypt_16m: 0,
                    aes_xts_encrypt_4k: 0,
                    aes_xts_encrypt_16m: 0,
                    aes_gcm_decrypt_4k: 0,
                    aes_gcm_decrypt_16m: 0,
                    aes_xts_decrypt_4k: 0,
                    aes_xts_decrypt_16m: 0,
                    aes_cbc_128_generate_and_delete: 0,
                    aes_cbc_192_generate_and_delete: 0,
                    aes_cbc_256_generate_and_delete: 0,
                    ecdh_derive_256_and_delete: 0,
                    ecdh_derive_384_and_delete: 0,
                    ecdh_derive_521_and_delete: 0,
                    hkdf_derive_256_and_delete: 0,
                    hkdf_derive_384_and_delete: 0,
                    hkdf_derive_521_and_delete: 0,
                    kbkdf_derive_256_and_delete: 0,
                    kbkdf_derive_384_and_delete: 0,
                    kbkdf_derive_521_and_delete: 0,
                    ecc_256_generate_and_delete: 0,
                    ecc_384_generate_and_delete: 0,
                    ecc_521_generate_and_delete: 0,
                    rsa_unwrap_rsa_2k_and_delete: 0,
                    rsa_unwrap_rsa_3k_and_delete: 0,
                    rsa_unwrap_rsa_4k_and_delete: 0,
                    rsa_unwrap_rsa_crt_2k_and_delete: 0,
                    rsa_unwrap_rsa_crt_3k_and_delete: 0,
                    rsa_unwrap_rsa_crt_4k_and_delete: 0,
                    rsa_unwrap_aes_cbc_128_and_delete: 0,
                    rsa_unwrap_aes_cbc_192_and_delete: 0,
                    rsa_unwrap_aes_cbc_256_and_delete: 0,
                    rsa_unwrap_ecc_256_and_delete: 0,
                    rsa_unwrap_ecc_384_and_delete: 0,
                    rsa_unwrap_ecc_521_and_delete: 0,
                    rsa_unwrap_secret_256_and_delete: 0,
                    rsa_unwrap_secret_384_and_delete: 0,
                    rsa_unwrap_secret_521_and_delete: 0,
                    aes_cbc_192_open_key: 0,
                    aes_xts_bulk_256_open_key: 0,
                    rsa_4k_open_key: 0,
                    rsa_4k_crt_open_key: 0,
                    ecc_521_open_key: 0,
                    ecc_521_attest_key: 0,
                    rsa_4k_attest_key: 0,
                    rsa_4k_crt_attest_key: 0,
                    open_manager_session_and_close: 0,
                    open_app_session_and_close: 0,
                    create_app_and_delete: 0,
                    get_cert_chain: 0,
                    get_unwrapping_key: 0,
                    get_device_info: 0,
                },
                PreMix::AllEqual => Self {
                    get_api_rev: 100,
                    ecc_sign_256: 100,
                    ecc_sign_384: 100,
                    ecc_sign_521: 100,
                    rsa_mod_exp_2k: 100,
                    rsa_mod_exp_3k: 100,
                    rsa_mod_exp_4k: 100,
                    rsa_mod_exp_crt_2k: 100,
                    rsa_mod_exp_crt_3k: 100,
                    rsa_mod_exp_crt_4k: 100,
                    aes_cbc_128_encrypt: 100,
                    aes_cbc_128_decrypt: 100,
                    aes_cbc_192_encrypt: 100,
                    aes_cbc_192_decrypt: 100,
                    aes_cbc_256_encrypt: 100,
                    aes_cbc_256_decrypt: 100,
                    aes_gcm_encrypt_4k: 100,
                    aes_gcm_encrypt_16m: 100,
                    aes_xts_encrypt_4k: 100,
                    aes_xts_encrypt_16m: 100,
                    aes_gcm_decrypt_4k: 100,
                    aes_gcm_decrypt_16m: 100,
                    aes_xts_decrypt_4k: 100,
                    aes_xts_decrypt_16m: 100,
                    aes_cbc_128_generate_and_delete: 100,
                    aes_cbc_192_generate_and_delete: 100,
                    aes_cbc_256_generate_and_delete: 100,
                    ecdh_derive_256_and_delete: 100,
                    ecdh_derive_384_and_delete: 100,
                    ecdh_derive_521_and_delete: 100,
                    hkdf_derive_256_and_delete: 100,
                    hkdf_derive_384_and_delete: 100,
                    hkdf_derive_521_and_delete: 100,
                    kbkdf_derive_256_and_delete: 100,
                    kbkdf_derive_384_and_delete: 100,
                    kbkdf_derive_521_and_delete: 100,
                    ecc_256_generate_and_delete: 100,
                    ecc_384_generate_and_delete: 100,
                    ecc_521_generate_and_delete: 100,
                    rsa_unwrap_rsa_2k_and_delete: 100,
                    rsa_unwrap_rsa_3k_and_delete: 100,
                    rsa_unwrap_rsa_4k_and_delete: 100,
                    rsa_unwrap_rsa_crt_2k_and_delete: 100,
                    rsa_unwrap_rsa_crt_3k_and_delete: 100,
                    rsa_unwrap_rsa_crt_4k_and_delete: 100,
                    rsa_unwrap_aes_cbc_128_and_delete: 100,
                    rsa_unwrap_aes_cbc_192_and_delete: 100,
                    rsa_unwrap_aes_cbc_256_and_delete: 100,
                    rsa_unwrap_ecc_256_and_delete: 100,
                    rsa_unwrap_ecc_384_and_delete: 100,
                    rsa_unwrap_ecc_521_and_delete: 100,
                    rsa_unwrap_secret_256_and_delete: 100,
                    rsa_unwrap_secret_384_and_delete: 100,
                    rsa_unwrap_secret_521_and_delete: 100,
                    aes_cbc_192_open_key: 100,
                    aes_xts_bulk_256_open_key: 100,
                    rsa_4k_open_key: 100,
                    rsa_4k_crt_open_key: 100,
                    ecc_521_open_key: 100,
                    ecc_521_attest_key: 100,
                    rsa_4k_attest_key: 100,
                    rsa_4k_crt_attest_key: 100,
                    open_manager_session_and_close: 0, // 0 because this must be tested solo
                    open_app_session_and_close: 0,     // 0 because this must be tested solo
                    create_app_and_delete: 0,          // 0 because this must be tested solo
                    get_cert_chain: 100,
                    get_unwrapping_key: 100,
                    get_device_info: 100,
                },
            },
        }
    }
}

fn main() {
    helper_print_banner();

    let cli_args = CliArgs::parse();

    match cli_args.command {
        CliCommand::Perf(perf_args) => command_perf(perf_args),
        CliCommand::BulkPostProcess(bulk_post_process_args) => {
            command_bulk_post_process(bulk_post_process_args)
        }
    }
}

fn command_perf(perf_args: PerfArgs) {
    let ddi = DdiTest::default();
    let mut devices = ddi.dev_info_list();
    devices.sort();

    let threads = perf_args.threads;
    let stabilize_seconds = perf_args.stabilize_seconds;

    let test_seconds = perf_args.test_seconds;

    if devices.is_empty() {
        panic!("No devices found");
    }

    println!("Found devices:");
    for (index, device) in devices.iter().enumerate() {
        println!("    {}. {:?}", index, device.path);
    }

    let selected_device = &devices[perf_args.device].path;
    println!("Selected device: {:?}", selected_device);

    // Setup device for perf test
    helper_setup(selected_device.clone()).unwrap();

    let mix_ratios = PerfMixRatios::from(perf_args.mix);

    // Open App Session
    let dev_with_shared_session = Arc::new(RwLock::new(ddi.open_dev(selected_device).unwrap()));
    {
        let mut dev = dev_with_shared_session.write();
        helper_set_device_kind(&mut dev).unwrap();
    }
    let dev_shared_without_session = Arc::new(RwLock::new(ddi.open_dev(selected_device).unwrap()));
    {
        let mut dev = dev_shared_without_session.write();
        helper_set_device_kind(&mut dev).unwrap();
    }

    let (app_sess_id, short_app_id) = helper_open_app_session(
        &dev_with_shared_session.read(),
        TEST_CRED_ID,
        TEST_CRED_PIN,
        TEST_SESSION_SEED,
    )
    .unwrap();

    let mix_keys = if perf_args.skip_key_create {
        PerfMixKeys {
            key_id_ecc_sign_256: 0xffff,
            key_id_ecc_sign_384: 0xffff,
            key_id_ecc_sign_521: 0xffff,
            key_id_rsa_mod_exp_2k: 0xffff,
            key_id_rsa_mod_exp_3k: 0xffff,
            key_id_rsa_mod_exp_4k: 0xffff,
            key_id_rsa_mod_exp_crt_2k: 0xffff,
            key_id_rsa_mod_exp_crt_3k: 0xffff,
            key_id_rsa_mod_exp_crt_4k: 0xffff,
            key_id_aes_cbc_128: 0xffff,
            key_id_aes_cbc_192: 0xffff,
            key_id_aes_cbc_256: 0xffff,
            key_id_aes_gcm_bulk_256: 0xffff,
            key_id_aes_xts_bulk_256: 0xffff,
            key_id_aes_xts_bulk_256_2: 0xffff,
            key_id_ecc_derive_256: 0xffff,
            key_id_ecc_derive_384: 0xffff,
            key_id_ecc_derive_521: 0xffff,
            key_id_secret_256: 0xffff,
            key_id_secret_384: 0xffff,
            key_id_secret_521: 0xffff,
            key_id_wrapping_key: 0xffff,
            encrypted_data_gcm_4k: None,
            tag_gcm_4k: None,
            encrypted_data_gcm_16m: None,
            tag_gcm_16m: None,

            // Empty wrapped blob values
            wrapped_blob_ecc_sign_256: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_ecc_sign_384: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_ecc_sign_521: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_2k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_3k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_4k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_crt_2k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_crt_3k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_rsa_crt_4k: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_aes_cbc_128: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_aes_cbc_192: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_aes_cbc_256: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_secret_256: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_secret_384: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
            wrapped_blob_secret_521: DataBlob {
                data: [0u8; 3072],
                len: 0,
            },
        }
    } else {
        helper_create_keys_for_mix(&dev_with_shared_session.read(), app_sess_id, short_app_id)
            .unwrap()
    };
    let app_sess_id = if perf_args.shared_session {
        Some(app_sess_id)
    } else {
        helper_close_app_session(&dev_with_shared_session.read(), app_sess_id).unwrap();
        None
    };

    let short_app_id = if perf_args.shared_session {
        Some(short_app_id)
    } else {
        None
    };

    let mut thread_list = Vec::new();
    for i in 0..threads {
        let thread_id = i as u8;
        let thread_device_path = selected_device.clone();

        let dev_with_session = dev_with_shared_session.clone();

        let perf_mix_args = PerfMixArguments {
            app_sess_id,
            short_app_id,
            skip_app_session_create: perf_args.skip_app_session_create,
            stabilize_seconds,
            test_seconds,
            prt_queue_length: perf_args.prt_queue_length,
            keys: mix_keys.clone(),
            ratios: mix_ratios.clone(),
        };

        let thread_dev_with_session = dev_with_session.clone();
        let thread_dev_without_session = dev_shared_without_session.clone();

        let thread = thread::spawn(move || {
            perf_test_thread(
                thread_id,
                thread_device_path,
                thread_dev_with_session,
                thread_dev_without_session,
                perf_mix_args,
            )
        });
        thread_list.push(thread);
    }

    const PROGRESS_PERIOD_MS: u64 = 1000;

    if !perf_args.hide_progress {
        println!(
            "Waiting for pre test stabilization time: {} seconds",
            stabilize_seconds
        );

        let progress_period = stabilize_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    if !perf_args.hide_progress {
        println!("Waiting for performance tests: {} seconds", test_seconds);

        let progress_period = test_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    if !perf_args.hide_progress {
        println!(
            "Waiting for post test stabilization time: {} seconds",
            stabilize_seconds
        );

        let progress_period = stabilize_seconds * 1000 / PROGRESS_PERIOD_MS;
        let pb = ProgressBar::new(progress_period);
        for _ in 0..progress_period {
            thread::sleep(std::time::Duration::from_millis(PROGRESS_PERIOD_MS));
            pb.inc(1);
        }
        pb.finish_and_clear();
        println!();
    }

    let mut threads_failed = 0;
    let mut total_counter: usize = 0;
    let mut total_prt = Vec::with_capacity(perf_args.prt_queue_length * perf_args.threads);
    let mut q = Quantogram::new();

    for thread in thread_list {
        let result = thread.join();
        if let Ok((thread_counter, thread_prt)) = result {
            total_counter += thread_counter;
            total_prt.extend(thread_prt);
        } else {
            threads_failed += 1;
        }
    }
    println!();

    println!(
        "MainThread: thread_count {} total_counter {} in secs {}: RPS: {}",
        threads,
        total_counter,
        test_seconds,
        total_counter as u64 / test_seconds
    );

    if perf_args.get_perf_log {
        let mut dev = ddi.open_dev(selected_device).unwrap();
        helper_set_device_kind(&mut dev).unwrap();

        let (session_id, _) =
            helper_open_app_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED).unwrap();

        let mut chunk_id = 0;

        let mut log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(perf_args.log_path.clone())
            .unwrap();

        let mut perf_log_raw = Vec::new();
        loop {
            let perf_log_chunk = helper_get_perf_log_chunk(&dev, session_id, chunk_id).unwrap();
            perf_log_raw.extend_from_slice(&perf_log_chunk);

            if perf_log_chunk.is_empty() {
                break;
            }

            chunk_id += 1;
        }
        log_file.write_all(&perf_log_raw).unwrap();
        // Drop the log file object explicitly to force the flush and close of the file
        drop(log_file);

        if perf_args.post_process_log {
            helper_post_process_log(perf_args.log_path.clone());
        }
    }

    // Cleanup device for perf test
    if let Some(app_sess_id) = app_sess_id {
        helper_close_app_session(&dev_with_shared_session.read(), app_sess_id).unwrap();
    };
    helper_cleanup(selected_device.clone()).unwrap();

    for prt in total_prt {
        q.add(prt as f64);
    }

    println!(
        "MainThread: Per request time: Samples {} Mean: {:.1}us, Median: {:.1}us, Min: {:.1}us, Max: {:.1}us, Std Dev: {:.1}us, P75: {:.1}us P90: {:.1}us P95: {:.1}us P99: {:.1}us",
        q.count(),
        q.mean().unwrap()/1000.0,
        q.median().unwrap()/1000.0,
        q.min().unwrap()/1000.0,
        q.max().unwrap()/1000.0,
        q.stddev().unwrap()/1000.0,
        q.quantile(0.75).unwrap()/1000.0,
        q.quantile(0.90).unwrap()/1000.0,
        q.quantile(0.95).unwrap()/1000.0,
        q.quantile(0.99).unwrap()/1000.0,
    );

    if threads_failed != 0 {
        panic!("MainThread: {} threads failed", threads_failed);
    }
}

fn command_bulk_post_process(bulk_post_process_args: BulkPostProcessArgs) {
    for file in glob(bulk_post_process_args.glob.as_str()).expect("Failed to read glob pattern") {
        let bin_log = file.unwrap();
        println!("Processing {:?}", bin_log);
        helper_post_process_log(bin_log);
    }
}

fn perf_test_thread(
    thread_id: u8,
    device_path: String,
    dev_with_session: Arc<RwLock<<DdiTest as Ddi>::Dev>>,
    dev_without_session: Arc<RwLock<<DdiTest as Ddi>::Dev>>,
    perf_mix_args: PerfMixArguments,
) -> (usize, Vec<u128>) {
    let ddi = DdiTest::default();

    let dev_without_session_thread_specific =
        Arc::new(RwLock::new(ddi.open_dev(device_path.as_str()).unwrap()));
    {
        let mut dev = dev_without_session_thread_specific.write();
        helper_set_device_kind(&mut dev).unwrap();
    }

    let dev_with_session_thread_specific =
        Arc::new(RwLock::new(ddi.open_dev(device_path.as_str()).unwrap()));
    {
        let mut dev = dev_with_session_thread_specific.write();
        helper_set_device_kind(&mut dev).unwrap();
    }

    let dev_with_session = if perf_mix_args.app_sess_id.is_none() {
        dev_with_session_thread_specific
    } else {
        dev_with_session
    };

    let dev_without_session = if perf_mix_args.app_sess_id.is_none() {
        dev_without_session_thread_specific
    } else {
        dev_without_session
    };

    let (app_sess_id, short_app_id) = if let (Some(app_sess_id), Some(short_app_id)) =
        (perf_mix_args.app_sess_id, perf_mix_args.short_app_id)
    {
        (app_sess_id, short_app_id)
    } else if !perf_mix_args.skip_app_session_create {
        helper_open_app_session(
            &dev_with_session.read(),
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .unwrap()
    } else {
        (0xffff, 0xff)
    };

    let dev_mgr_thread_specific =
        Arc::new(RwLock::new(ddi.open_dev(device_path.as_str()).unwrap()));
    {
        let mut dev = dev_mgr_thread_specific.write();
        helper_set_device_kind(&mut dev).unwrap();
    }

    let mut rng = thread_rng();

    let mix_items = [
        ("get_api_rev", perf_mix_args.ratios.get_api_rev),
        ("ecc_sign_256", perf_mix_args.ratios.ecc_sign_256),
        ("ecc_sign_384", perf_mix_args.ratios.ecc_sign_384),
        ("ecc_sign_521", perf_mix_args.ratios.ecc_sign_521),
        ("rsa_mod_exp_2k", perf_mix_args.ratios.rsa_mod_exp_2k),
        ("rsa_mod_exp_3k", perf_mix_args.ratios.rsa_mod_exp_3k),
        ("rsa_mod_exp_4k", perf_mix_args.ratios.rsa_mod_exp_4k),
        (
            "rsa_mod_exp_crt_2k",
            perf_mix_args.ratios.rsa_mod_exp_crt_2k,
        ),
        (
            "rsa_mod_exp_crt_3k",
            perf_mix_args.ratios.rsa_mod_exp_crt_3k,
        ),
        (
            "rsa_mod_exp_crt_4k",
            perf_mix_args.ratios.rsa_mod_exp_crt_4k,
        ),
        (
            "aes_cbc_128_encrypt",
            perf_mix_args.ratios.aes_cbc_128_encrypt,
        ),
        (
            "aes_cbc_128_decrypt",
            perf_mix_args.ratios.aes_cbc_128_decrypt,
        ),
        (
            "aes_cbc_192_encrypt",
            perf_mix_args.ratios.aes_cbc_192_encrypt,
        ),
        (
            "aes_cbc_192_decrypt",
            perf_mix_args.ratios.aes_cbc_192_decrypt,
        ),
        (
            "aes_cbc_256_encrypt",
            perf_mix_args.ratios.aes_cbc_256_encrypt,
        ),
        (
            "aes_cbc_256_decrypt",
            perf_mix_args.ratios.aes_cbc_256_decrypt,
        ),
        (
            "aes_gcm_encrypt_4k",
            perf_mix_args.ratios.aes_gcm_encrypt_4k,
        ),
        (
            "aes_gcm_encrypt_16m",
            perf_mix_args.ratios.aes_gcm_encrypt_16m,
        ),
        (
            "aes_xts_encrypt_4k",
            perf_mix_args.ratios.aes_xts_encrypt_4k,
        ),
        (
            "aes_xts_encrypt_16m",
            perf_mix_args.ratios.aes_xts_encrypt_16m,
        ),
        (
            "aes_gcm_decrypt_4k",
            perf_mix_args.ratios.aes_gcm_decrypt_4k,
        ),
        (
            "aes_gcm_decrypt_16m",
            perf_mix_args.ratios.aes_gcm_decrypt_16m,
        ),
        (
            "aes_xts_decrypt_4k",
            perf_mix_args.ratios.aes_xts_decrypt_4k,
        ),
        (
            "aes_xts_decrypt_16m",
            perf_mix_args.ratios.aes_xts_decrypt_16m,
        ),
        (
            "aes_cbc_128_generate_and_delete",
            perf_mix_args.ratios.aes_cbc_128_generate_and_delete,
        ),
        (
            "aes_cbc_192_generate_and_delete",
            perf_mix_args.ratios.aes_cbc_192_generate_and_delete,
        ),
        (
            "aes_cbc_256_generate_and_delete",
            perf_mix_args.ratios.aes_cbc_256_generate_and_delete,
        ),
        (
            "ecdh_derive_256_and_delete",
            perf_mix_args.ratios.ecdh_derive_256_and_delete,
        ),
        (
            "ecdh_derive_384_and_delete",
            perf_mix_args.ratios.ecdh_derive_384_and_delete,
        ),
        (
            "ecdh_derive_521_and_delete",
            perf_mix_args.ratios.ecdh_derive_521_and_delete,
        ),
        (
            "hkdf_derive_256_and_delete",
            perf_mix_args.ratios.hkdf_derive_256_and_delete,
        ),
        (
            "hkdf_derive_384_and_delete",
            perf_mix_args.ratios.hkdf_derive_384_and_delete,
        ),
        (
            "hkdf_derive_521_and_delete",
            perf_mix_args.ratios.hkdf_derive_521_and_delete,
        ),
        (
            "kbkdf_derive_256_and_delete",
            perf_mix_args.ratios.kbkdf_derive_256_and_delete,
        ),
        (
            "kbkdf_derive_384_and_delete",
            perf_mix_args.ratios.kbkdf_derive_384_and_delete,
        ),
        (
            "kbkdf_derive_521_and_delete",
            perf_mix_args.ratios.kbkdf_derive_521_and_delete,
        ),
        (
            "ecc_256_generate_and_delete",
            perf_mix_args.ratios.ecc_256_generate_and_delete,
        ),
        (
            "ecc_384_generate_and_delete",
            perf_mix_args.ratios.ecc_384_generate_and_delete,
        ),
        (
            "ecc_521_generate_and_delete",
            perf_mix_args.ratios.ecc_521_generate_and_delete,
        ),
        (
            "rsa_unwrap_rsa_2k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_2k_and_delete,
        ),
        (
            "rsa_unwrap_rsa_3k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_3k_and_delete,
        ),
        (
            "rsa_unwrap_rsa_4k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_4k_and_delete,
        ),
        (
            "rsa_unwrap_rsa_crt_2k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_crt_2k_and_delete,
        ),
        (
            "rsa_unwrap_rsa_crt_3k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_crt_3k_and_delete,
        ),
        (
            "rsa_unwrap_rsa_crt_4k_and_delete",
            perf_mix_args.ratios.rsa_unwrap_rsa_crt_4k_and_delete,
        ),
        (
            "rsa_unwrap_aes_cbc_128_and_delete",
            perf_mix_args.ratios.rsa_unwrap_aes_cbc_128_and_delete,
        ),
        (
            "rsa_unwrap_aes_cbc_192_and_delete",
            perf_mix_args.ratios.rsa_unwrap_aes_cbc_192_and_delete,
        ),
        (
            "rsa_unwrap_aes_cbc_256_and_delete",
            perf_mix_args.ratios.rsa_unwrap_aes_cbc_256_and_delete,
        ),
        (
            "rsa_unwrap_ecc_256_and_delete",
            perf_mix_args.ratios.rsa_unwrap_ecc_256_and_delete,
        ),
        (
            "rsa_unwrap_ecc_384_and_delete",
            perf_mix_args.ratios.rsa_unwrap_ecc_384_and_delete,
        ),
        (
            "rsa_unwrap_ecc_521_and_delete",
            perf_mix_args.ratios.rsa_unwrap_ecc_521_and_delete,
        ),
        (
            "rsa_unwrap_secret_256_and_delete",
            perf_mix_args.ratios.rsa_unwrap_secret_256_and_delete,
        ),
        (
            "rsa_unwrap_secret_384_and_delete",
            perf_mix_args.ratios.rsa_unwrap_secret_384_and_delete,
        ),
        (
            "rsa_unwrap_secret_521_and_delete",
            perf_mix_args.ratios.rsa_unwrap_secret_521_and_delete,
        ),
        (
            "aes_cbc_192_open_key",
            perf_mix_args.ratios.aes_cbc_192_open_key,
        ),
        (
            "aes_xts_bulk_256_open_key",
            perf_mix_args.ratios.aes_xts_bulk_256_open_key,
        ),
        ("rsa_4k_open_key", perf_mix_args.ratios.rsa_4k_open_key),
        (
            "rsa_4k_crt_open_key",
            perf_mix_args.ratios.rsa_4k_crt_open_key,
        ),
        ("ecc_521_open_key", perf_mix_args.ratios.ecc_521_open_key),
        (
            "ecc_521_attest_key",
            perf_mix_args.ratios.ecc_521_attest_key,
        ),
        ("rsa_4k_attest_key", perf_mix_args.ratios.rsa_4k_attest_key),
        (
            "rsa_4k_crt_attest_key",
            perf_mix_args.ratios.rsa_4k_crt_attest_key,
        ),
        (
            "open_manager_session_and_close",
            perf_mix_args.ratios.open_manager_session_and_close,
        ),
        (
            "open_app_session_and_close",
            perf_mix_args.ratios.open_app_session_and_close,
        ),
        (
            "create_app_and_delete",
            perf_mix_args.ratios.create_app_and_delete,
        ),
        ("get_cert_chain", perf_mix_args.ratios.get_cert_chain),
        (
            "get_unwrapping_key",
            perf_mix_args.ratios.get_unwrapping_key,
        ),
        ("get_device_info", perf_mix_args.ratios.get_device_info),
    ];

    let mix_distribution =
        WeightedAliasIndex::new(mix_items.iter().map(|item| item.1).collect()).unwrap();

    let mut prt_queue = CircularQueue::with_capacity(perf_mix_args.prt_queue_length);

    let mut loop_counter: usize = 0;

    thread::sleep(std::time::Duration::from_secs(
        perf_mix_args.stabilize_seconds,
    ));

    let start_time = Instant::now();
    while Instant::now().duration_since(start_time).as_secs() < perf_mix_args.test_seconds {
        let selected_command = mix_items[mix_distribution.sample(&mut rng)];
        let request_start = Instant::now();

        let resp = match selected_command.0 {
            "get_api_rev" => helper_get_api_rev(&dev_without_session.read()),
            "ecc_sign_256" => helper_ecc_sign(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_sign_256,
                [100u8; 96],
                32,
            ),
            "ecc_sign_384" => helper_ecc_sign(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_sign_384,
                [100u8; 96],
                48,
            ),
            "ecc_sign_521" => helper_ecc_sign(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_sign_521,
                [100u8; 96],
                64,
            ),

            "rsa_mod_exp_2k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_2k,
                [100u8; 512],
                256,
                DdiRsaOpType::Sign,
            ),
            "rsa_mod_exp_3k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_3k,
                [100u8; 512],
                384,
                DdiRsaOpType::Sign,
            ),
            "rsa_mod_exp_4k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_4k,
                [100u8; 512],
                512,
                DdiRsaOpType::Sign,
            ),
            "rsa_mod_exp_crt_2k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_crt_2k,
                [100u8; 512],
                256,
                DdiRsaOpType::Sign,
            ),
            "rsa_mod_exp_crt_3k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_crt_3k,
                [100u8; 512],
                384,
                DdiRsaOpType::Sign,
            ),
            "rsa_mod_exp_crt_4k" => helper_rsa_mod_exp(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_crt_4k,
                [100u8; 512],
                512,
                DdiRsaOpType::Sign,
            ),
            "aes_cbc_128_encrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_128,
                [100u8; 1024],
                512,
                DdiAesOp::Encrypt,
            ),
            "aes_cbc_128_decrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_128,
                [100u8; 1024],
                512,
                DdiAesOp::Decrypt,
            ),
            "aes_cbc_192_encrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_192,
                [100u8; 1024],
                512,
                DdiAesOp::Encrypt,
            ),
            "aes_cbc_192_decrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_192,
                [100u8; 1024],
                512,
                DdiAesOp::Decrypt,
            ),
            "aes_cbc_256_encrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_256,
                [100u8; 1024],
                512,
                DdiAesOp::Encrypt,
            ),
            "aes_cbc_256_decrypt" => helper_aes_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_aes_cbc_256,
                [100u8; 1024],
                512,
                DdiAesOp::Decrypt,
            ),

            "aes_gcm_encrypt_4k" => {
                let res = helper_aes_gcm_encrypt_decrypt(
                    &dev_with_session.read(),
                    app_sess_id,
                    short_app_id,
                    perf_mix_args.keys.key_id_aes_gcm_bulk_256,
                    DdiAesOp::Encrypt,
                    vec![100u8; 1024 * 4],
                    [0x3; 12],
                    Some([0x4; 32].to_vec()),
                    None,
                );
                res.map(|_| ())
            }

            "aes_gcm_encrypt_16m" => {
                let res = helper_aes_gcm_encrypt_decrypt(
                    &dev_with_session.read(),
                    app_sess_id,
                    short_app_id,
                    perf_mix_args.keys.key_id_aes_gcm_bulk_256,
                    DdiAesOp::Encrypt,
                    vec![100u8; 1024 * 1024 * 16 - 32], // - 32 because we have AAD of 32
                    [0x3; 12],
                    Some([0x4; 32].to_vec()),
                    None,
                );
                res.map(|_| ())
            }

            "aes_gcm_decrypt_4k" => {
                let res = helper_aes_gcm_encrypt_decrypt(
                    &dev_with_session.read(),
                    app_sess_id,
                    short_app_id,
                    perf_mix_args.keys.key_id_aes_gcm_bulk_256,
                    DdiAesOp::Decrypt,
                    perf_mix_args.keys.encrypted_data_gcm_4k.unwrap().to_vec(),
                    [0x3; 12],
                    Some([0x4; 32].to_vec()),
                    perf_mix_args.keys.tag_gcm_4k,
                );
                res.map(|_| ())
            }

            "aes_gcm_decrypt_16m" => {
                let res = helper_aes_gcm_encrypt_decrypt(
                    &dev_with_session.read(),
                    app_sess_id,
                    short_app_id,
                    perf_mix_args.keys.key_id_aes_gcm_bulk_256,
                    DdiAesOp::Decrypt,
                    perf_mix_args
                        .keys
                        .encrypted_data_gcm_16m
                        .as_ref()
                        .unwrap()
                        .to_vec(),
                    [0x3; 12],
                    Some([0x4; 32].to_vec()),
                    perf_mix_args.keys.tag_gcm_16m,
                );
                res.map(|_| ())
            }
            "aes_xts_encrypt_4k" => helper_aes_xts_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                short_app_id,
                perf_mix_args.keys.key_id_aes_xts_bulk_256,
                perf_mix_args.keys.key_id_aes_xts_bulk_256_2,
                DdiAesOp::Encrypt,
                vec![100u8; 1024 * 4],
                1024 * 4,
                [0x4; 16usize],
            ),

            "aes_xts_encrypt_16m" => helper_aes_xts_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                short_app_id,
                perf_mix_args.keys.key_id_aes_xts_bulk_256,
                perf_mix_args.keys.key_id_aes_xts_bulk_256_2,
                DdiAesOp::Encrypt,
                vec![100u8; 1024 * 1024 * 16],
                1024 * 4,
                [0x4; 16usize],
            ),
            "aes_xts_decrypt_4k" => helper_aes_xts_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                short_app_id,
                perf_mix_args.keys.key_id_aes_xts_bulk_256,
                perf_mix_args.keys.key_id_aes_xts_bulk_256_2,
                DdiAesOp::Decrypt,
                vec![100u8; 1024 * 4],
                1024 * 4,
                [0x4; 16usize],
            ),

            "aes_xts_decrypt_16m" => helper_aes_xts_encrypt_decrypt(
                &dev_with_session.read(),
                app_sess_id,
                short_app_id,
                perf_mix_args.keys.key_id_aes_xts_bulk_256,
                perf_mix_args.keys.key_id_aes_xts_bulk_256_2,
                DdiAesOp::Decrypt,
                vec![100u8; 1024 * 1024 * 16],
                1024 * 4,
                [0x4; 16usize],
            ),
            "aes_cbc_128_generate_and_delete" => helper_create_aes_cbc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiAesKeySize::Aes128,
                None,
            ),
            "aes_cbc_192_generate_and_delete" => helper_create_aes_cbc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiAesKeySize::Aes192,
                None,
            ),
            "aes_cbc_256_generate_and_delete" => helper_create_aes_cbc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiAesKeySize::Aes256,
                None,
            ),
            "ecdh_derive_256_and_delete" => helper_ecdh_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_derive_256,
                None,
                TEST_ECC_256_PUBLIC_KEY_DATA,
                TEST_ECC_256_PUBLIC_KEY_LEN,
                DdiKeyType::Secret256,
            ),
            "ecdh_derive_384_and_delete" => helper_ecdh_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_derive_384,
                None,
                TEST_ECC_384_PUBLIC_KEY_DATA,
                TEST_ECC_384_PUBLIC_KEY_LEN,
                DdiKeyType::Secret384,
            ),
            "ecdh_derive_521_and_delete" => helper_ecdh_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_derive_521,
                None,
                TEST_ECC_521_PUBLIC_KEY_DATA,
                TEST_ECC_521_PUBLIC_KEY_LEN,
                DdiKeyType::Secret521,
            ),
            "hkdf_derive_256_and_delete" => helper_hkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_256,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "hkdf_derive_384_and_delete" => helper_hkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_384,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "hkdf_derive_521_and_delete" => helper_hkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_521,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "kbkdf_derive_256_and_delete" => helper_kbkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_256,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "kbkdf_derive_384_and_delete" => helper_kbkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_384,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "kbkdf_derive_521_and_delete" => helper_kbkdf_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_secret_521,
                DdiHashAlgorithm::Sha256,
                DdiKeyType::Aes256,
                DdiKeyUsage::EncryptDecrypt,
            ),
            "ecc_256_generate_and_delete" => helper_create_ecc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiEccCurve::P256,
                None,
                DdiKeyUsage::SignVerify,
            ),
            "ecc_384_generate_and_delete" => helper_create_ecc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiEccCurve::P384,
                None,
                DdiKeyUsage::SignVerify,
            ),
            "ecc_521_generate_and_delete" => helper_create_ecc_key_and_delete(
                &dev_with_session.read(),
                app_sess_id,
                DdiEccCurve::P521,
                None,
                DdiKeyUsage::SignVerify,
            ),
            "rsa_unwrap_rsa_2k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_2k.data),
                perf_mix_args.keys.wrapped_blob_rsa_2k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_rsa_3k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_3k.data),
                perf_mix_args.keys.wrapped_blob_rsa_3k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_rsa_4k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_4k.data),
                perf_mix_args.keys.wrapped_blob_rsa_4k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_rsa_crt_2k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_crt_2k.data),
                perf_mix_args.keys.wrapped_blob_rsa_crt_2k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_rsa_crt_3k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_crt_3k.data),
                perf_mix_args.keys.wrapped_blob_rsa_crt_3k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_rsa_crt_4k_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_rsa_crt_4k.data),
                perf_mix_args.keys.wrapped_blob_rsa_crt_4k.len,
                DdiKeyClass::Rsa,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_aes_cbc_128_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_aes_cbc_128.data),
                perf_mix_args.keys.wrapped_blob_aes_cbc_128.len,
                DdiKeyClass::Aes,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_aes_cbc_192_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_aes_cbc_192.data),
                perf_mix_args.keys.wrapped_blob_aes_cbc_192.len,
                DdiKeyClass::Aes,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_aes_cbc_256_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_aes_cbc_256.data),
                perf_mix_args.keys.wrapped_blob_aes_cbc_256.len,
                DdiKeyClass::Aes,
                None,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_secret_256_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_secret_256.data),
                perf_mix_args.keys.wrapped_blob_secret_256.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_secret_384_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_secret_384.data),
                perf_mix_args.keys.wrapped_blob_secret_384.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_secret_521_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_secret_521.data),
                perf_mix_args.keys.wrapped_blob_secret_521.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_ecc_256_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_ecc_sign_256.data),
                perf_mix_args.keys.wrapped_blob_ecc_sign_256.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_ecc_384_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_ecc_sign_384.data),
                perf_mix_args.keys.wrapped_blob_ecc_sign_384.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "rsa_unwrap_ecc_521_and_delete" => helper_rsa_unwrap_delete(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_wrapping_key,
                &(perf_mix_args.keys.wrapped_blob_ecc_sign_521.data),
                perf_mix_args.keys.wrapped_blob_ecc_sign_521.len,
                DdiKeyClass::Ecc,
                None,
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
            ),

            "aes_cbc_192_open_key" => {
                helper_open_key(&dev_with_session.read(), app_sess_id, KEY_TAG_AES_CBC_192)
            }

            "aes_xts_bulk_256_open_key" => helper_open_key(
                &dev_with_session.read(),
                app_sess_id,
                KEY_TAG_AES_XTS_BULK_256,
            ),

            "rsa_4k_open_key" => helper_open_key(
                &dev_with_session.read(),
                app_sess_id,
                KEY_TAG_RSA_MOD_EXP_4K,
            ),

            "rsa_4k_crt_open_key" => helper_open_key(
                &dev_with_session.read(),
                app_sess_id,
                KEY_TAG_RSA_MOD_EXP_CRT_4K,
            ),

            "ecc_521_open_key" => {
                helper_open_key(&dev_with_session.read(), app_sess_id, KEY_TAG_ECC_SIGN_521)
            }

            "ecc_521_attest_key" => helper_attest_key(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_ecc_sign_521,
                &[100u8; 128],
            ),
            "rsa_4k_attest_key" => helper_attest_key(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_4k,
                &[100u8; 128],
            ),
            "rsa_4k_crt_attest_key" => helper_attest_key(
                &dev_with_session.read(),
                app_sess_id,
                perf_mix_args.keys.key_id_rsa_mod_exp_crt_4k,
                &[100u8; 128],
            ),
            "open_app_session_and_close" => helper_open_app_session_and_close(
                &dev_without_session.read(),
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            ),

            "get_cert_chain" => helper_get_certificate(&dev_with_session.read()),

            "get_unwrapping_key" => {
                helper_get_unwrapping_key(&dev_with_session.read(), app_sess_id).map(|_| ())
            }

            "get_device_info" => helper_get_device_info(&dev_without_session.read()).map(|_| ()),

            val => panic!("Unknown mix: {}", val),
        };
        let request_time = request_start.elapsed().as_nanos();

        if let Err(e) = resp {
            panic!(
                "TestThread{}: Error: {:?} Selected command: {:?}",
                thread_id, e, selected_command
            );
        }

        prt_queue.push(request_time);

        loop_counter += 1;
    }

    thread::sleep(std::time::Duration::from_secs(
        perf_mix_args.stabilize_seconds,
    ));

    if perf_mix_args.app_sess_id.is_none() && !perf_mix_args.skip_app_session_create {
        helper_close_app_session(&dev_with_session.read(), app_sess_id).unwrap();
    }

    let mut prt_vec = Vec::with_capacity(prt_queue.len());
    for &duration in prt_queue.asc_iter() {
        prt_vec.push(duration);
    }

    (loop_counter, prt_vec)
}
