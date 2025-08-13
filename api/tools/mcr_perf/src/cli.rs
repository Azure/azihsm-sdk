// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env;
use std::path::PathBuf;

use super::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct CliArgs {
    /// CLI Command
    #[command(subcommand)]
    pub(crate) command: CliCommand,
}

#[derive(Subcommand)]
pub(crate) enum CliCommand {
    /// Performance Test
    Perf(PerfArgs),

    /// Bulk post processing
    BulkPostProcess(BulkPostProcessArgs),
}

#[derive(Args)]
pub(crate) struct PerfArgs {
    /// Selected device index
    #[arg(long, default_value_t = 0)]
    pub(crate) device: usize,

    /// Number of test threads
    #[arg(long, default_value_t = 128)]
    pub(crate) threads: usize,

    /// Skip key creation (helpful for non crypto commands)
    #[arg(long, default_value_t = false)]
    pub(crate) skip_key_create: bool,

    /// Skip app session creation (helpful for measuring open app/mgr sessions commands)
    #[arg(long, default_value_t = false)]
    pub(crate) skip_app_session_create: bool,

    /// Stabilization time in seconds
    #[arg(long, default_value_t = 5)]
    pub(crate) stabilize_seconds: u64,

    /// Number of seconds to run performance test
    #[arg(long, default_value_t = 100)]
    pub(crate) test_seconds: u64,

    /// Use shared session for all threads or let each thread have their own session
    #[arg(long, default_value_t = false)]
    pub(crate) shared_session: bool,

    /// Hide progress bar
    #[arg(long, default_value_t = false)]
    pub(crate) hide_progress: bool,

    /// Per request time queue size per thread
    #[arg(long, default_value_t = 10000)]
    pub(crate) prt_queue_length: usize,

    /// Get Perf Log
    #[arg(long, default_value_t = false)]
    pub(crate) get_perf_log: bool,

    /// Perf Log Path
    #[arg(long, default_value = get_default_perf_log_path().into_os_string())]
    pub(crate) log_path: PathBuf,

    /// Post process log
    #[arg(long, default_value_t = true)]
    pub(crate) post_process_log: bool,

    /// Mix for testing
    #[command(subcommand)]
    pub(crate) mix: PerfMix,
}

#[derive(Subcommand)]
pub(crate) enum PerfMix {
    /// Custom Performance Mix
    Custom(CustomMixArgs),

    /// Predefined Performance Mixes
    PreMix(PreMixArgs),
}

#[derive(Args)]
pub(crate) struct CustomMixArgs {
    /// Ratio of Get API Revision operations
    #[arg(long, default_value_t = 0)]
    pub(crate) get_api_rev: u16,

    /// Ratio of ECC Sign 256 operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_sign_256: u16,

    /// Ratio of ECC Sign 384 operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_sign_384: u16,

    /// Ratio of ECC Sign 521 operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_sign_521: u16,

    /// Ratio of RSA 2K Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_2k: u16,

    /// Ratio of RSA 3K Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_3k: u16,

    /// Ratio of RSA 4K Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_4k: u16,

    /// Ratio of RSA 2K CRT Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_crt_2k: u16,

    /// Ratio of RSA 3K CRT Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_crt_3k: u16,

    /// Ratio of RSA 4K CRT Modular Exponentiation operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_mod_exp_crt_4k: u16,

    /// Ratio of AES-CBC 128 Encrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_128_encrypt: u16,

    /// Ratio of AES-CBC 128 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_128_decrypt: u16,

    /// Ratio of AES-CBC 192 Encrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_192_encrypt: u16,

    /// Ratio of AES-CBC 192 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_192_decrypt: u16,

    /// Ratio of AES-CBC 256 Encrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_256_encrypt: u16,

    /// Ratio of AES-CBC 256 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_256_decrypt: u16,

    /// Ratio of AES GCM Encrypt operations for data size 4k
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_gcm_encrypt_4k: u16,

    /// Ratio of AES GCM Encrypt operations for data size 16m
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_gcm_encrypt_16m: u16,

    /// Ratio of AES XTS Encrypt operations for data size 4k
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_xts_encrypt_4k: u16,

    /// Ratio of AES XTS Encrypt operations for data size 16m
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_xts_encrypt_16m: u16,

    /// Ratio of AES GCM Decrypt operations for data size 4k
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_gcm_decrypt_4k: u16,

    /// Ratio of AES GCM Decrypt operations  for data size 16m
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_gcm_decrypt_16m: u16,

    /// Ratio of AES XTS Decrypt operations  for data size 4k
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_xts_decrypt_4k: u16,

    /// Ratio of AES XTS Decrypt operations  for data size 16m
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_xts_decrypt_16m: u16,

    /// Ratio of AES-CBC 256 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_128_generate_and_delete: u16,

    /// Ratio of AES-CBC 256 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_192_generate_and_delete: u16,

    /// Ratio of AES-CBC 256 Decrypt operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_256_generate_and_delete: u16,

    /// Ratio of ECDH 256 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecdh_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecdh_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecdh_derive_521_and_delete: u16,

    /// Ratio of HKDF 256 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) hkdf_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) hkdf_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) hkdf_derive_521_and_delete: u16,

    /// Ratio of HKDF 256 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) kbkdf_derive_256_and_delete: u16,

    /// Ratio of ECDH 384 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) kbkdf_derive_384_and_delete: u16,

    /// Ratio of ECDH 521 Derive operations
    #[arg(long, default_value_t = 0)]
    pub(crate) kbkdf_derive_521_and_delete: u16,

    /// Ratio of ECC 256 Generate operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_256_generate_and_delete: u16,

    /// Ratio of ECC 384 Generate operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_384_generate_and_delete: u16,

    /// Ratio of ECC 521 Generate operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_521_generate_and_delete: u16,

    /// Ratio of RSA 2K rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_2k_and_delete: u16,

    /// Ratio of RSA 3K rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_3k_and_delete: u16,

    /// Ratio of RSA 4K rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_4k_and_delete: u16,

    /// Ratio of RSA 2K CRT rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_crt_2k_and_delete: u16,

    /// Ratio of RSA 3K CRT rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_crt_3k_and_delete: u16,

    /// Ratio of RSA 4K CRT rsa_unwrap delete operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_rsa_crt_4k_and_delete: u16,

    /// Ratio of AES CBC 128 rsa_unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_aes_cbc_128_and_delete: u16,

    /// Ratio of AES CBC 192 rsa_unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_aes_cbc_192_and_delete: u16,

    /// Ratio of AES CBC 256 rsa_unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_aes_cbc_256_and_delete: u16,

    /// Ratio of ECC 521 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_ecc_521_and_delete: u16,

    /// Ratio of ECC 384 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_ecc_384_and_delete: u16,

    /// Ratio of ECC 256 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_ecc_256_and_delete: u16,

    /// Ratio of secret 521 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_secret_521_and_delete: u16,

    /// Ratio of secret 384 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_secret_384_and_delete: u16,

    /// Ratio of secret 256 RSA unwrap operation
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_unwrap_secret_256_and_delete: u16,

    /// Ratio of AES-CBC 192 OpenKey  operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_cbc_192_open_key: u16,

    /// Ratio of AES Bulk 256 OpenKey  operations
    #[arg(long, default_value_t = 0)]
    pub(crate) aes_bulk_256_open_key: u16,

    /// Ratio of RSA 4K No CRT OpenKey  operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_4k_open_key: u16,

    /// Ratio of RSA 4K CRT OpenKey  operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_4k_crt_open_key: u16,

    /// Ratio of ECC 521 OpenKey  operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_521_open_key: u16,

    /// Ratio of ECC 521 Attest Key operations
    #[arg(long, default_value_t = 0)]
    pub(crate) ecc_521_attest_key: u16,

    /// Ratio of RSA 4k Attest Key operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_4k_attest_key: u16,

    /// Ratio of RSA 4k CRT Attest Key operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_4k_crt_attest_key: u16,

    /// Ratio of Manager Session Open and Close operations (Must not be used --shared-session or with any other command since they create sessions which have limits)
    /// Must be tested solo.
    #[arg(long, default_value_t = 0)]
    pub(crate) open_manager_session_and_close: u16,

    /// Ratio of Application Session Open and Close operations (Must not be used --shared-session or with any other command since they create sessions which have limits)
    /// Must be tested solo.
    #[arg(long, default_value_t = 0)]
    pub(crate) open_app_session_and_close: u16,

    /// Ratio of App Create and Delete operations (Must not be used --shared-session or with any other command since they use app sessions and this one uses manager session)
    /// Must be tested solo.
    #[arg(long, default_value_t = 0)]
    pub(crate) create_app_and_delete: u16,

    /// Ratio of Get Collateral operations
    #[arg(long, default_value_t = 0)]
    pub(crate) get_collateral: u16,

    /// Ratio of Get Unwrapping Key operations
    #[arg(long, default_value_t = 0)]
    pub(crate) get_unwrapping_key: u16,

    /// Ratio of Get Device Info operations
    #[arg(long, default_value_t = 0)]
    pub(crate) get_device_info: u16,
}

#[derive(Args)]
pub(crate) struct PreMixArgs {
    pub(crate) pre_mix: PreMix,
}

#[derive(ValueEnum, Clone)]
pub(crate) enum PreMix {
    /// Get API Revision only
    GetApiRevOnly,

    /// All Equal
    AllEqual,
}

#[derive(Args)]
pub(crate) struct BulkPostProcessArgs {
    /// Binary file glob
    #[arg(long)]
    pub(crate) glob: String,
}

fn get_default_perf_log_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path.push("perf-log.log");
    path
}
