// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#[cfg(test)]
mod integration {
    pub mod aes_cbc;
    pub mod aes_gcm_bulk_stress;
    pub mod aes_generate;
    pub mod aes_xts_bulk_stress;
    pub mod aes_xts_encrypt_decrypt;
    pub mod attest_key;
    pub mod change_pin;
    pub mod close_session;
    pub mod common;
    pub mod ddi_dev_info;
    pub mod delete_key;
    pub mod device_handle_session;
    pub mod ecc_generate;
    pub mod ecc_sign_compat;
    pub mod ecc_sign_stress;
    pub mod ecc_sign_verify;
    pub mod ecdh_256_key_exchange;
    pub mod ecdh_384_key_exchange;
    pub mod ecdh_521_key_exchange;
    pub mod establish_credential;
    pub mod extension_support;
    pub mod flush_session;
    pub mod get_api_rev;
    pub mod get_cert_chain;
    pub mod get_device_info;
    pub mod get_establish_cred_encryption_key;
    pub mod get_session_encryption_key;
    pub mod get_unwrapping_key;
    pub mod hmac;
    pub mod invalid_ecc_pub_key_vectors;
    pub mod live_migration_expected_errors;
    pub mod live_migration_sim;
    pub mod lm_context;
    pub mod masked_key;
    pub mod masked_key_aes_gen;
    pub mod masked_key_ecc_gen;
    pub mod masked_key_ecdh_exchange;
    pub mod masked_key_get_unwrapping;
    pub mod masked_key_hkdf_derive;
    pub mod masked_key_kbkdf_derive;
    pub mod masked_key_rsa_unwrap;
    pub mod open_key;
    pub mod open_key_no_import;
    pub mod open_session;
    pub mod prov_part;
    pub mod reopen_session;
    pub mod rsa_2k_decrypt_no_crt;
    pub mod rsa_2k_decrypt_with_crt;
    pub mod rsa_2k_sign;
    pub mod rsa_3k_decrypt_no_crt;
    pub mod rsa_3k_decrypt_with_crt;
    pub mod rsa_3k_sign;
    pub mod rsa_4k_decrypt_no_crt;
    pub mod rsa_4k_decrypt_with_crt;
    pub mod rsa_4k_sign;
    pub mod rsa_mod_exp;
    pub mod rsa_unwrap_generated_key;
    pub mod secret_hkdf_derive;
    pub mod secret_kbkdf_derive;
}
