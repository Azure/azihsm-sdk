// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <vector>

/// Helper to build XTS wrapped blob header
/// Format: magic (u64 LE) + version (u16 LE) + key1_len (u16 LE) + key2_len (u16 LE) + reserved
/// (u16 LE)
std::vector<uint8_t> build_xts_wrapped_blob_header(uint16_t key1_len, uint16_t key2_len);

/// Helper to build complete XTS wrapped blob (header + wrapped_key1 + wrapped_key2)
std::vector<uint8_t> build_xts_wrapped_blob(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &key1_plain,
    const std::vector<uint8_t> &key2_plain
);

/// Helper to build OAEP params with SHA-256 for RSA AES key unwrap
azihsm_algo_rsa_pkcs_oaep_params build_oaep_sha256_params();

/// Helper to build RSA AES key unwrap params for given key kind and bits
azihsm_algo_rsa_aes_key_wrap_params build_rsa_aes_key_unwrap_params(
    azihsm_algo_rsa_pkcs_oaep_params &oaep_params,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Helper to build RSA AES key unwrap algo struct
azihsm_algo build_rsa_aes_key_unwrap_algo(azihsm_algo_rsa_aes_key_wrap_params &unwrap_params);

/// Helper function to wrap a local AES key using RSA AES Wrap algo
std::vector<uint8_t> wrap_local_aes_key(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &local_key,
    uint32_t aes_key_bits,
    azihsm_algo_rsa_pkcs_oaep_params &oaep_params
);

/// Helper function to verify properties of a generated AES key
void verify_generated_aes_key_properties(
    azihsm_handle key_handle,
    azihsm_key_kind key_kind,
    uint32_t bits,
    bool is_session,
    bool expected_local
);

// Helper function to compare properties of two keys
void compare_key_properties(azihsm_handle key_handle1, azihsm_handle key_handle2);

/// Helper function template to verify one property of a generated AES key
template <typename T>
void verify_key_property(azihsm_handle key_handle, azihsm_key_prop_id prop_id, T expected)
{
    T actual{};
    azihsm_key_prop prop{};
    prop.id = prop_id;
    prop.val = &actual;
    prop.len = sizeof(actual);
    azihsm_status err = azihsm_key_get_prop(key_handle, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual, expected);
}

/// Helper function template to compare one property of two different keys
template <typename T>
void compare_key_property(
    azihsm_handle key_handle1,
    azihsm_handle key_handle2,
    azihsm_key_prop_id prop_id
)
{
    T actual1{};
    azihsm_key_prop prop1{};
    prop1.id = prop_id;
    prop1.val = &actual1;
    prop1.len = sizeof(actual1);
    azihsm_status err = azihsm_key_get_prop(key_handle1, &prop1);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    T actual2{};
    azihsm_key_prop prop2{};
    prop2.id = prop_id;
    prop2.val = &actual2;
    prop2.len = sizeof(actual2);
    err = azihsm_key_get_prop(key_handle2, &prop2);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(actual1, actual2);
}

/// Helper function to generate AES key for testing
void session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Helper function to attempt to generate AES key with invalid properties for testing
void aes_key_gen_invalid_props_fail_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    std::vector<azihsm_key_prop_id> flag_prop_ids
);

/// Helper function to attempt to generate AES key with multiple invalid capabilities for testing
void aes_key_gen_multiple_invalid_capabilities_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Helper function to generate AES key with non-session persistence and verify
/// AZIHSM_KEY_PROP_ID_SESSION property is false
void aes_key_gen_persistent_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unwrapping and verify properties of unwrapped key
void aes_key_unwrap_common(azihsm_handle session, azihsm_key_kind key_kind, uint32_t bits);

/// Helper function to test AES key unmask: generate, get masked blob, unmask, and verify properties
void aes_key_unmask_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unmasking with wrong key kind and expect failure
void aes_unmask_wrong_kind_fails_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    azihsm_key_kind wrong_kind
);

/// Common test function to test AES key unmasking with corrupted masked blob and expect failure
void aes_unmask_corrupted_blob_fails_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unwrapping with corrupted wrapped key and expect failure
void aes_key_unwrap_corrupted_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unwrapping with wrong algorithm parameters and expect
/// failure
void aes_unwrap_wrong_algo_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits,
    azihsm_algo_id wrong_algo_id
);

/// Common test function to test unmasked key is functional and independent of the original key
void aes_unmasked_key_independent_handle_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unwrapping with truncated wrapped blob and expect failure
void aes_unwrap_truncated_blob_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Common test function to test AES key unwrapping with mismatched bit length and expect failure
void aes_unwrap_bits_mismatch_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits,
    uint32_t wrong_bits
);

/// Common test function to test AES key unwrapping with correct parameters and verify the unwrapped
/// key is functional
void aes_unwrapped_key_roundtrip_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
);
