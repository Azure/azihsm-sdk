// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <vector>

/// Helper function to generate AES key for testing
void session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Verify properties of a generated AES key
void verify_generated_aes_key_properties(
    azihsm_handle key_handle,
    azihsm_key_kind key_kind,
    uint32_t bits,
    bool is_session,
    bool expected_local
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

void aes_key_unwrap_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Helper function to test AES key unmask: generate, get masked blob, unmask, and verify properties
void aes_key_unmask_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

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

azihsm_algo_rsa_pkcs_oaep_params build_oaep_sha256_params();