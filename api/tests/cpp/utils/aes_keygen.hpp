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
    bool is_session
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