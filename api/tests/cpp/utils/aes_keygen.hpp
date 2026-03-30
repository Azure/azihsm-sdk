// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

/// Helper function to generate AES key for testing
void test_session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

/// Verify properties of a generated AES key
void verify_generated_aes_key_properties(azihsm_handle key_handle, uint32_t bits, bool is_session);