// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

/// Helper function to generate AES key for testing
void session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
);

template <typename T>
void verify_key_property(azihsm_handle key_handle, azihsm_key_prop_id prop_id, T expected);

/// Verify properties of a generated AES key
void verify_generated_aes_key_properties(azihsm_handle key_handle, azihsm_key_kind key_kind, uint32_t bits, bool is_session);