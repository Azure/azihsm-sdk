// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include "handle/key_handle.hpp"
#include <azihsm_api.h>

// Helper function to generate AES key for testing
static KeyHandle generate_aes_key(azihsm_handle session, uint32_t bits)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    key_props key_props;
    key_props.key_kind = AZIHSM_KEY_KIND_AES;
    key_props.key_class = AZIHSM_KEY_CLASS_SECRET;
    key_props.bits = bits;
    key_props.is_session = true;
    key_props.can_encrypt = true;
    key_props.can_decrypt = true;

    return KeyHandle(session, &keygen_algo, key_props);
}