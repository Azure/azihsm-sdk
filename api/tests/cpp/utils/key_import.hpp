// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "key_props.hpp"
#include <azihsm_api.h>
#include <vector>

/// Helper function to import a key pair (RSA or ECC) using RSA-AES key wrapping
azihsm_status import_keypair(
    azihsm_handle wrapping_pub_key,
    azihsm_handle wrapping_priv_key,
    const std::vector<uint8_t> &key_der,
    key_props props,
    azihsm_handle *imported_priv_key,
    azihsm_handle *imported_pub_key
);