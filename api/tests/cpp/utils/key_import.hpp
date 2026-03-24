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

/// Helper to RSA-AES wrap an arbitrary plaintext buffer for later unwrap/import.
azihsm_status rsa_aes_wrap_bytes(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &plaintext,
    uint32_t aes_key_bits,
    std::vector<uint8_t> &wrapped_out
);