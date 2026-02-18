// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>

/// Helper function to generate RSA unwrapping key pair for testing
azihsm_status generate_rsa_unwrapping_keypair(
    azihsm_handle session,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
);