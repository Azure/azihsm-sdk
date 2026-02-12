// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "auto_key.hpp"
#include <azihsm_api.h>
#include <vector>

// Helper function to get key size in bits from EC curve
uint32_t get_curve_key_bits(azihsm_ecc_curve curve);

// Helper function to generate an EC key pair for derivation operations
azihsm_status generate_ec_key_pair_for_derive(
    azihsm_handle session_handle,
    azihsm_handle &pub_key_handle,
    azihsm_handle &priv_key_handle,
    azihsm_ecc_curve curve
);

// Helper function to derive a shared secret key via ECDH
// Returns the shared secret key handle via out_shared_secret_handle
azihsm_status derive_shared_secret_via_ecdh(
    azihsm_handle session_handle,
    azihsm_handle priv_key_handle,
    azihsm_handle peer_pub_key_handle,
    azihsm_ecc_curve curve,
    azihsm_handle &out_shared_secret_handle
);

// Helper struct to manage ECDH key pairs with automatic cleanup
struct EcdhKeyPairSet
{
    auto_key pub_key_a;
    auto_key priv_key_a;
    auto_key pub_key_b;
    auto_key priv_key_b;

    // Generate two EC key pairs for ECDH operations
    azihsm_status generate(azihsm_handle session_handle, azihsm_ecc_curve curve)
    {
        azihsm_status err = generate_ec_key_pair_for_derive(
            session_handle,
            pub_key_a.handle,
            priv_key_a.handle,
            curve
        );
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return err;
        }

        return generate_ec_key_pair_for_derive(
            session_handle,
            pub_key_b.handle,
            priv_key_b.handle,
            curve
        );
    }
};