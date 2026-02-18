// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "auto_key.hpp"
#include <azihsm_api.h>
#include <vector>

// Helper function to get key size in bits from EC curve
<<<<<<< HEAD
inline uint32_t get_curve_key_bits(azihsm_ecc_curve curve)
{
    switch (curve)
    {
    case AZIHSM_ECC_CURVE_P256:
        return 256;
    case AZIHSM_ECC_CURVE_P384:
        return 384;
    case AZIHSM_ECC_CURVE_P521:
        return 521;
    default:
        return 256; // Default to P256
    }
}

// Helper function to generate an EC key pair for derivation operations
inline azihsm_status generate_ec_key_pair_for_derive(
=======
uint32_t get_curve_key_bits(azihsm_ecc_curve curve);

// Helper function to generate an EC key pair for derivation operations
azihsm_status generate_ec_key_pair_for_derive(
>>>>>>> main
    azihsm_handle session_handle,
    azihsm_handle &pub_key_handle,
    azihsm_handle &priv_key_handle,
    azihsm_ecc_curve curve
<<<<<<< HEAD
)
{
    azihsm_algo ec_keygen_algo = { .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
                                   .params = nullptr,
                                   .len = 0 };

    // Common properties
    azihsm_key_kind key_kind = AZIHSM_KEY_KIND_ECC;
    bool derive_prop = true;

    // Public key properties
    azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;
    std::vector<azihsm_key_prop> pub_props;
    pub_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) }
    );
    pub_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
    );
    pub_props.push_back({ .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) });
    pub_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &derive_prop, .len = sizeof(derive_prop) }
    );

    // Private key properties
    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;

    std::vector<azihsm_key_prop> priv_props;
    priv_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &priv_key_class, .len = sizeof(priv_key_class) }
    );
    priv_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
    );
    priv_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) }
    );
    priv_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &derive_prop, .len = sizeof(derive_prop) }
    );

    azihsm_key_prop_list pub_prop_list = { .props = pub_props.data(),
                                           .count = static_cast<uint32_t>(pub_props.size()) };
    azihsm_key_prop_list priv_prop_list = { .props = priv_props.data(),
                                            .count = static_cast<uint32_t>(priv_props.size()) };

    return azihsm_key_gen_pair(
        session_handle,
        &ec_keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
}

// Helper function to derive a shared secret key via ECDH
// Returns the shared secret key handle via out_shared_secret_handle
inline azihsm_status derive_shared_secret_via_ecdh(
=======
);

// Helper function to derive a shared secret key via ECDH
// Returns the shared secret key handle via out_shared_secret_handle
azihsm_status derive_shared_secret_via_ecdh(
>>>>>>> main
    azihsm_handle session_handle,
    azihsm_handle priv_key_handle,
    azihsm_handle peer_pub_key_handle,
    azihsm_ecc_curve curve,
    azihsm_handle &out_shared_secret_handle
<<<<<<< HEAD
)
{
    azihsm_status err;

    // Get peer's public key in DER format for ECDH
    std::vector<uint8_t> peer_pub_key_data(512);
    uint32_t peer_pub_key_len = static_cast<uint32_t>(peer_pub_key_data.size());

    azihsm_buffer pub_key_buffer = { .ptr = peer_pub_key_data.data(), .len = peer_pub_key_len };

    azihsm_key_prop pub_key_prop = { .id = AZIHSM_KEY_PROP_ID_PUB_KEY_INFO,
                                     .val = peer_pub_key_data.data(),
                                     .len = peer_pub_key_len };

    err = azihsm_key_get_prop(peer_pub_key_handle, &pub_key_prop);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    // Update the actual length returned
    peer_pub_key_len = pub_key_prop.len;
    pub_key_buffer.len = peer_pub_key_len;

    // Perform ECDH derivation to get shared secret
    azihsm_algo_ecdh_params ecdh_params = { .pub_key = &pub_key_buffer };
    azihsm_algo ecdh_algo = { .id = AZIHSM_ALGO_ID_ECDH,
                              .params = &ecdh_params,
                              .len = sizeof(ecdh_params) };

    // Properties for the shared secret key
    bool derive_prop = true;
    bool is_session = true;
    azihsm_key_class secret_class = AZIHSM_KEY_CLASS_SECRET;
    azihsm_key_kind secret_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
    uint32_t key_bits = get_curve_key_bits(curve);

    std::vector<azihsm_key_prop> secret_props;
    secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &secret_class, .len = sizeof(secret_class) }
    );
    secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &secret_kind, .len = sizeof(secret_kind) }
    );
    secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &key_bits, .len = sizeof(key_bits) }
    );
    secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &derive_prop, .len = sizeof(derive_prop) }
    );
    secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) }
    );

    azihsm_key_prop_list secret_prop_list = { .props = secret_props.data(),
                                              .count =
                                                  static_cast<uint32_t>(secret_props.size()) };

    return azihsm_key_derive(
        session_handle,
        &ecdh_algo,
        priv_key_handle,
        &secret_prop_list,
        &out_shared_secret_handle
    );
}
=======
);
>>>>>>> main

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