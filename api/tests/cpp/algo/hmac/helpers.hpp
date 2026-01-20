// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include "utils/auto_key.hpp"
#include <azihsm_api.h>
#include <vector>

// Helper struct to manage ECDH key pairs with automatic cleanup
struct EcdhKeyPairs
{
    azihsm_handle server_pub_key = 0;
    azihsm_handle server_priv_key = 0;
    azihsm_handle client_pub_key = 0;
    azihsm_handle client_priv_key = 0;
    azihsm_handle session_handle = 0;

    ~EcdhKeyPairs()
    {
        if (server_pub_key != 0)
            azihsm_key_delete(server_pub_key);
        if (server_priv_key != 0)
            azihsm_key_delete(server_priv_key);
        if (client_pub_key != 0)
            azihsm_key_delete(client_pub_key);
        if (client_priv_key != 0)
            azihsm_key_delete(client_priv_key);
    }
};

// Helper function to get key size in bits from EC curve
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

// Helper function to get expected HMAC key size in bits from HMAC key kind.
inline uint32_t get_hmac_key_bits(azihsm_key_kind hmac_key_kind)
{
    switch (hmac_key_kind)
    {
    case AZIHSM_KEY_KIND_HMAC_SHA256:
        return 256;
    case AZIHSM_KEY_KIND_HMAC_SHA384:
        return 384;
    case AZIHSM_KEY_KIND_HMAC_SHA512:
        return 512;
    default:
        return 256;
    }
}

azihsm_status generate_ec_key_pair_for_derive(
    azihsm_handle session_handle,
    azihsm_handle &pub_key_handle,
    azihsm_handle &priv_key_handle,
    azihsm_ecc_curve curve
)
{
    azihsm_algo ec_keygen_algo = { .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
                                   .params = nullptr,
                                   .len = 0 };

    // Common properties
    azihsm_key_kind key_kind = AZIHSM_KEY_KIND_ECC;

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

    // Private key properties
    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    bool derive_prop = true;
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

azihsm_status derive_hmac_key_via_ecdh_hkdf(
    azihsm_handle session_handle,
    azihsm_handle server_priv_key,
    azihsm_handle client_pub_key,
    azihsm_key_kind hmac_key_kind,
    azihsm_handle &hmac_key_handle,
    azihsm_ecc_curve curve,
    azihsm_handle *base_secret_handle = nullptr
)
{
    azihsm_status err;

    // Step 1: Get client's public key in DER format for ECDH
    std::vector<uint8_t> client_pub_key_data(512);
    uint32_t client_pub_key_len = static_cast<uint32_t>(client_pub_key_data.size());

    azihsm_buffer pub_key_buffer = { .ptr = client_pub_key_data.data(), .len = client_pub_key_len };

    azihsm_key_prop pub_key_prop = { .id = AZIHSM_KEY_PROP_ID_PUB_KEY_INFO,
                                     .val = client_pub_key_data.data(),
                                     .len = client_pub_key_len };

    err = azihsm_key_get_prop(client_pub_key, &pub_key_prop);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    // Update the actual length returned
    client_pub_key_len = pub_key_prop.len;
    pub_key_buffer.len = client_pub_key_len;

    // Step 2: Perform ECDH derivation to get base secret
    azihsm_algo_ecdh_params ecdh_params = { .pub_key = &pub_key_buffer };
    azihsm_algo ecdh_algo = { .id = AZIHSM_ALGO_ID_ECDH,
                              .params = &ecdh_params,
                              .len = sizeof(ecdh_params) };

    // Properties for the secret key from ECDH
    // Use auto_key to ensure cleanup even on error
    auto_key temp_base_secret;
    bool ecdh_derive_prop = true;
    azihsm_key_class base_secret_class = AZIHSM_KEY_CLASS_SECRET;
    azihsm_key_kind base_secret_kind = AZIHSM_KEY_KIND_SHARED_SECRET;

    std::vector<azihsm_key_prop> base_secret_props;
    base_secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS,
          .val = &base_secret_class,
          .len = sizeof(base_secret_class) }
    );
    base_secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &base_secret_kind, .len = sizeof(base_secret_kind) }
    );
    base_secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DERIVE,
          .val = &ecdh_derive_prop,
          .len = sizeof(ecdh_derive_prop) }
    );
    // Get key bits from the EC curve
    uint32_t key_bits = get_curve_key_bits(curve);
    base_secret_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &key_bits, .len = sizeof(key_bits) }
    );

    azihsm_key_prop_list base_secret_prop_list = {
        .props = base_secret_props.data(),
        .count = static_cast<uint32_t>(base_secret_props.size())
    };

    err = azihsm_key_derive(
        session_handle,
        &ecdh_algo,
        server_priv_key,
        &base_secret_prop_list,
        &temp_base_secret.handle
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err; // auto_key will clean up temp_base_secret automatically
    }

    // Step 3: Use HKDF to derive HMAC key from base secret
    const char *salt = "test-salt-hmac-key";
    const char *info = "test-info-hmac-key";

    azihsm_buffer salt_buf = { .ptr = (uint8_t *)salt, .len = static_cast<uint32_t>(strlen(salt)) };
    azihsm_buffer info_buf = { .ptr = (uint8_t *)info, .len = static_cast<uint32_t>(strlen(info)) };

    azihsm_algo_hkdf_params hkdf_params = { .hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256,
                                            .salt = &salt_buf,
                                            .info = &info_buf };

    azihsm_algo hkdf_algo = { .id = AZIHSM_ALGO_ID_HKDF_DERIVE,
                              .params = &hkdf_params,
                              .len = sizeof(hkdf_params) };

    bool hmac_sign_prop = true;
    bool hmac_verify_prop = true;
    azihsm_key_class hmac_key_class = AZIHSM_KEY_CLASS_SECRET;
    azihsm_key_kind hmac_kind = hmac_key_kind;
    // For HMAC keys, the API expects the bit-length to match the digest size
    uint32_t hmac_key_bits = get_hmac_key_bits(hmac_key_kind);

    std::vector<azihsm_key_prop> hmac_key_props;
    hmac_key_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &hmac_key_class, .len = sizeof(hmac_key_class) }
    );
    hmac_key_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &hmac_kind, .len = sizeof(hmac_kind) }
    );
    hmac_key_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &hmac_key_bits, .len = sizeof(hmac_key_bits) }
    );
    hmac_key_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &hmac_sign_prop, .len = sizeof(hmac_sign_prop) }
    );
    hmac_key_props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_VERIFY,
          .val = &hmac_verify_prop,
          .len = sizeof(hmac_verify_prop) }
    );

    azihsm_key_prop_list hmac_key_prop_list = { .props = hmac_key_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(hmac_key_props.size()) };

    err = azihsm_key_derive(
        session_handle,
        &hkdf_algo,
        temp_base_secret.get(),
        &hmac_key_prop_list,
        &hmac_key_handle
    );

    // If caller wants to keep the base secret, transfer ownership
    if (base_secret_handle != nullptr && err == AZIHSM_STATUS_SUCCESS)
    {
        *base_secret_handle = temp_base_secret.handle;
        temp_base_secret.handle = 0; // Release ownership so auto_key won't delete it
    }
    // Otherwise, temp_base_secret will be automatically deleted by auto_key destructor

    return err;
}

// Helper function to generate EC key pairs and derive HMAC key
inline azihsm_status generate_ecdh_keys_and_derive_hmac(
    azihsm_handle session_handle,
    azihsm_key_kind hmac_key_type,
    EcdhKeyPairs &key_pairs,
    azihsm_handle &hmac_key_handle,
    azihsm_ecc_curve curve
)
{
    key_pairs.session_handle = session_handle;

    // Generate server EC key pair
    azihsm_status err = generate_ec_key_pair_for_derive(
        session_handle,
        key_pairs.server_pub_key,
        key_pairs.server_priv_key,
        curve
    );
    if (err != AZIHSM_STATUS_SUCCESS)
        return err;

    // Generate client EC key pair
    err = generate_ec_key_pair_for_derive(
        session_handle,
        key_pairs.client_pub_key,
        key_pairs.client_priv_key,
        curve
    );
    if (err != AZIHSM_STATUS_SUCCESS)
        return err;

    // Derive HMAC key
    err = derive_hmac_key_via_ecdh_hkdf(
        session_handle,
        key_pairs.server_priv_key,
        key_pairs.client_pub_key,
        hmac_key_type,
        hmac_key_handle,
        curve
    );

    return err;
}