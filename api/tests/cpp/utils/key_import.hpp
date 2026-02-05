// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "key_props.hpp"
#include <azihsm_api.h>
#include <vector>

/// Helper function to import a key pair (RSA or ECC) using RSA-AES key wrapping
inline azihsm_status import_keypair(
    azihsm_handle wrapping_pub_key,
    azihsm_handle wrapping_priv_key,
    const std::vector<uint8_t> &key_der,
    key_props props,
    azihsm_handle *imported_priv_key,
    azihsm_handle *imported_pub_key
)
{
    // Step 1: Setup RSA-AES wrapping algorithm
    azihsm_algo_rsa_pkcs_oaep_params oaep_params = {};
    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = nullptr;

    azihsm_algo_rsa_aes_wrap_params wrap_params = {};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = 256; // AES-256

    azihsm_algo wrap_algo = {};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    // Step 2: Wrap the DER-encoded key
    azihsm_buffer input_key = {};
    input_key.ptr = const_cast<uint8_t *>(key_der.data());
    input_key.len = static_cast<uint32_t>(key_der.size());

    std::vector<uint8_t> wrapped_key_data(4096);
    azihsm_buffer wrapped_key_buf = {};
    wrapped_key_buf.ptr = wrapped_key_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_key_data.size());

    auto wrap_err =
        azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &input_key, &wrapped_key_buf);
    if (wrap_err != AZIHSM_STATUS_SUCCESS)
    {
        return wrap_err;
    }

    // Step 3: Setup unwrap algorithm
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {};
    unwrap_params.oaep_params = &oaep_params;

    azihsm_algo unwrap_algo = {};
    unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    unwrap_algo.params = &unwrap_params;
    unwrap_algo.len = sizeof(unwrap_params);

    // Step 4: Setup key properties based on key kind
    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;

    std::vector<azihsm_key_prop> priv_props_vec;
    std::vector<azihsm_key_prop> pub_props_vec;

    if (props.key_kind == AZIHSM_KEY_KIND_RSA)
    {
        // RSA private key properties (decrypt and sign capabilities)
        priv_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
              .val = &props.key_size_bits,
              .len = sizeof(props.key_size_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = &priv_key_class,
              .len = sizeof(priv_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT,
              .val = &props.decrypt,
              .len = sizeof(props.decrypt) },
            { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &props.sign, .len = sizeof(props.sign) }
        };

        // RSA public key properties (encrypt and verify capabilities)
        pub_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
              .val = &props.key_size_bits,
              .len = sizeof(props.key_size_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT,
              .val = &props.encrypt,
              .len = sizeof(props.encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &props.verify, .len = sizeof(props.verify) }
        };
    }
    else if (props.key_kind == AZIHSM_KEY_KIND_ECC)
    {
        // Determine ECC curve from key size
        azihsm_ecc_curve curve;
        switch (props.key_size_bits)
        {
        case 256:
            curve = AZIHSM_ECC_CURVE_P256;
            break;
        case 384:
            curve = AZIHSM_ECC_CURVE_P384;
            break;
        case 521:
            curve = AZIHSM_ECC_CURVE_P521;
            break;
        default:
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }

        // ECC private key properties (sign capability)
        priv_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = &priv_key_class,
              .len = sizeof(priv_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &props.sign, .len = sizeof(props.sign) }
        };

        // ECC public key properties (verify capability)
        pub_props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND,
              .val = &props.key_kind,
              .len = sizeof(props.key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION,
              .val = &props.session_key,
              .len = sizeof(props.session_key) },
            { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &props.verify, .len = sizeof(props.verify) }
        };
    }
    else
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    azihsm_key_prop_list priv_key_props = { .props = priv_props_vec.data(),
                                            .count = static_cast<uint32_t>(priv_props_vec.size()) };

    azihsm_key_prop_list pub_key_props = { .props = pub_props_vec.data(),
                                           .count = static_cast<uint32_t>(pub_props_vec.size()) };

    // Step 5: Unwrap the key pair
    return azihsm_key_unwrap_pair(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &priv_key_props,
        &pub_key_props,
        imported_priv_key,
        imported_pub_key
    );
}