// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "rsa_keygen.hpp"

#include "key_props.hpp"

#include <vector>

azihsm_status generate_rsa_unwrapping_keypair(
    azihsm_handle session,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    key_props props = {
        .key_kind = AZIHSM_KEY_KIND_RSA,
        .key_size_bits = 2048,
        .session_key = false,
        .wrap = true,
        .unwrap = true,
    };

    azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;

    // Private key properties
    std::vector<azihsm_key_prop> priv_props_vec = std::vector<azihsm_key_prop>{
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = &props.key_size_bits,
          .len = sizeof(props.key_size_bits) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &priv_key_class, .len = sizeof(priv_key_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &props.key_kind, .len = sizeof(props.key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION,
          .val = &props.session_key,
          .len = sizeof(props.session_key) },
        { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &props.unwrap, .len = sizeof(props.unwrap) }
    };

    azihsm_key_prop_list priv_prop_list{ .props = priv_props_vec.data(),
                                         .count = static_cast<uint32_t>(priv_props_vec.size()) };

    // Public key properties
    std::vector<azihsm_key_prop> pub_props_vec = std::vector<azihsm_key_prop>{
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
          .val = &props.key_size_bits,
          .len = sizeof(props.key_size_bits) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &pub_key_class, .len = sizeof(pub_key_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &props.key_kind, .len = sizeof(props.key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION,
          .val = &props.session_key,
          .len = sizeof(props.session_key) },
        { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = &props.wrap, .len = sizeof(props.wrap) }
    };

    azihsm_key_prop_list pub_prop_list{ .props = pub_props_vec.data(),
                                        .count = static_cast<uint32_t>(pub_props_vec.size()) };

    return azihsm_key_gen_pair(
        session,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        priv_key_handle,
        pub_key_handle
    );
}
