// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstdint>
#include <vector>

/// Key properties
typedef struct _KeyProps
{
    azihsm_key_class key_class;
    azihsm_key_kind key_kind;
    uint32_t key_size_bits;
    bool session_key = true;
    bool sign = false;
    bool verify = false;
    bool encrypt = false;
    bool decrypt = false;
    bool derive = false;
    bool wrap = false;
    bool unwrap = false;
} key_props;

/// Helper method to build an azihsm_key_prop_list from a key_props struct
inline azihsm_key_prop_list build_key_prop_list(
    key_props &props,
    std::vector<azihsm_key_prop> &prop_vec
)
{
    prop_vec.clear();
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &props.key_class, .len = sizeof(props.key_class) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &props.key_kind, .len = sizeof(props.key_kind) }
    );
    prop_vec.push_back({ .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
                         .val = &props.key_size_bits,
                         .len = sizeof(props.key_size_bits) });
    prop_vec.push_back({ .id = AZIHSM_KEY_PROP_ID_SESSION,
                         .val = &props.session_key,
                         .len = sizeof(props.session_key) });
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_SIGN, .val = &props.sign, .len = sizeof(props.sign) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &props.verify, .len = sizeof(props.verify) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &props.encrypt, .len = sizeof(props.encrypt) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &props.decrypt, .len = sizeof(props.decrypt) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &props.derive, .len = sizeof(props.derive) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = &props.wrap, .len = sizeof(props.wrap) }
    );
    prop_vec.push_back(
        { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &props.unwrap, .len = sizeof(props.unwrap) }
    );

    azihsm_key_prop_list prop_list = { .props = prop_vec.data(),
                                       .count = static_cast<uint32_t>(prop_vec.size()) };

    return prop_list;
}