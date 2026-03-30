// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "aes_keygen.hpp"

#include "key_props.hpp"

#include <gtest/gtest.h>
#include <vector>

#include "utils/auto_key.hpp"

void test_session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate AES key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = true;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> props_vec = {
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
        { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
        { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
    };

    azihsm_key_prop_list prop_list{
        .props = props_vec.data(),
        .count = static_cast<uint32_t>(props_vec.size())
    };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Verify key properties
    verify_generated_aes_key_properties(original_key, key_kind, bits, is_session);
    
    // Step 3: Delete the key
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();

}

template <typename T>
static void check_key_prop(azihsm_handle key_handle, azihsm_key_prop_id prop_id, T expected)
{
    T actual{};
    azihsm_key_prop prop{};
    prop.id = prop_id;
    prop.val = &actual;
    prop.len = sizeof(actual);
    azihsm_status err = azihsm_key_get_prop(key_handle, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    EXPECT_EQ(actual, expected);
}

void verify_generated_aes_key_properties(azihsm_handle key_handle, azihsm_key_kind key_kind, uint32_t bits, bool is_session)
{
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_CLASS,     AZIHSM_KEY_CLASS_SECRET);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_KIND,      key_kind);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_BIT_LEN,   bits);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_LOCAL,     true);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_SESSION,   is_session);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_SENSITIVE, true);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_EXTRACTABLE, true);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_ENCRYPT,   true);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_DECRYPT,   true);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_SIGN,      false);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_VERIFY,    false);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_UNWRAP,    false);
    check_key_prop(key_handle, AZIHSM_KEY_PROP_ID_DERIVE,    false);
}
