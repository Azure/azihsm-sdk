// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <vector>

#include "aes_keygen.hpp"
#include "utils/auto_key.hpp"

void session_aes_key_generation_common(
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Verify key properties
    verify_generated_aes_key_properties(original_key, key_kind, bits, is_session);

    // Step 3: Delete the key
    azihsm_handle key_handle = original_key.release();
    err = azihsm_key_delete(key_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

void verify_generated_aes_key_properties(
    azihsm_handle key_handle,
    azihsm_key_kind key_kind,
    uint32_t bits,
    bool is_session
)
{
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_CLASS, AZIHSM_KEY_CLASS_SECRET);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_KIND, key_kind);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_BIT_LEN, bits);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_LOCAL, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SESSION, is_session);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SENSITIVE, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_EXTRACTABLE, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_ENCRYPT, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_DECRYPT, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SIGN, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_VERIFY, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_WRAP, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_UNWRAP, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_DERIVE, false);
}

void aes_key_gen_invalid_props_fail_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    std::vector<azihsm_key_prop_id> flag_prop_ids
)
{
    // Step 1: Attempt to generate invalid AES key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = true;

    std::vector<azihsm_key_prop> props_vec = {
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) }
    };

    // Add flag properties
    std::vector<uint8_t> flag_values(flag_prop_ids.size(), 1);
    for (size_t i = 0; i < flag_prop_ids.size(); i++)
    {
        props_vec.push_back(
            { .id = flag_prop_ids[i], .val = &flag_values[i], .len = sizeof(flag_values[i]) }
        );
    }

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    ASSERT_EQ(original_key, 0);
}

void aes_key_gen_multiple_invalid_capabilities_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    bool invalid_flag_sets[16][5] = {
        { true, false, false, false, false }, // sign
        { false, true, false, false, false }, // verify
        { false, false, true, false, false }, // wrap
        { false, false, false, true, false }, // unwrap
        { false, false, false, false, true }, // derive
        { true, true, false, false, false },  // sign + verify
        { true, false, true, false, false },  // sign + wrap
        { true, false, false, true, false },  // sign + unwrap
        { true, false, false, false, true },  // sign + derive
        { false, true, true, false, false },  // verify + wrap
        { false, true, false, true, false },  // verify + unwrap
        { false, true, false, false, true },  // verify + derive
        { false, false, true, true, false },  // wrap + unwrap
        { false, false, true, false, true },  // wrap + derive
        { false, false, false, true, true },  // unwrap + derive
        { true, true, true, true, true },     // all invalid flags
    };

    for (bool *flag_set : invalid_flag_sets)
    {
        std::vector<azihsm_key_prop_id> invalid_props;
        invalid_props.push_back(AZIHSM_KEY_PROP_ID_ENCRYPT);
        invalid_props.push_back(AZIHSM_KEY_PROP_ID_DECRYPT);
        if (flag_set[0])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_SIGN);
        if (flag_set[1])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_VERIFY);
        if (flag_set[2])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_WRAP);
        if (flag_set[3])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_UNWRAP);
        if (flag_set[4])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_DERIVE);

        aes_key_gen_invalid_props_fail_common(session, algo_id, key_kind, bits, invalid_props);
    }
}

void aes_key_gen_persistent_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate AES key with non-session persistence
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = false;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Verify key has correct AZIHSM_KEY_PROP_ID_SESSION property
    verify_key_property(original_key, AZIHSM_KEY_PROP_ID_SESSION, false);

    // Step 3: Delete the key
    azihsm_handle key_handle = original_key.release();
    err = azihsm_key_delete(key_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}
