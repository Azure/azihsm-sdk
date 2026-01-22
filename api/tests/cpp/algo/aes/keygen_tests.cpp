// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_aes_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to compare key properties
    static void compare_key_properties(
        azihsm_handle original_key,
        azihsm_handle unmasked_key,
        uint32_t expected_bits
    )
    {
        // Compare key class
        azihsm_key_class original_class, unmasked_class;
        uint32_t len = sizeof(azihsm_key_class);
        azihsm_key_prop prop{};
        
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &original_class;
        prop.len = len;
        azihsm_status err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_class;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_class, unmasked_class);

        // Compare key kind
        azihsm_key_kind original_kind, unmasked_kind;
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.len = sizeof(azihsm_key_kind);
        
        prop.val = &original_kind;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_kind;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_kind, unmasked_kind);
        EXPECT_EQ(original_kind, AZIHSM_KEY_KIND_AES);

        // Compare key bit length
        uint32_t original_bits, unmasked_bits;
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.len = sizeof(uint32_t);
        
        prop.val = &original_bits;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_bits;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_bits, unmasked_bits);
        EXPECT_EQ(original_bits, expected_bits);

        // Compare encrypt capability
        bool original_can_encrypt, unmasked_can_encrypt;
        prop.id = AZIHSM_KEY_PROP_ID_ENCRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_encrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_encrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_encrypt, unmasked_can_encrypt);

        // Compare decrypt capability
        bool original_can_decrypt, unmasked_can_decrypt;
        prop.id = AZIHSM_KEY_PROP_ID_DECRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_decrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_decrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_decrypt, unmasked_can_decrypt);
    }
};

TEST_F(azihsm_aes_keygen, unmask_aes_128_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 128;
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

        azihsm_handle original_key = 0;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, &original_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_key, 0);

        auto cleanup_original = scope_guard::make_scope_exit([original_key] {
            azihsm_key_delete(original_key);
        });

        // Step 2: Get masked key via property
        uint8_t *masked_key_ptr = nullptr;
        uint32_t masked_key_len = 0;
        
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = masked_key_ptr;
        masked_prop.len = masked_key_len;
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 3: Unmask the masked key
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle unmasked_key = 0;
        err = azihsm_key_unmask(session, AZIHSM_KEY_KIND_AES, &masked_key_buf, &unmasked_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_key, 0);

        auto cleanup_unmasked = scope_guard::make_scope_exit([unmasked_key] {
            azihsm_key_delete(unmasked_key);
        });

        // Step 4: Compare key properties
        compare_key_properties(original_key, unmasked_key, 128);
    });
}

