// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"

class azihsm_hmac_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Test data structure for HMAC key tests
struct HmacKeyTestParams
{
    azihsm_key_kind key_kind;
    azihsm_ecc_curve curve;
    uint32_t expected_bits;
    const char *test_name;
};

// Helper to verify all HMAC key properties
static void verify_hmac_key_properties(
    azihsm_handle hmac_key,
    azihsm_key_kind expected_kind,
    uint32_t expected_bits
)
{
    azihsm_status err;
    azihsm_key_prop prop{};

    // Verify key kind
    azihsm_key_kind actual_kind;
    prop.id = AZIHSM_KEY_PROP_ID_KIND;
    prop.val = &actual_kind;
    prop.len = sizeof(actual_kind);
    err = azihsm_key_get_prop(hmac_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_kind, expected_kind);

    // Verify key class
    azihsm_key_class actual_class;
    prop.id = AZIHSM_KEY_PROP_ID_CLASS;
    prop.val = &actual_class;
    prop.len = sizeof(actual_class);
    err = azihsm_key_get_prop(hmac_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_class, AZIHSM_KEY_CLASS_SECRET);

    // Verify bit length
    uint32_t actual_bits;
    prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
    prop.val = &actual_bits;
    prop.len = sizeof(actual_bits);
    err = azihsm_key_get_prop(hmac_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_bits, expected_bits);

    // Verify sign capability
    bool can_sign;
    prop.id = AZIHSM_KEY_PROP_ID_SIGN;
    prop.val = &can_sign;
    prop.len = sizeof(can_sign);
    err = azihsm_key_get_prop(hmac_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_TRUE(can_sign);

    // Verify verify capability
    bool can_verify;
    prop.id = AZIHSM_KEY_PROP_ID_VERIFY;
    prop.val = &can_verify;
    prop.len = sizeof(can_verify);
    err = azihsm_key_get_prop(hmac_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_TRUE(can_verify);
}

// Test HMAC key derivation and property verification for all algorithms
TEST_F(azihsm_hmac_keygen, derive_and_get_properties_all_algorithms)
{
    std::vector<HmacKeyTestParams> test_cases = {
        { AZIHSM_KEY_KIND_HMAC_SHA256, AZIHSM_ECC_CURVE_P256, 256, "HMAC-SHA256" },
        { AZIHSM_KEY_KIND_HMAC_SHA384, AZIHSM_ECC_CURVE_P384, 384, "HMAC-SHA384" },
        { AZIHSM_KEY_KIND_HMAC_SHA512, AZIHSM_ECC_CURVE_P521, 512, "HMAC-SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            // Generate EC key pairs and derive HMAC key
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            auto err = generate_ecdh_keys_and_derive_hmac(
                session,
                test_case.key_kind,
                key_pairs,
                hmac_key.handle,
                test_case.curve
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(hmac_key.get(), 0);

            // Verify all key properties
            verify_hmac_key_properties(hmac_key.get(), test_case.key_kind, test_case.expected_bits);
        });
    }
}

// Test key deletion
TEST_F(azihsm_hmac_keygen, delete_hmac_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(hmac_key.get(), 0);

        // Get the handle for deletion and release from auto_key to prevent double deletion
        azihsm_handle hmac_key_handle = hmac_key.release();

        // Delete the key
        err = azihsm_key_delete(hmac_key_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify key is no longer accessible
        azihsm_key_kind kind;
        azihsm_key_prop prop = { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        err = azihsm_key_get_prop(hmac_key_handle, &prop);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Negative tests for get property
TEST_F(azihsm_hmac_keygen, get_prop_negative)
{
    // Test with null prop
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_key_get_prop(hmac_key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });

    // Test with invalid key handles
    azihsm_key_kind kind;
    azihsm_key_prop prop = { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

    auto err = azihsm_key_get_prop(0, &prop);
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

    err = azihsm_key_get_prop(0xDEADBEEF, &prop);
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
}