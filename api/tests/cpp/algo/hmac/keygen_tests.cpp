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

// Helper to compare HMAC key properties between original and unmasked keys
static void compare_hmac_key_properties(
    azihsm_handle original_key,
    azihsm_handle unmasked_key,
    azihsm_key_kind expected_kind,
    uint32_t expected_bits
)
{
    azihsm_status err;
    azihsm_key_prop prop{};

    // Compare key kind
    azihsm_key_kind original_kind, unmasked_kind;
    prop.id = AZIHSM_KEY_PROP_ID_KIND;
    prop.len = sizeof(azihsm_key_kind);

    prop.val = &original_kind;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_kind;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_kind, unmasked_kind);
    ASSERT_EQ(original_kind, expected_kind);

    // Compare key class
    azihsm_key_class original_class, unmasked_class;
    prop.id = AZIHSM_KEY_PROP_ID_CLASS;
    prop.len = sizeof(azihsm_key_class);

    prop.val = &original_class;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_class;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_class, unmasked_class);
    ASSERT_EQ(original_class, AZIHSM_KEY_CLASS_SECRET);

    // Compare bit length
    uint32_t original_bits, unmasked_bits;
    prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
    prop.len = sizeof(uint32_t);

    prop.val = &original_bits;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_bits;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_bits, unmasked_bits);
    ASSERT_EQ(original_bits, expected_bits);

    // Compare sign capability
    bool original_sign, unmasked_sign;
    prop.id = AZIHSM_KEY_PROP_ID_SIGN;
    prop.len = sizeof(bool);

    prop.val = &original_sign;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_sign;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_sign, unmasked_sign);
    ASSERT_TRUE(original_sign);

    // Compare verify capability
    bool original_verify, unmasked_verify;
    prop.id = AZIHSM_KEY_PROP_ID_VERIFY;
    prop.len = sizeof(bool);

    prop.val = &original_verify;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_verify;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_verify, unmasked_verify);
    ASSERT_TRUE(original_verify);
}

// Common test function for unmasking HMAC keys
static void test_hmac_key_unmask(
    azihsm_handle session,
    azihsm_key_kind hmac_key_kind,
    azihsm_ecc_curve curve
)
{
    uint32_t expected_bits = get_hmac_key_bits(hmac_key_kind);

    // Step 1: Generate EC key pairs and derive HMAC key
    EcdhKeyPairSet key_pairs;
    auto_key original_hmac_key;

    azihsm_status err = generate_ecdh_keys_and_derive_hmac(
        session,
        hmac_key_kind,
        key_pairs,
        original_hmac_key.handle,
        curve
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_hmac_key.get(), 0);

    // Step 2: Get masked key via property
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0u);

    std::vector<uint8_t> masked_key_data(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Step 3: Unmask the masked key
    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_hmac_key;
    err = azihsm_key_unmask(session, hmac_key_kind, &masked_key_buf, unmasked_hmac_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_hmac_key.get(), 0);

    // Step 4: Compare key properties
    compare_hmac_key_properties(
        original_hmac_key.get(),
        unmasked_hmac_key.get(),
        hmac_key_kind,
        expected_bits
    );
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

// Test HMAC-SHA256 key unmask
TEST_F(azihsm_hmac_keygen, unmask_hmac_sha256_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_hmac_key_unmask(session, AZIHSM_KEY_KIND_HMAC_SHA256, AZIHSM_ECC_CURVE_P256);
    });
}

// Test HMAC-SHA384 key unmask
TEST_F(azihsm_hmac_keygen, unmask_hmac_sha384_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_hmac_key_unmask(session, AZIHSM_KEY_KIND_HMAC_SHA384, AZIHSM_ECC_CURVE_P384);
    });
}

// Test HMAC-SHA512 key unmask
TEST_F(azihsm_hmac_keygen, unmask_hmac_sha512_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_hmac_key_unmask(session, AZIHSM_KEY_KIND_HMAC_SHA512, AZIHSM_ECC_CURVE_P521);
    });
}

// Test that unmasked HMAC key can be used for sign/verify operations
TEST_F(azihsm_hmac_keygen, unmask_and_use_hmac_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Derive and unmask HMAC-SHA256 key
        EcdhKeyPairSet key_pairs;
        auto_key original_hmac_key;

        azihsm_status err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            original_hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Get masked key
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = nullptr;
        masked_prop.len = 0;

        err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();

        err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Unmask key
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_hmac_key;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &masked_key_buf,
            unmasked_hmac_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Use unmasked key for sign operation
        const char *test_data = "Test data for HMAC signing with unmasked key";
        azihsm_buffer data_buf = { .ptr = (uint8_t *)test_data,
                                   .len = static_cast<uint32_t>(strlen(test_data)) };

        // Get signature size first
        azihsm_algo hmac_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

        err = azihsm_crypt_sign(&hmac_algo, unmasked_hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0u);

        // Perform actual signing
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();

        err = azihsm_crypt_sign(&hmac_algo, unmasked_hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify with unmasked key
        azihsm_buffer verify_sig_buf = { .ptr = signature.data(),
                                         .len = static_cast<uint32_t>(signature.size()) };

        err = azihsm_crypt_verify(&hmac_algo, unmasked_hmac_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Cross-verify: signature from unmasked key should verify with original key
        err = azihsm_crypt_verify(&hmac_algo, original_hmac_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Negative test: unmask with null buffer
TEST_F(azihsm_hmac_keygen, unmask_null_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key unmasked_key;
        azihsm_status err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            nullptr,
            unmasked_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Negative test: unmask with invalid masked key data
TEST_F(azihsm_hmac_keygen, unmask_invalid_data)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> invalid_data = { 0x00, 0x01, 0x02, 0x03 };
        azihsm_buffer invalid_buf = { .ptr = invalid_data.data(),
                                      .len = static_cast<uint32_t>(invalid_data.size()) };

        auto_key unmasked_key;
        azihsm_status err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &invalid_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}