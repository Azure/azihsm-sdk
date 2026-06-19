// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

// Helper to map an HMAC key kind to the matching sign/verify algorithm
static azihsm_algo_id hmac_algo_id_for_key_kind(azihsm_key_kind key_kind)
{
    switch (key_kind)
    {
    case AZIHSM_KEY_KIND_HMAC_SHA256:
        return AZIHSM_ALGO_ID_HMAC_SHA256;
    case AZIHSM_KEY_KIND_HMAC_SHA384:
        return AZIHSM_ALGO_ID_HMAC_SHA384;
    case AZIHSM_KEY_KIND_HMAC_SHA512:
        return AZIHSM_ALGO_ID_HMAC_SHA512;
    default:
        ADD_FAILURE() << "Unsupported HMAC key kind";
        return AZIHSM_ALGO_ID_HMAC_SHA256;
    }
}

// Helper to map an HMAC key kind to the ECDH curve used by the existing HMAC tests
static azihsm_ecc_curve ecc_curve_for_hmac_key_kind(azihsm_key_kind key_kind)
{
    switch (key_kind)
    {
    case AZIHSM_KEY_KIND_HMAC_SHA256:
        return AZIHSM_ECC_CURVE_P256;
    case AZIHSM_KEY_KIND_HMAC_SHA384:
        return AZIHSM_ECC_CURVE_P384;
    case AZIHSM_KEY_KIND_HMAC_SHA512:
        return AZIHSM_ECC_CURVE_P521;
    default:
        ADD_FAILURE() << "Unsupported HMAC key kind";
        return AZIHSM_ECC_CURVE_P256;
    }
}

// Helper to read a boolean key property
static bool read_bool_key_prop(azihsm_handle key, azihsm_key_prop_id prop_id)
{
    bool value = false;
    azihsm_key_prop prop = { .id = prop_id, .val = &value, .len = sizeof(value) };
    auto err = azihsm_key_get_prop(key, &prop);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    return value;
}

// Helper to derive an HMAC key with caller-provided derived-key properties
static azihsm_status derive_hmac_key_with_custom_props(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    azihsm_algo_id hkdf_hmac_algo_id,
    std::vector<azihsm_key_prop> &hmac_key_props,
    azihsm_handle &hmac_key_handle
)
{
    EcdhKeyPairSet key_pairs;
    azihsm_ecc_curve curve = ecc_curve_for_hmac_key_kind(key_kind);

    auto err = key_pairs.generate(session, curve);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    auto_key base_secret;
    err = derive_shared_secret_via_ecdh(
        session,
        key_pairs.priv_key_a.handle,
        key_pairs.pub_key_b.handle,
        curve,
        base_secret.handle
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    const char *salt = "test-salt-hmac-key";
    const char *info = "test-info-hmac-key";
    azihsm_buffer salt_buf = { .ptr = (uint8_t *)salt, .len = static_cast<uint32_t>(strlen(salt)) };
    azihsm_buffer info_buf = { .ptr = (uint8_t *)info, .len = static_cast<uint32_t>(strlen(info)) };

    azihsm_algo_hkdf_params hkdf_params = {
        .hmac_algo_id = hkdf_hmac_algo_id,
        .salt = &salt_buf,
        .info = &info_buf,
    };
    azihsm_algo hkdf_algo = {
        .id = AZIHSM_ALGO_ID_HKDF_DERIVE,
        .params = &hkdf_params,
        .len = sizeof(hkdf_params),
    };

    azihsm_key_prop_list hmac_key_prop_list = {
        .props = hmac_key_props.data(),
        .count = static_cast<uint32_t>(hmac_key_props.size()),
    };

    return azihsm_key_derive(
        session,
        &hkdf_algo,
        base_secret.get(),
        &hmac_key_prop_list,
        &hmac_key_handle
    );
}

// Helper to build common HMAC key properties for HKDF-derived HMAC keys
static std::vector<azihsm_key_prop> build_hmac_derive_props(
    azihsm_key_class &key_class,
    azihsm_key_kind &key_kind,
    uint32_t &bits,
    bool *can_sign,
    bool *can_verify
)
{
    std::vector<azihsm_key_prop> props = {
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
    };

    if (can_sign != nullptr)
    {
        props.push_back({ .id = AZIHSM_KEY_PROP_ID_SIGN, .val = can_sign, .len = sizeof(*can_sign) }
        );
    }

    if (can_verify != nullptr)
    {
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_VERIFY, .val = can_verify, .len = sizeof(*can_verify) }
        );
    }

    return props;
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
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
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
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_key_get_prop(0xDEADBEEF, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
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
        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
    });
}

// Test that masked-key property reports required size and rejects too-small buffers
TEST_F(azihsm_hmac_keygen, get_masked_key_prop_rejects_too_small_buffer)
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

        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = nullptr;
        masked_prop.len = 0;

        err = azihsm_key_get_prop(hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 1u);

        const uint32_t required_len = masked_prop.len;
        std::vector<uint8_t> too_small(required_len - 1);
        masked_prop.val = too_small.data();
        masked_prop.len = static_cast<uint32_t>(too_small.size());

        err = azihsm_key_get_prop(hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GE(masked_prop.len, required_len);
    });
}

// Test that unmask rejects a null output key pointer
TEST_F(azihsm_hmac_keygen, unmask_null_output_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> invalid_data = { 0x00, 0x01, 0x02, 0x03 };
        azihsm_buffer invalid_buf = { .ptr = invalid_data.data(),
                                      .len = static_cast<uint32_t>(invalid_data.size()) };

        azihsm_status err =
            azihsm_key_unmask(session, AZIHSM_KEY_KIND_HMAC_SHA256, &invalid_buf, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Test that unmask rejects a masked-key buffer with null data pointer
TEST_F(azihsm_hmac_keygen, unmask_buffer_with_null_data_pointer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_buffer invalid_buf = { .ptr = nullptr, .len = 16 };

        auto_key unmasked_key;
        azihsm_status err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &invalid_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(unmasked_key.get(), 0);
    });
}

// Test that unmask rejects an empty masked-key buffer
TEST_F(azihsm_hmac_keygen, unmask_empty_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        uint8_t dummy = 0;
        azihsm_buffer empty_buf = { .ptr = &dummy, .len = 0 };

        auto_key unmasked_key;
        azihsm_status err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &empty_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);

        ASSERT_EQ(unmasked_key.get(), 0);
    });
}

// Test that unmasked HMAC keys can sign and verify for every supported HMAC algorithm
TEST_F(azihsm_hmac_keygen, unmask_and_use_hmac_key_all_algorithms)
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
            EcdhKeyPairSet key_pairs;
            auto_key original_hmac_key;

            auto err = generate_ecdh_keys_and_derive_hmac(
                session,
                test_case.key_kind,
                key_pairs,
                original_hmac_key.handle,
                test_case.curve
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(original_hmac_key.get(), 0);

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

            azihsm_buffer masked_key_buf = { .ptr = masked_key_data.data(),
                                             .len = static_cast<uint32_t>(masked_key_data.size()) };

            auto_key unmasked_hmac_key;
            err = azihsm_key_unmask(
                session,
                test_case.key_kind,
                &masked_key_buf,
                unmasked_hmac_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(unmasked_hmac_key.get(), 0);

            const char *test_data = "Test data for unmasked HMAC signing";
            azihsm_buffer data_buf = { .ptr = (uint8_t *)test_data,
                                       .len = static_cast<uint32_t>(strlen(test_data)) };

            azihsm_algo hmac_algo = { .id = hmac_algo_id_for_key_kind(test_case.key_kind),
                                      .params = nullptr,
                                      .len = 0 };
            azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
            err = azihsm_crypt_sign(&hmac_algo, unmasked_hmac_key.get(), &data_buf, &sig_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(sig_buf.len, test_case.expected_bits / 8);

            std::vector<uint8_t> signature(sig_buf.len);
            sig_buf.ptr = signature.data();

            err = azihsm_crypt_sign(&hmac_algo, unmasked_hmac_key.get(), &data_buf, &sig_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer verify_sig_buf = { .ptr = signature.data(),
                                             .len = static_cast<uint32_t>(signature.size()) };

            err = azihsm_crypt_verify(
                &hmac_algo,
                unmasked_hmac_key.get(),
                &data_buf,
                &verify_sig_buf
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            err = azihsm_crypt_verify(
                &hmac_algo,
                original_hmac_key.get(),
                &data_buf,
                &verify_sig_buf
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        });
    }
}

// Test that HMAC verify fails when the message or signature is modified
TEST_F(azihsm_hmac_keygen, hmac_verify_rejects_modified_data_and_signature)
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

        const char *test_data = "Original HMAC message";
        azihsm_buffer data_buf = { .ptr = (uint8_t *)test_data,
                                   .len = static_cast<uint32_t>(strlen(test_data)) };

        azihsm_algo hmac_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0u);

        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();

        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const char *modified_data = "Modified HMAC message";
        azihsm_buffer modified_data_buf = { .ptr = (uint8_t *)modified_data,
                                            .len = static_cast<uint32_t>(strlen(modified_data)) };
        azihsm_buffer verify_sig_buf = { .ptr = signature.data(),
                                         .len = static_cast<uint32_t>(signature.size()) };

        err = azihsm_crypt_verify(&hmac_algo, hmac_key.get(), &modified_data_buf, &verify_sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_SIGNATURE);

        signature[0] ^= 0x01;
        verify_sig_buf.ptr = signature.data();
        verify_sig_buf.len = static_cast<uint32_t>(signature.size());

        err = azihsm_crypt_verify(&hmac_algo, hmac_key.get(), &data_buf, &verify_sig_buf);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Parity with Rust: HMAC derived key rejects non-secret key classes
TEST_F(azihsm_hmac_keygen, derive_rejects_invalid_hmac_key_classes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        for (auto invalid_class : { AZIHSM_KEY_CLASS_PUBLIC, AZIHSM_KEY_CLASS_PRIVATE })
        {
            azihsm_key_class key_class = invalid_class;
            azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            uint32_t bits = 256;
            bool can_sign = true;
            bool can_verify = true;

            auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);

            azihsm_handle hmac_key = 0;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                hmac_key
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

            ASSERT_EQ(hmac_key, 0);
        }
    });
}

// Parity with Rust: HMAC derived key rejects non-HMAC key kind
TEST_F(azihsm_hmac_keygen, derive_rejects_non_hmac_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        uint32_t bits = 256;
        bool can_sign = true;
        bool can_verify = true;

        auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);

        azihsm_handle hmac_key = 0;
        auto err = derive_hmac_key_with_custom_props(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            hmac_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

        ASSERT_EQ(hmac_key, 0);
    });
}

// Parity with Rust: HMAC derived key rejects ECC curve metadata
TEST_F(azihsm_hmac_keygen, derive_rejects_hmac_key_with_ecc_curve_prop)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
        uint32_t bits = 256;
        bool can_sign = true;
        bool can_verify = true;
        azihsm_ecc_curve curve = AZIHSM_ECC_CURVE_P256;

        auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);
        props.push_back({ .id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve) });

        azihsm_handle hmac_key = 0;
        auto err = derive_hmac_key_with_custom_props(
            session,
            key_kind,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            hmac_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

        ASSERT_EQ(hmac_key, 0);
    });
}

// Parity with Rust: HMAC derived key rejects missing sign/verify usage flags
TEST_F(azihsm_hmac_keygen, derive_rejects_missing_hmac_usage_flags)
{
    part_list_.for_each_session([](azihsm_handle session) {
        struct MissingUsageCase
        {
            bool include_sign;
            bool include_verify;
            const char *case_name;
        };

        for (const auto &test_case : {
                 MissingUsageCase{ false, true, "missing sign" },
                 MissingUsageCase{ true, false, "missing verify" },
                 MissingUsageCase{ false, false, "missing sign and verify" },
             })
        {
            SCOPED_TRACE(test_case.case_name);

            azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
            azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            uint32_t bits = 256;
            bool can_sign = true;
            bool can_verify = true;

            auto props = build_hmac_derive_props(
                key_class,
                key_kind,
                bits,
                test_case.include_sign ? &can_sign : nullptr,
                test_case.include_verify ? &can_verify : nullptr
            );

            azihsm_handle hmac_key = 0;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                hmac_key
            );
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(hmac_key, 0);
        }
    });
}

// Parity with Rust: HMAC derived key rejects invalid bit lengths for every HMAC kind
TEST_F(azihsm_hmac_keygen, derive_rejects_invalid_hmac_bits_all_kinds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        struct InvalidBitsCase
        {
            azihsm_key_kind key_kind;
            uint32_t bad_bits;
            const char *case_name;
        };

        for (const auto &test_case : {
                 InvalidBitsCase{ AZIHSM_KEY_KIND_HMAC_SHA256, 0, "SHA256 zero bits" },
                 InvalidBitsCase{ AZIHSM_KEY_KIND_HMAC_SHA256, 128, "SHA256 short bits" },
                 InvalidBitsCase{ AZIHSM_KEY_KIND_HMAC_SHA256, 1024, "SHA256 oversized bits" },
                 InvalidBitsCase{ AZIHSM_KEY_KIND_HMAC_SHA384, 256, "SHA384 wrong bits" },
                 InvalidBitsCase{ AZIHSM_KEY_KIND_HMAC_SHA512, 384, "SHA512 wrong bits" },
             })
        {
            SCOPED_TRACE(test_case.case_name);

            azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
            azihsm_key_kind key_kind = test_case.key_kind;
            uint32_t bits = test_case.bad_bits;
            bool can_sign = true;
            bool can_verify = true;

            auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);

            azihsm_handle hmac_key = 0;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                hmac_algo_id_for_key_kind(key_kind),
                props,
                hmac_key
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

            ASSERT_EQ(hmac_key, 0);
        }
    });
}

// Parity with Rust: HMAC derived key rejects unsupported usage flags
TEST_F(azihsm_hmac_keygen, derive_rejects_unsupported_hmac_usage_flags)
{
    part_list_.for_each_session([](azihsm_handle session) {
        struct UnsupportedFlagCase
        {
            azihsm_key_prop_id prop_id;
            const char *case_name;
        };

        for (const auto &test_case : {
                 UnsupportedFlagCase{ AZIHSM_KEY_PROP_ID_ENCRYPT, "encrypt" },
                 UnsupportedFlagCase{ AZIHSM_KEY_PROP_ID_DECRYPT, "decrypt" },
                 UnsupportedFlagCase{ AZIHSM_KEY_PROP_ID_WRAP, "wrap" },
                 UnsupportedFlagCase{ AZIHSM_KEY_PROP_ID_UNWRAP, "unwrap" },
                 UnsupportedFlagCase{ AZIHSM_KEY_PROP_ID_DERIVE, "derive" },
             })
        {
            SCOPED_TRACE(test_case.case_name);

            azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
            azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            uint32_t bits = 256;
            bool can_sign = true;
            bool can_verify = true;
            bool unsupported_flag = true;

            auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);
            props.push_back({ .id = test_case.prop_id,
                              .val = &unsupported_flag,
                              .len = sizeof(unsupported_flag) });

            azihsm_handle hmac_key = 0;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                hmac_key
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

            ASSERT_EQ(hmac_key, 0);
        }
    });
}

// Parity with Rust: explicit false unsupported flags are allowed with valid sign/verify flags
TEST_F(azihsm_hmac_keygen, derive_allows_explicit_false_unsupported_hmac_flags)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
        uint32_t bits = 256;
        bool can_sign = true;
        bool can_verify = true;
        bool false_flag = false;

        auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &false_flag, .len = sizeof(false_flag) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &false_flag, .len = sizeof(false_flag) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_WRAP, .val = &false_flag, .len = sizeof(false_flag) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &false_flag, .len = sizeof(false_flag) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &false_flag, .len = sizeof(false_flag) }
        );

        auto_key hmac_key;
        auto err = derive_hmac_key_with_custom_props(
            session,
            key_kind,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            hmac_key.handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(hmac_key.get(), 0);

        verify_hmac_key_properties(hmac_key.get(), key_kind, bits);
        ASSERT_FALSE(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_ENCRYPT));
        ASSERT_FALSE(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_DECRYPT));
        ASSERT_FALSE(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_WRAP));
        ASSERT_FALSE(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_UNWRAP));
        ASSERT_FALSE(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_DERIVE));
    });
}

// Parity with Rust: session and non-session flags are preserved on derived HMAC keys
TEST_F(azihsm_hmac_keygen, derive_preserves_hmac_session_flag)
{
    part_list_.for_each_session([](azihsm_handle session) {
        for (bool session_flag : { true, false })
        {
            SCOPED_TRACE(session_flag ? "session key" : "non-session key");

            azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
            azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
            uint32_t bits = 256;
            bool can_sign = true;
            bool can_verify = true;
            bool is_session = session_flag;

            auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);
            props.push_back(
                { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) }
            );

            auto_key hmac_key;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                hmac_key.handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(hmac_key.get(), 0);

            ASSERT_EQ(read_bool_key_prop(hmac_key.get(), AZIHSM_KEY_PROP_ID_SESSION), session_flag);
            verify_hmac_key_properties(hmac_key.get(), key_kind, bits);
        }
    });
}

// Parity with Rust: HKDF hash algorithm may differ from the derived HMAC key kind
TEST_F(azihsm_hmac_keygen, derive_allows_hkdf_hash_mismatch_all_hmac_kinds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        struct HashMismatchCase
        {
            azihsm_key_kind key_kind;
            uint32_t bits;
            azihsm_algo_id hkdf_hmac_algo_id;
            const char *case_name;
        };

        for (const auto &test_case : {
                 HashMismatchCase{
                     AZIHSM_KEY_KIND_HMAC_SHA256,
                     256,
                     AZIHSM_ALGO_ID_HMAC_SHA384,
                     "HMAC-SHA256 from HKDF-SHA384",
                 },
                 HashMismatchCase{
                     AZIHSM_KEY_KIND_HMAC_SHA384,
                     384,
                     AZIHSM_ALGO_ID_HMAC_SHA512,
                     "HMAC-SHA384 from HKDF-SHA512",
                 },
                 HashMismatchCase{
                     AZIHSM_KEY_KIND_HMAC_SHA512,
                     512,
                     AZIHSM_ALGO_ID_HMAC_SHA256,
                     "HMAC-SHA512 from HKDF-SHA256",
                 },
             })
        {
            SCOPED_TRACE(test_case.case_name);

            azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
            azihsm_key_kind key_kind = test_case.key_kind;
            uint32_t bits = test_case.bits;
            bool can_sign = true;
            bool can_verify = true;

            auto props = build_hmac_derive_props(key_class, key_kind, bits, &can_sign, &can_verify);

            auto_key hmac_key;
            auto err = derive_hmac_key_with_custom_props(
                session,
                key_kind,
                test_case.hkdf_hmac_algo_id,
                props,
                hmac_key.handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(hmac_key.get(), 0);

            verify_hmac_key_properties(hmac_key.get(), key_kind, bits);
        }
    });
}

// Parity with Rust: combining multiple invalid HMAC properties is rejected
TEST_F(azihsm_hmac_keygen, derive_rejects_multiple_invalid_hmac_props)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_HMAC_SHA256;
        uint32_t bits = 128;
        bool can_encrypt = true;

        std::vector<azihsm_key_prop> props = {
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
        };

        azihsm_handle hmac_key = 0;
        auto err = derive_hmac_key_with_custom_props(
            session,
            key_kind,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            hmac_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);

        ASSERT_EQ(hmac_key, 0);
    });
}

// Test that unmask rejects a truncated valid masked-key blob
TEST_F(azihsm_hmac_keygen, unmask_rejects_truncated_masked_key_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key original_hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            original_hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = nullptr;
        masked_prop.len = 0;

        err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 1u);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();

        err = azihsm_key_get_prop(original_hmac_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer truncated_buf = { .ptr = masked_key_data.data(),
                                        .len = static_cast<uint32_t>(masked_key_data.size() - 1) };

        auto_key unmasked_key;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &truncated_buf,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);

        ASSERT_EQ(unmasked_key.get(), 0);
    });
}

// Test that unmask rejects a corrupted valid masked-key blob
TEST_F(azihsm_hmac_keygen, unmask_rejects_corrupted_masked_key_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key original_hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            original_hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

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

        masked_key_data[masked_key_data.size() / 2] ^= 0x01;

        azihsm_buffer corrupted_buf = { .ptr = masked_key_data.data(),
                                        .len = static_cast<uint32_t>(masked_key_data.size()) };

        auto_key unmasked_key;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &corrupted_buf,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);

        ASSERT_EQ(unmasked_key.get(), 0);
    });
}

// Test that HMAC verify rejects a truncated signature
TEST_F(azihsm_hmac_keygen, hmac_verify_rejects_truncated_signature)
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

        const char *test_data = "HMAC message";
        azihsm_buffer data_buf = { .ptr = (uint8_t *)test_data,
                                   .len = static_cast<uint32_t>(strlen(test_data)) };

        azihsm_algo hmac_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 1u);

        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();

        err = azihsm_crypt_sign(&hmac_algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer truncated_sig_buf = { .ptr = signature.data(),
                                            .len = static_cast<uint32_t>(signature.size() - 1) };

        err = azihsm_crypt_verify(&hmac_algo, hmac_key.get(), &data_buf, &truncated_sig_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_SIGNATURE);
    });
}

// Test that unmask rejects unsupported key kinds
TEST_F(azihsm_hmac_keygen, unmask_rejects_unsupported_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key original_hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            key_pairs,
            original_hmac_key.handle,
            AZIHSM_ECC_CURVE_P256
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_hmac_key.get(), 0);

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

        azihsm_buffer masked_key_buf = {
            .ptr = masked_key_data.data(),
            .len = static_cast<uint32_t>(masked_key_data.size()),
        };

        auto_key unmasked_key;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_AES,
            &masked_key_buf,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(unmasked_key.get(), 0);
    });
}