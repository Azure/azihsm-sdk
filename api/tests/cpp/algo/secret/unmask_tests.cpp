// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"
#include <azihsm_api.h>
#include <vector>

class azihsm_secret_unmask : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Helper to compare key properties between original and unmasked keys
static void compare_shared_secret_properties(
    azihsm_handle original_key,
    azihsm_handle unmasked_key,
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
    ASSERT_EQ(original_kind, AZIHSM_KEY_KIND_SHARED_SECRET);

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

    // Compare derive capability
    bool original_derive, unmasked_derive;
    prop.id = AZIHSM_KEY_PROP_ID_DERIVE;
    prop.len = sizeof(bool);

    prop.val = &original_derive;
    err = azihsm_key_get_prop(original_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    prop.val = &unmasked_derive;
    err = azihsm_key_get_prop(unmasked_key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(original_derive, unmasked_derive);
}

// Common test function for unmasking shared secret keys
static void test_shared_secret_unmask(azihsm_handle session, azihsm_ecc_curve curve)
{
    uint32_t expected_bits = get_curve_key_bits(curve);

    // Step 1: Generate two EC key pairs
    EcdhKeyPairSet key_pairs;
    azihsm_status err = key_pairs.generate(session, curve);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Step 2: Derive shared secret using party A's private key and party B's public key
    auto_key original_secret;
    err = derive_shared_secret_via_ecdh(
        session,
        key_pairs.priv_key_a.handle,
        key_pairs.pub_key_b.handle,
        curve,
        original_secret.handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_secret.get(), 0);

    // Step 3: Get masked key via property
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(original_secret.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0u);

    std::vector<uint8_t> masked_key_data(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    err = azihsm_key_get_prop(original_secret.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Step 4: Unmask the masked key
    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_secret;
    err = azihsm_key_unmask(
        session,
        AZIHSM_KEY_KIND_SHARED_SECRET,
        &masked_key_buf,
        unmasked_secret.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_secret.get(), 0);

    // Step 5: Compare key properties
    compare_shared_secret_properties(original_secret.get(), unmasked_secret.get(), expected_bits);
}

TEST_F(azihsm_secret_unmask, unmask_shared_secret_p256)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_shared_secret_unmask(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_secret_unmask, unmask_shared_secret_p384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_shared_secret_unmask(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_secret_unmask, unmask_shared_secret_p521)
{
    part_list_.for_each_session([](azihsm_handle session) {
        test_shared_secret_unmask(session, AZIHSM_ECC_CURVE_P521);
    });
}