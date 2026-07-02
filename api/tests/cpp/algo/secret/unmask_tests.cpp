// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"
#include <array>
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

// Helper to derive a shared secret and read its masked-key property bytes.
static void get_masked_shared_secret(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    std::vector<uint8_t> &masked_key_data
)
{
    EcdhKeyPairSet key_pairs;
    auto err = key_pairs.generate(session, curve);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    auto_key original_secret;
    err = derive_shared_secret_via_ecdh(
        session,
        key_pairs.priv_key_a.handle,
        key_pairs.pub_key_b.handle,
        curve,
        original_secret.handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_secret.get(), 0u);

    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(original_secret.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0u);

    masked_key_data.resize(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    err = azihsm_key_get_prop(original_secret.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_GT(masked_prop.len, 0u);

    masked_key_data.resize(static_cast<size_t>(masked_prop.len));
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

TEST_F(azihsm_secret_unmask, unmask_rejects_unsupported_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::array<uint8_t, 16> masked_data{};
        azihsm_buffer masked_key{ masked_data.data(), static_cast<uint32_t>(masked_data.size()) };

        auto_key unmasked_key;
        auto err =
            azihsm_key_unmask(session, AZIHSM_KEY_KIND_RSA, &masked_key, unmasked_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a null masked-key buffer pointer.
TEST_F(azihsm_secret_unmask, unmask_rejects_null_masked_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key unmasked_key;

        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            nullptr,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a null output key handle pointer.
TEST_F(azihsm_secret_unmask, unmask_rejects_null_output_key_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto err = azihsm_key_unmask(session, AZIHSM_KEY_KIND_SHARED_SECRET, &masked_key, nullptr);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Unmask rejects a buffer with null ptr and nonzero len.
TEST_F(azihsm_secret_unmask, unmask_rejects_null_masked_key_ptr)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_buffer masked_key{};
        masked_key.ptr = nullptr;
        masked_key.len = 32;

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects an empty masked-key buffer.
TEST_F(azihsm_secret_unmask, unmask_rejects_empty_masked_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::array<uint8_t, 1> masked_data{};

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_data.data();
        masked_key.len = 0;

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a truncated masked-key blob.
TEST_F(azihsm_secret_unmask, unmask_rejects_truncated_masked_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_GT(masked_key_data.size(), 1u);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size() - 1);

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a corrupted masked-key blob.
TEST_F(azihsm_secret_unmask, unmask_rejects_corrupted_masked_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_GT(masked_key_data.size(), 0u);

        masked_key_data[masked_key_data.size() / 2] ^= 0x01;

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a masked shared-secret blob when requested as another supported secret key kind.
TEST_F(azihsm_secret_unmask, unmask_rejects_wrong_secret_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_HMAC_SHA256,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmasking the same masked-key blob twice creates valid independent key handles.
TEST_F(azihsm_secret_unmask, unmask_same_masked_key_twice_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P384, masked_key_data);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_secret_1;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_secret_1.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_secret_1.get(), 0u);

        auto_key unmasked_secret_2;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_secret_2.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_secret_2.get(), 0u);

        ASSERT_NE(unmasked_secret_1.get(), unmasked_secret_2.get());
    });
}

// Unmasked shared secret preserves derive capability and can be used for HKDF-style derivation if
// supported.
TEST_F(azihsm_secret_unmask, unmasked_shared_secret_can_be_used_for_derivation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_secret;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_secret.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_secret.get(), 0u);

        bool can_derive = false;
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_DERIVE;
        prop.val = &can_derive;
        prop.len = sizeof(can_derive);

        err = azihsm_key_get_prop(unmasked_secret.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_TRUE(can_derive);
    });
}

// Masked-key property rejects a too-small nonzero output buffer.
TEST_F(azihsm_secret_unmask, get_masked_key_rejects_small_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(session, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_key original_secret;
        err = derive_shared_secret_via_ecdh(
            session,
            key_pairs.priv_key_a.handle,
            key_pairs.pub_key_b.handle,
            AZIHSM_ECC_CURVE_P256,
            original_secret.handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_secret.get(), 0u);

        std::array<uint8_t, 1> small_buffer{};

        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = small_buffer.data();
        masked_prop.len = static_cast<uint32_t>(small_buffer.size());

        err = azihsm_key_get_prop(original_secret.get(), &masked_prop);

        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, small_buffer.size());
    });
}

// Unmask rejects random bytes that are not a real masked-key blob.
TEST_F(azihsm_secret_unmask, unmask_rejects_random_masked_key_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::array<uint8_t, 64> masked_data{};
        for (size_t i = 0; i < masked_data.size(); ++i)
        {
            masked_data[i] = static_cast<uint8_t>(i + 1);
        }

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_data.data();
        masked_key.len = static_cast<uint32_t>(masked_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects an invalid session handle.
TEST_F(azihsm_secret_unmask, unmask_rejects_invalid_session_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            0,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

         ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
                 ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects a masked-key blob with extra trailing bytes.
TEST_F(azihsm_secret_unmask, unmask_rejects_masked_key_with_extra_trailing_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        masked_key_data.push_back(0xAA);

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

         ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
                 ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects prefix-only masked-key blobs at multiple invalid lengths.
TEST_F(azihsm_secret_unmask, unmask_rejects_prefix_only_masked_key_lengths)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P384, masked_key_data);
        ASSERT_GT(masked_key_data.size(), 4u);

        const std::vector<uint32_t> invalid_lengths = {
            1u,
            static_cast<uint32_t>(masked_key_data.size() / 4),
            static_cast<uint32_t>(masked_key_data.size() / 2),
            static_cast<uint32_t>(masked_key_data.size() - 1),
        };

        for (uint32_t invalid_len : invalid_lengths)
        {
            SCOPED_TRACE("invalid_len=" + std::to_string(invalid_len));

            azihsm_buffer masked_key{};
            masked_key.ptr = masked_key_data.data();
            masked_key.len = invalid_len;

            auto_key unmasked_key;
            auto err = azihsm_key_unmask(
                session,
                AZIHSM_KEY_KIND_SHARED_SECRET,
                &masked_key,
                unmasked_key.get_ptr()
            );

            ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
            ASSERT_EQ(unmasked_key.get(), 0u);
        }
    });
}

// Unmask rejects corruption at the first byte of the masked-key blob.
TEST_F(azihsm_secret_unmask, unmask_rejects_corrupted_first_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_FALSE(masked_key_data.empty());

        masked_key_data.front() ^= 0x01;

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

         ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
                 ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask rejects corruption at the last byte of the masked-key blob.
TEST_F(azihsm_secret_unmask, unmask_rejects_corrupted_last_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P521, masked_key_data);
        ASSERT_FALSE(masked_key_data.empty());

        masked_key_data.back() ^= 0x01;

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_key.get(), 0u);
    });
}

// Unmask does not mutate the caller-owned masked-key input buffer.
TEST_F(azihsm_secret_unmask, unmask_does_not_mutate_masked_key_input_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P256, masked_key_data);

        const std::vector<uint8_t> original_masked_key_data = masked_key_data;

        azihsm_buffer masked_key{};
        masked_key.ptr = masked_key_data.data();
        masked_key.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &masked_key,
            unmasked_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_key.get(), 0u);
        ASSERT_EQ(masked_key_data, original_masked_key_data);
    });
}

// A key produced by unmask can expose its own masked-key property and be unmasked again.
TEST_F(azihsm_secret_unmask, unmasked_shared_secret_can_be_masked_and_unmasked_again)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> first_masked_key_data;
        get_masked_shared_secret(session, AZIHSM_ECC_CURVE_P384, first_masked_key_data);

        azihsm_buffer first_masked_key{};
        first_masked_key.ptr = first_masked_key_data.data();
        first_masked_key.len = static_cast<uint32_t>(first_masked_key_data.size());

        auto_key first_unmasked_secret;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &first_masked_key,
            first_unmasked_secret.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(first_unmasked_secret.get(), 0u);

        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = nullptr;
        masked_prop.len = 0;

        err = azihsm_key_get_prop(first_unmasked_secret.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0u);

        std::vector<uint8_t> second_masked_key_data(masked_prop.len);
        masked_prop.val = second_masked_key_data.data();

        err = azihsm_key_get_prop(first_unmasked_secret.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer second_masked_key{};
        second_masked_key.ptr = second_masked_key_data.data();
        second_masked_key.len = static_cast<uint32_t>(second_masked_key_data.size());

        auto_key second_unmasked_secret;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_SHARED_SECRET,
            &second_masked_key,
            second_unmasked_secret.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(second_unmasked_secret.get(), 0u);
        ASSERT_NE(first_unmasked_secret.get(), second_unmasked_secret.get());

        compare_shared_secret_properties(
            first_unmasked_secret.get(),
            second_unmasked_secret.get(),
            get_curve_key_bits(AZIHSM_ECC_CURVE_P384)
        );
    });
}

// The masked-key property length query is stable across repeated calls.
TEST_F(azihsm_secret_unmask, get_masked_key_length_query_is_stable)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto err = key_pairs.generate(session, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_key original_secret;
        err = derive_shared_secret_via_ecdh(
            session,
            key_pairs.priv_key_a.handle,
            key_pairs.pub_key_b.handle,
            AZIHSM_ECC_CURVE_P256,
            original_secret.handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_secret.get(), 0u);

        azihsm_key_prop first_query{};
        first_query.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        first_query.val = nullptr;
        first_query.len = 0;

        err = azihsm_key_get_prop(original_secret.get(), &first_query);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(first_query.len, 0u);

        azihsm_key_prop second_query{};
        second_query.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        second_query.val = nullptr;
        second_query.len = 0;

        err = azihsm_key_get_prop(original_secret.get(), &second_query);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(second_query.len, first_query.len);
    });
}
