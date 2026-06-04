// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"

/// Test fixture for ECC key generation tests across available partition sessions.
class azihsm_ecc_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Test data structure for ECC key generation tests
struct KeygenTestParams
{
    azihsm_ecc_curve curve;
    const char *test_name;
};

/// Verifies that a generated ECC key pair reports the expected key kind and curve properties.
static void run_generated_keypair_has_expected_properties(
    azihsm_handle session,
    azihsm_ecc_curve curve
)
{
    auto_key priv_key;
    auto_key pub_key;

    auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(priv_key.get(), 0u);
    ASSERT_NE(pub_key.get(), 0u);

    EccKeySummary private_summary{};
    EccKeySummary public_summary{};

    ASSERT_EQ(read_ecc_key_summary(priv_key.get(), private_summary), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(read_ecc_key_summary(pub_key.get(), public_summary), AZIHSM_STATUS_SUCCESS);

    ASSERT_TRUE(is_expected_ecc_curve(private_summary, curve));
    ASSERT_TRUE(is_expected_ecc_curve(public_summary, curve));
}

/// Verifies that a masked ECC private key can be unmasked into a valid key pair for the given
/// curve.
static void run_unmask_ecc_keypair_for_curve(azihsm_handle session, azihsm_ecc_curve curve)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = azihsm_key_unmask_pair(
        session,
        AZIHSM_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);

    EccKeySummary private_summary{};
    EccKeySummary public_summary{};

    ASSERT_EQ(
        read_ecc_key_summary(unmasked_priv_key.get(), private_summary),
        AZIHSM_STATUS_SUCCESS
    );
    ASSERT_EQ(read_ecc_key_summary(unmasked_pub_key.get(), public_summary), AZIHSM_STATUS_SUCCESS);

    ASSERT_TRUE(is_expected_ecc_curve(private_summary, curve));
    ASSERT_TRUE(is_expected_ecc_curve(public_summary, curve));
}

/// Runs ECC key pair generation with caller-provided private and public key properties.
static azihsm_status run_ecc_keygen_with_props(
    azihsm_handle session,
    azihsm_key_prop_list *priv_prop_list,
    azihsm_key_prop_list *pub_prop_list
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(
        session,
        &keygen_algo,
        priv_prop_list,
        pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );

    if (err == AZIHSM_STATUS_SUCCESS)
    {
        if (priv_key_handle != 0)
        {
            auto delete_err = azihsm_key_delete(priv_key_handle);
            EXPECT_EQ(delete_err, AZIHSM_STATUS_SUCCESS);
        }

        if (pub_key_handle != 0)
        {
            auto delete_err = azihsm_key_delete(pub_key_handle);
            EXPECT_EQ(delete_err, AZIHSM_STATUS_SUCCESS);
        }
    }

    return err;
}

/// Verifies that a masked ECC key can still be unmasked after the original key pair is deleted.
static void run_unmask_after_original_keys_deleted(azihsm_handle session, azihsm_ecc_curve curve)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    auto original_priv_handle = original_priv_key.get();
    auto original_pub_handle = original_pub_key.get();

    err = azihsm_key_delete(original_priv_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_priv_key.release();

    err = azihsm_key_delete(original_pub_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_pub_key.release();

    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = azihsm_key_unmask_pair(
        session,
        AZIHSM_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );

    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);
}

/// Verifies that unmasking an ECC key returns new handles distinct from the original key handles.
static void run_unmasked_handles_are_distinct_from_original(
    azihsm_handle session,
    azihsm_ecc_curve curve
)
{
    auto_key original_priv_key;
    auto_key original_pub_key;

    auto err = generate_ecc_keypair(
        session,
        curve,
        true,
        original_priv_key.get_ptr(),
        original_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_priv_key.get(), 0u);
    ASSERT_NE(original_pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_FALSE(masked_key_data.empty());

    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_priv_key;
    auto_key unmasked_pub_key;

    err = azihsm_key_unmask_pair(
        session,
        AZIHSM_KEY_KIND_ECC,
        &masked_key_buf,
        unmasked_priv_key.get_ptr(),
        unmasked_pub_key.get_ptr()
    );

    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_priv_key.get(), 0u);
    ASSERT_NE(unmasked_pub_key.get(), 0u);

    ASSERT_NE(unmasked_priv_key.get(), original_priv_key.get());
    ASSERT_NE(unmasked_pub_key.get(), original_pub_key.get());
}

/// Verifies that the masked key property for a generated ECC private key is present and non-empty.
static void run_masked_key_property_is_non_empty(azihsm_handle session, azihsm_ecc_curve curve)
{
    auto_key priv_key;
    auto_key pub_key;

    auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(priv_key.get(), 0u);
    ASSERT_NE(pub_key.get(), 0u);

    std::vector<uint8_t> masked_key_data;
    err = get_masked_key_blob(priv_key.get(), masked_key_data);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    ASSERT_FALSE(masked_key_data.empty());
}

/// Verifies that ECC key pair generation succeeds for all supported curves.
TEST_F(azihsm_ecc_keygen, generate_keypair_all_curves)
{
    std::vector<KeygenTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing key generation with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                test_case.curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);

            // Explicitly test deletion (auto_key will also delete on scope exit as backup)
            auto delete_priv_err = azihsm_key_delete(priv_key.get());
            ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
            priv_key.release();

            auto delete_pub_err = azihsm_key_delete(pub_key.get());
            ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
            pub_key.release();
        });
    }
}

/// Verifies that ECC key generation rejects a null algorithm pointer.
TEST_F(azihsm_ecc_keygen, null_algorithm)
{
    part_list_.for_each_session([](azihsm_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = azihsm_key_gen_pair(
            session,
            nullptr,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects null private key properties.
TEST_F(azihsm_ecc_keygen, null_priv_key_props)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            nullptr,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects null public key properties.
TEST_F(azihsm_ecc_keygen, null_pub_key_props)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            nullptr,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects a null private key output pointer.
TEST_F(azihsm_ecc_keygen, null_priv_key_handle_output)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            nullptr,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects a null public key output pointer.
TEST_F(azihsm_ecc_keygen, null_pub_key_handle_output)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            nullptr
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key generation rejects an invalid session handle.
TEST_F(azihsm_ecc_keygen, invalid_session_handle)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(
        0xDEADBEEF,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

/// Verifies that ECC key generation rejects an unsupported algorithm identifier.
TEST_F(azihsm_ecc_keygen, unsupported_algorithm)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that ECC key pair unmasking rejects an unsupported key kind.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_unsupported_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key priv_key;
        auto_key pub_key;
        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_AES,
            &masked_key_buf,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that a generated P-256 ECC key pair has the expected properties.
TEST_F(azihsm_ecc_keygen, generated_p256_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Verifies that a generated P-384 ECC key pair has the expected properties.
TEST_F(azihsm_ecc_keygen, generated_p384_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Verifies that a generated P-521 ECC key pair has the expected properties.
TEST_F(azihsm_ecc_keygen, generated_p521_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Verifies that a masked P-256 ECC private key can be unmasked into a key pair.
TEST_F(azihsm_ecc_keygen, unmask_ecc_p256_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Verifies that a masked P-384 ECC private key can be unmasked into a key pair.
TEST_F(azihsm_ecc_keygen, unmask_ecc_p384_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Verifies that a masked P-521 ECC private key can be unmasked into a key pair.
TEST_F(azihsm_ecc_keygen, unmask_ecc_p521_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Verifies that ECC key pair unmasking rejects corrupted masked key data.
TEST_F(azihsm_ecc_keygen, unmask_ecc_rejects_corrupted_data)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key original_priv_key;
        auto_key original_pub_key;

        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());

        masked_key_data[masked_key_data.size() / 2] ^= 0x5A;

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_priv_key;
        auto_key unmasked_pub_key;

        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null masked key buffer.
TEST_F(azihsm_ecc_keygen, unmask_rejects_null_masked_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            nullptr,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null private key output pointer.
TEST_F(azihsm_ecc_keygen, unmask_rejects_null_private_output)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key pub_key;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            nullptr,
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects a null public key output pointer.
TEST_F(azihsm_ecc_keygen, unmask_rejects_null_public_output)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data(16, 0x42);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key priv_key;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            priv_key.get_ptr(),
            nullptr
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key.get(), 0u);
    });
}

/// Verifies that ECC key pair unmasking rejects an empty masked key buffer.
TEST_F(azihsm_ecc_keygen, unmask_rejects_empty_masked_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = nullptr;
        masked_key_buf.len = 0;

        auto_key priv_key;
        auto_key pub_key;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_MASKED_KEY_DECODE_FAILED);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

/// Verifies that ECC masked key data cannot be unmasked as an RSA key pair.
TEST_F(azihsm_ecc_keygen, unmask_rejects_wrong_key_kind_for_real_ecc_masked_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key original_priv_key;
        auto_key original_pub_key;

        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_priv_key.get(), 0u);
        ASSERT_NE(original_pub_key.get(), 0u);

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_priv_key;
        auto_key unmasked_pub_key;

        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_RSA,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INTERNAL_ERROR);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

/// Verifies that ECC key generation rejects mismatched P-256 private and P-384 public key curves.
TEST_F(azihsm_ecc_keygen, keygen_rejects_curve_mismatch_p256_private_p384_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P256;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that ECC key generation rejects mismatched P-384 private and P-521 public key curves.
TEST_F(azihsm_ecc_keygen, keygen_rejects_curve_mismatch_p384_private_p521_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P521;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that ECC key generation rejects mismatched P-521 private and P-256 public key curves.
TEST_F(azihsm_ecc_keygen, keygen_rejects_curve_mismatch_p521_private_p256_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P256;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = run_ecc_keygen_with_props(session, &priv_prop_list, &pub_prop_list);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

/// Verifies that a masked P-256 ECC key can be unmasked after the original key pair is deleted.
TEST_F(azihsm_ecc_keygen, unmask_p256_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Verifies that a masked P-384 ECC key can be unmasked after the original key pair is deleted.
TEST_F(azihsm_ecc_keygen, unmask_p384_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Verifies that a masked P-521 ECC key can be unmasked after the original key pair is deleted.
TEST_F(azihsm_ecc_keygen, unmask_p521_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Verifies that unmasking a P-256 ECC key returns handles distinct from the original handles.
TEST_F(azihsm_ecc_keygen, unmask_p256_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Verifies that unmasking a P-384 ECC key returns handles distinct from the original handles.
TEST_F(azihsm_ecc_keygen, unmask_p384_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Verifies that unmasking a P-521 ECC key returns handles distinct from the original handles.
TEST_F(azihsm_ecc_keygen, unmask_p521_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Verifies that a generated P-256 ECC private key exposes a non-empty masked key property.
TEST_F(azihsm_ecc_keygen, p256_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Verifies that a generated P-384 ECC private key exposes a non-empty masked key property.
TEST_F(azihsm_ecc_keygen, p384_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Verifies that a generated P-521 ECC private key exposes a non-empty masked key property.
TEST_F(azihsm_ecc_keygen, p521_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Verifies that ECC key pair unmasking rejects an invalid session handle.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_invalid_session_handle)
{
    std::vector<uint8_t> masked_key_data(16, 0x42);

    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key priv_key;
    auto_key pub_key;

    auto err = azihsm_key_unmask_pair(
        0xDEADBEEF,
        AZIHSM_KEY_KIND_ECC,
        &masked_key_buf,
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );

    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(priv_key.get(), 0u);
    ASSERT_EQ(pub_key.get(), 0u);
}