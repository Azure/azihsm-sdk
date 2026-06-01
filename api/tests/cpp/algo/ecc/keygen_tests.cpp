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

    {
        azihsm_key_kind kind{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &kind;
        prop.len = sizeof(kind);

        err = azihsm_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(kind, AZIHSM_KEY_KIND_ECC);
    }

    {
        azihsm_key_kind kind{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &kind;
        prop.len = sizeof(kind);

        err = azihsm_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(kind, AZIHSM_KEY_KIND_ECC);
    }

    {
        azihsm_ecc_curve actual_curve{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
        prop.val = &actual_curve;
        prop.len = sizeof(actual_curve);

        err = azihsm_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_curve, curve);
    }

    {
        azihsm_ecc_curve actual_curve{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
        prop.val = &actual_curve;
        prop.len = sizeof(actual_curve);

        err = azihsm_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_curve, curve);
    }
}

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

    {
        azihsm_key_kind actual_kind{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &actual_kind;
        prop.len = sizeof(actual_kind);

        err = azihsm_key_get_prop(unmasked_priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_kind, AZIHSM_KEY_KIND_ECC);
    }

    {
        azihsm_key_kind actual_kind{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &actual_kind;
        prop.len = sizeof(actual_kind);

        err = azihsm_key_get_prop(unmasked_pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_kind, AZIHSM_KEY_KIND_ECC);
    }

    {
        azihsm_ecc_curve actual_curve{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
        prop.val = &actual_curve;
        prop.len = sizeof(actual_curve);

        err = azihsm_key_get_prop(unmasked_priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_curve, curve);
    }

    {
        azihsm_ecc_curve actual_curve{};
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
        prop.val = &actual_curve;
        prop.len = sizeof(actual_curve);

        err = azihsm_key_get_prop(unmasked_pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_curve, curve);
    }
}

static void expect_ecc_key_kind(azihsm_handle key)
{
    azihsm_key_kind kind{};
    azihsm_key_prop prop{};
    prop.id = AZIHSM_KEY_PROP_ID_KIND;
    prop.val = &kind;
    prop.len = sizeof(kind);

    auto err = azihsm_key_get_prop(key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(kind, AZIHSM_KEY_KIND_ECC);
}

static void expect_ecc_curve(azihsm_handle key, azihsm_ecc_curve expected_curve)
{
    azihsm_ecc_curve actual_curve{};
    azihsm_key_prop prop{};
    prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
    prop.val = &actual_curve;
    prop.len = sizeof(actual_curve);

    auto err = azihsm_key_get_prop(key, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_curve, expected_curve);
}

static void run_generated_keypair_has_expected_kind_and_curve(
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

    expect_ecc_key_kind(priv_key.get());
    expect_ecc_key_kind(pub_key.get());

    expect_ecc_curve(priv_key.get(), curve);
    expect_ecc_curve(pub_key.get(), curve);
}

static void run_unmask_ecc_keypair_preserves_kind_and_curve(
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

    expect_ecc_key_kind(unmasked_priv_key.get());
    expect_ecc_key_kind(unmasked_pub_key.get());

    expect_ecc_curve(unmasked_priv_key.get(), curve);
    expect_ecc_curve(unmasked_pub_key.get(), curve);
}

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

// ============================================================
// Additional ECC keygen/unmask robustness coverage.
// No for-loops: each curve has its own TEST_F.
// ============================================================

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
    ASSERT_GT(masked_key_data.size(), 0u);
}

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

// Parameter validation tests
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

TEST_F(azihsm_ecc_keygen, generated_p256_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, generated_p384_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, generated_p521_keypair_has_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_properties(session, AZIHSM_ECC_CURVE_P521);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_ecc_p256_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_ecc_p384_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_ecc_p521_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_for_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

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

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

TEST_F(azihsm_ecc_keygen, generated_p256_keypair_has_expected_kind_and_curve)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_kind_and_curve(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, generated_p384_keypair_has_expected_kind_and_curve)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_kind_and_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, generated_p521_keypair_has_expected_kind_and_curve)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_generated_keypair_has_expected_kind_and_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p384_keypair_preserves_kind_and_curve)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_preserves_kind_and_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p521_keypair_preserves_kind_and_curve)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_ecc_keypair_preserves_kind_and_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

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

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key.get(), 0u);
        ASSERT_EQ(pub_key.get(), 0u);
    });
}

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

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(unmasked_priv_key.get(), 0u);
        ASSERT_EQ(unmasked_pub_key.get(), 0u);
    });
}

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
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

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
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

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
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p256_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p384_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p521_succeeds_after_original_keys_deleted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmask_after_original_keys_deleted(session, AZIHSM_ECC_CURVE_P521);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p256_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p384_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_p521_returns_distinct_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_unmasked_handles_are_distinct_from_original(session, AZIHSM_ECC_CURVE_P521);
    });
}

TEST_F(azihsm_ecc_keygen, p256_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P256);
    });
}

TEST_F(azihsm_ecc_keygen, p384_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P384);
    });
}

TEST_F(azihsm_ecc_keygen, p521_masked_key_property_is_non_empty)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_masked_key_property_is_non_empty(session, AZIHSM_ECC_CURVE_P521);
    });
}

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