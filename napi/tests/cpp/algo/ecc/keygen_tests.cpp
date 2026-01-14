// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "ecc_test_helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_ecc_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_ecc_keygen, generate_p256_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_handle priv_key = 0;
        azihsm_handle pub_key = 0;
        generate_ecc_keypair(session.get(), 1 /* P256 */, priv_key, pub_key);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key);
        auto pub_err = azihsm_key_delete(pub_key);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_keygen, generate_p384_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_handle priv_key = 0;
        azihsm_handle pub_key = 0;
        generate_ecc_keypair(session.get(), 2 /* P384 */, priv_key, pub_key);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key);
        auto pub_err = azihsm_key_delete(pub_key);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc_keygen, generate_p521_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_handle priv_key = 0;
        azihsm_handle pub_key = 0;
        generate_ecc_keypair(session.get(), 3 /* P521 */, priv_key, pub_key);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key);
        auto pub_err = azihsm_key_delete(pub_key);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

// Parameter validation tests
TEST_F(azihsm_ecc_keygen, null_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
        uint8_t priv_is_session, priv_can_sign;
        azihsm_key_prop priv_props[5];
        build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                                 priv_props);
        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
        uint8_t pub_is_session, pub_can_verify;
        azihsm_key_prop pub_props[5];
        build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                                pub_props);
        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), nullptr, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                       &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, null_priv_key_props)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
        uint8_t pub_is_session, pub_can_verify;
        azihsm_key_prop pub_props[5];
        build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                                pub_props);
        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, nullptr, &pub_prop_list, &priv_key_handle,
                                       &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, null_pub_key_props)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
        uint8_t priv_is_session, priv_can_sign;
        azihsm_key_prop priv_props[5];
        build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                                 priv_props);
        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, nullptr, &priv_key_handle,
                                       &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, null_priv_key_handle_output)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
        uint8_t priv_is_session, priv_can_sign;
        azihsm_key_prop priv_props[5];
        build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                                 priv_props);
        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
        uint8_t pub_is_session, pub_can_verify;
        azihsm_key_prop pub_props[5];
        build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                                pub_props);
        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle pub_key_handle = 0;

        auto err =
            azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, nullptr, &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, null_pub_key_handle_output)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
        uint8_t priv_is_session, priv_can_sign;
        azihsm_key_prop priv_props[5];
        build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                                 priv_props);
        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
        uint8_t pub_is_session, pub_can_verify;
        azihsm_key_prop pub_props[5];
        build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                                pub_props);
        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                       nullptr);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, invalid_session_handle)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
    uint8_t priv_is_session, priv_can_sign;
    azihsm_key_prop priv_props[5];
    build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                             priv_props);
    azihsm_key_prop_list priv_prop_list{priv_props, 5};

    uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
    uint8_t pub_is_session, pub_can_verify;
    azihsm_key_prop pub_props[5];
    build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify, pub_props);
    azihsm_key_prop_list pub_prop_list{pub_props, 5};

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(0xDEADBEEF, &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                   &pub_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(azihsm_ecc_keygen, delete_invalid_key_handle)
{
    auto err = azihsm_key_delete(0xDEADBEEF);
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(azihsm_ecc_keygen, unsupported_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo keygen_algo{};
        keygen_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
        uint8_t priv_is_session, priv_can_sign;
        azihsm_key_prop priv_props[5];
        build_ecc_priv_key_props(1, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                                 priv_props);
        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
        uint8_t pub_is_session, pub_can_verify;
        azihsm_key_prop pub_props[5];
        build_ecc_pub_key_props(1, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                                pub_props);
        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                       &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}