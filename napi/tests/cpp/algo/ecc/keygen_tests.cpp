// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils.hpp"

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

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P256, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_ERROR_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_ERROR_SUCCESS);
        pub_key.release();
    });
}

TEST_F(azihsm_ecc_keygen, generate_p384_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P384, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_ERROR_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_ERROR_SUCCESS);
        pub_key.release();
    });
}

TEST_F(azihsm_ecc_keygen, generate_p521_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_ecc_keypair(session.get(), AZIHSM_ECC_CURVE_P521, true, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_ERROR_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_ERROR_SUCCESS);
        pub_key.release();
    });
}

// Parameter validation tests
TEST_F(azihsm_ecc_keygen, null_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

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

        DummyEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

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

        DummyEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

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

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

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

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

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

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(0xDEADBEEF, &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                   &pub_key_handle);
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

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle,
                                       &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}