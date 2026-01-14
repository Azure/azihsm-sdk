// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_ecc : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_ecc, generate_p256_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate ECC P-256 key pair
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        // Set up private key properties
        uint32_t priv_key_class = 3;  // AZIHSM_KEY_CLASS_PRIVATE
        uint32_t priv_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint32_t ecc_curve = 1;       // P256 curve
        uint8_t priv_is_session = 1;
        uint8_t priv_can_sign = 1;

        azihsm_key_prop priv_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &priv_is_session, sizeof(priv_is_session)},
            {AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign)},
        };

        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        // Set up public key properties
        uint32_t pub_key_class = 2;  // AZIHSM_KEY_CLASS_PUBLIC
        uint32_t pub_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint8_t pub_is_session = 1;
        uint8_t pub_can_verify = 1;

        azihsm_key_prop pub_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &pub_is_session, sizeof(pub_is_session)},
            {AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify)},
        };

        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle, &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key_handle);
        auto pub_err = azihsm_key_delete(pub_key_handle);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc, generate_p384_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate ECC P-384 key pair
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        // Set up private key properties
        uint32_t priv_key_class = 3;  // AZIHSM_KEY_CLASS_PRIVATE
        uint32_t priv_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint32_t ecc_curve = 2;       // P384 curve
        uint8_t priv_is_session = 1;
        uint8_t priv_can_sign = 1;

        azihsm_key_prop priv_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &priv_is_session, sizeof(priv_is_session)},
            {AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign)},
        };

        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        // Set up public key properties
        uint32_t pub_key_class = 2;  // AZIHSM_KEY_CLASS_PUBLIC
        uint32_t pub_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint8_t pub_is_session = 1;
        uint8_t pub_can_verify = 1;

        azihsm_key_prop pub_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &pub_is_session, sizeof(pub_is_session)},
            {AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify)},
        };

        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle, &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key_handle, 0);
        ASSERT_NE(pub_key_handle, 0);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key_handle);
        auto pub_err = azihsm_key_delete(pub_key_handle);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_ecc, generate_p521_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate ECC P-521 key pair
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        // Set up private key properties
        uint32_t priv_key_class = 3;  // AZIHSM_KEY_CLASS_PRIVATE
        uint32_t priv_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint32_t ecc_curve = 3;       // P521 curve
        uint8_t priv_is_session = 1;
        uint8_t priv_can_sign = 1;

        azihsm_key_prop priv_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &priv_is_session, sizeof(priv_is_session)},
            {AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign)},
        };

        azihsm_key_prop_list priv_prop_list{priv_props, 5};

        // Set up public key properties
        uint32_t pub_key_class = 2;  // AZIHSM_KEY_CLASS_PUBLIC
        uint32_t pub_key_kind = 2;   // AZIHSM_KEY_KIND_EC
        uint32_t pub_bits = 521;
        uint8_t pub_is_session = 1;
        uint8_t pub_can_verify = 1;

        azihsm_key_prop pub_props[] = {
            {AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class)},
            {AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind)},
            {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)},
            {AZIHSM_KEY_PROP_ID_SESSION, &pub_is_session, sizeof(pub_is_session)},
            {AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify)},
        };

        azihsm_key_prop_list pub_prop_list{pub_props, 5};

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(session.get(), &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle, &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(priv_key_handle, 0);
        ASSERT_NE(pub_key_handle, 0);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key_handle);
        auto pub_err = azihsm_key_delete(pub_key_handle);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}