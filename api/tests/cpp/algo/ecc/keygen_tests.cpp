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
        auto err = generate_ecc_keypair(
            session.get(),
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
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
        auto err = generate_ecc_keypair(
            session.get(),
            AZIHSM_ECC_CURVE_P384,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
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
        auto err = generate_ecc_keypair(
            session.get(),
            AZIHSM_ECC_CURVE_P521,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (AutoKey will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
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

        auto err = azihsm_key_gen_pair(
            session.get(),
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

        auto err = azihsm_key_gen_pair(
            session.get(),
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

        auto err = azihsm_key_gen_pair(
            session.get(),
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

        auto err = azihsm_key_gen_pair(
            session.get(),
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

        auto err = azihsm_key_gen_pair(
            session.get(),
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

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
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

        auto err = azihsm_key_gen_pair(
            session.get(),
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keygen, unmask_ecc_p256_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Step 1: Generate ECC P256 key pair with sign/verify capabilities
        AutoKey original_priv_key;
        AutoKey original_pub_key;
        auto err = generate_ecc_keypair(
            session.get(),
            AZIHSM_ECC_CURVE_P256,
            true, // session key
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_priv_key.get(), 0);
        ASSERT_NE(original_pub_key.get(), 0);

        // Step 2: Get masked key from private key
        uint8_t *masked_key_ptr = nullptr;
        uint32_t masked_key_len = 0;
        
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = masked_key_ptr;
        masked_prop.len = masked_key_len;
        
        err = azihsm_key_get_prop(original_priv_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();
        
        err = azihsm_key_get_prop(original_priv_key.get(), &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 3: Unmask the key pair
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        AutoKey unmasked_priv_key;
        AutoKey unmasked_pub_key;
        err = azihsm_key_unmask_pair(
            session.get(),
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_priv_key.get(), 0);
        ASSERT_NE(unmasked_pub_key.get(), 0);

        // Step 4: Compare key properties - private keys
        {
            // Compare key kind
            azihsm_key_kind original_kind, unmasked_kind;
            uint32_t len = sizeof(azihsm_key_kind);
            azihsm_key_prop prop{};
            
            prop.id = AZIHSM_KEY_PROP_ID_KIND;
            prop.val = &original_kind;
            prop.len = len;
            err = azihsm_key_get_prop(original_priv_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            
            prop.val = &unmasked_kind;
            err = azihsm_key_get_prop(unmasked_priv_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(original_kind, unmasked_kind);
            ASSERT_EQ(original_kind, AZIHSM_KEY_KIND_ECC);

            // Compare ECC curve
            azihsm_ecc_curve original_curve, unmasked_curve;
            prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
            prop.len = sizeof(azihsm_ecc_curve);
            
            prop.val = &original_curve;
            err = azihsm_key_get_prop(original_priv_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            
            prop.val = &unmasked_curve;
            err = azihsm_key_get_prop(unmasked_priv_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(original_curve, unmasked_curve);
            ASSERT_EQ(original_curve, AZIHSM_ECC_CURVE_P256);
        }

        // Step 5: Compare key properties - public keys
        {
            // Compare key kind
            azihsm_key_kind original_kind, unmasked_kind;
            uint32_t len = sizeof(azihsm_key_kind);
            azihsm_key_prop prop{};
            
            prop.id = AZIHSM_KEY_PROP_ID_KIND;
            prop.val = &original_kind;
            prop.len = len;
            err = azihsm_key_get_prop(original_pub_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            
            prop.val = &unmasked_kind;
            err = azihsm_key_get_prop(unmasked_pub_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(original_kind, unmasked_kind);
            ASSERT_EQ(original_kind, AZIHSM_KEY_KIND_ECC);

            // Compare ECC curve
            azihsm_ecc_curve original_curve, unmasked_curve;
            prop.id = AZIHSM_KEY_PROP_ID_EC_CURVE;
            prop.len = sizeof(azihsm_ecc_curve);
            
            prop.val = &original_curve;
            err = azihsm_key_get_prop(original_pub_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            
            prop.val = &unmasked_curve;
            err = azihsm_key_get_prop(unmasked_pub_key.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(original_curve, unmasked_curve);
            ASSERT_EQ(original_curve, AZIHSM_ECC_CURVE_P256);
        }
    });
}