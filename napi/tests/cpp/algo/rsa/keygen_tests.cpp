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

class azihsm_rsa_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_rsa_keygen, generate_rsa_2048_keypair)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        AutoKey priv_key;
        AutoKey pub_key;
        auto err = generate_rsa_unwrapping_keypair(session.get(), priv_key.get_ptr(), pub_key.get_ptr());
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