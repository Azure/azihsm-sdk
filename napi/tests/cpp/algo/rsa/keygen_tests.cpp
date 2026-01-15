// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "rsa_test_helpers.hpp"

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

        azihsm_handle priv_key = 0;
        azihsm_handle pub_key = 0;
        generate_rsa_keypair(session.get(), 2048, priv_key, pub_key);

        // Clean up keys
        auto priv_err = azihsm_key_delete(priv_key);
        auto pub_err = azihsm_key_delete(pub_key);

        ASSERT_EQ(priv_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pub_err, AZIHSM_ERROR_SUCCESS);
    });
}