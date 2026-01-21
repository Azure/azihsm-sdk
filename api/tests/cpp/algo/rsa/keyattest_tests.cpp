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

class azihsm_rsa_keyattest : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_rsa_keyattest, attest_rsa_2048_key)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate an RSA 2048 key pair
        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_rsa_unwrapping_keypair(session.get(), priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Prepare report data (128 bytes is the maximum)
        std::vector<uint8_t> report_data(128, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        // First call: get the required report buffer size
        std::vector<uint8_t> report;
        azihsm_buffer report_buf{ nullptr, 0 };

        auto attest_err = azihsm_attest_key(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);

        // Second call: generate the actual report
        report.resize(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_attest_key(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);

        // Verify the report buffer was populated (not all zeros)
        bool has_non_zero = false;
        for (size_t i = 0; i < report_buf.len; ++i)
        {
            if (report[i] != 0)
            {
                has_non_zero = true;
                break;
            }
        }
        ASSERT_TRUE(has_non_zero) << "Report should contain non-zero data";
    });
}

TEST_F(azihsm_rsa_keyattest, attest_with_empty_report_data)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate an RSA 2048 key pair
        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_rsa_unwrapping_keypair(session.get(), priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Use empty report data
        std::vector<uint8_t> report_data;
        azihsm_buffer report_data_buf{ report_data.data(), 0 };

        // First call: get the required report buffer size
        std::vector<uint8_t> report;
        azihsm_buffer report_buf{ nullptr, 0 };

        auto attest_err = azihsm_attest_key(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);

        // Second call: generate the actual report
        report.resize(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_attest_key(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
    });
}

TEST_F(azihsm_rsa_keyattest, attest_invalid_key_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Use an invalid key handle
        azihsm_handle invalid_key = 0;

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_attest_key(invalid_key, &report_data_buf, &report_buf);
        ASSERT_NE(attest_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_rsa_keyattest, attest_public_key_fails)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate an RSA 2048 key pair
        AutoKey priv_key;
        AutoKey pub_key;
        auto err =
            generate_rsa_unwrapping_keypair(session.get(), priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Try to attest the public key (should fail - only private keys can be attested)
        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_attest_key(pub_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
    });
}