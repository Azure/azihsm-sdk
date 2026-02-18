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

class azihsm_ecc_keyattest : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Test data structure for ECC key attestation tests
struct KeyAttestTestParams
{
    azihsm_ecc_curve curve;
    const char *test_name;
};

TEST_F(azihsm_ecc_keyattest, attest_key_all_curves)
{
    std::vector<KeyAttestTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing key attestation with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            // Generate an ECC key pair for the specified curve
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

            // Prepare report data (128 bytes is the maximum)
            std::vector<uint8_t> report_data(128, 0x42);
            azihsm_buffer report_data_buf{ report_data.data(),
                                           static_cast<uint32_t>(report_data.size()) };

            // First call: get the required report buffer size
            std::vector<uint8_t> report;
            azihsm_buffer report_buf{ nullptr, 0 };

            auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(report_buf.len, 0);

            // Second call: generate the actual report
            report.resize(report_buf.len);
            report_buf.ptr = report.data();

            attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
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
}

TEST_F(azihsm_ecc_keyattest, null_report_data_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Generate an ECC P-256 key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), nullptr, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keyattest, null_report_output_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Generate an ECC P-256 key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, nullptr);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keyattest, invalid_key_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Use an invalid key handle
        azihsm_handle invalid_key = 0;

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(invalid_key, &report_data_buf, &report_buf);
        ASSERT_NE(attest_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_keyattest, public_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Generate an ECC P-256 key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Try to attest the public key (should fail - only private keys can be attested)
        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(pub_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
    });
}