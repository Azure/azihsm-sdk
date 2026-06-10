// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"

/// Test fixture for ECC key attestation tests across available partition sessions.
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

/// Verifies that key attestation succeeds for generated ECC private keys across all supported
/// curves.
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

            auto attest_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
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

/// Verifies that key attestation rejects a null report data buffer.
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

/// Verifies that key attestation rejects a null report output buffer.
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

/// Verifies that key attestation rejects an invalid key handle.
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
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

/// Verifies that key attestation fails when attempted with an ECC public key.
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

/// Verifies that key attestation succeeds with zero-length report data.
TEST_F(azihsm_ecc_keyattest, zero_length_report_data_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer report_data_buf{ nullptr, 0 };

        azihsm_buffer report_buf{ nullptr, 0 };
        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, 0);

        std::vector<uint8_t> report(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
    });
}

/// Verifies that key attestation succeeds with one byte of report data.
TEST_F(azihsm_ecc_keyattest, one_byte_report_data_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        uint8_t report_data = 0xAB;
        azihsm_buffer report_data_buf{ &report_data, 1 };

        azihsm_buffer report_buf{ nullptr, 0 };
        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, 0);

        std::vector<uint8_t> report(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
    });
}

/// Verifies that key attestation succeeds with the maximum supported report data length.
TEST_F(azihsm_ecc_keyattest, max_length_report_data_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> report_data(128, 0x5A);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 0 };
        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, 0);

        std::vector<uint8_t> report(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
    });
}

/// Verifies that key attestation rejects report data larger than the maximum supported length.
TEST_F(azihsm_ecc_keyattest, report_data_larger_than_max_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> report_data(129, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that key attestation rejects a null report data pointer with a nonzero length.
TEST_F(azihsm_ecc_keyattest, report_data_null_ptr_with_nonzero_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer report_data_buf{ nullptr, 64 };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that a too-small output buffer reports the required attestation report size.
TEST_F(azihsm_ecc_keyattest, output_buffer_too_small_reports_required_size)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> small_report(1);
        azihsm_buffer report_buf{ small_report.data(), static_cast<uint32_t>(small_report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, small_report.size());
    });
}

/// Verifies that key attestation succeeds when the output buffer is exactly the required size.
TEST_F(azihsm_ecc_keyattest, exact_sized_output_buffer_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer size_query_buf{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &size_query_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(size_query_buf.len, 0);

        std::vector<uint8_t> report(size_query_buf.len);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
        ASSERT_LE(report_buf.len, report.size());

        bool has_non_zero = false;
        for (size_t i = 0; i < report_buf.len; ++i)
        {
            if (report[i] != 0)
            {
                has_non_zero = true;
                break;
            }
        }

        ASSERT_TRUE(has_non_zero);
    });
}

/// Verifies that successful key attestation does not modify the input report data.
TEST_F(azihsm_ecc_keyattest, valid_report_generation_does_not_modify_report_data)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> report_data(64, 0xA5);
        std::vector<uint8_t> original_report_data = report_data;

        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 0 };
        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, 0);

        std::vector<uint8_t> report(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(report_data, original_report_data);
    });
}

/// Verifies that repeated key attestation succeeds for the same ECC private key.
TEST_F(azihsm_ecc_keyattest, repeated_attestation_succeeds_for_same_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        for (int i = 0; i < 2; ++i)
        {
            azihsm_buffer report_buf{ nullptr, 0 };

            auto attest_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(report_buf.len, 0);

            std::vector<uint8_t> report(report_buf.len);
            report_buf.ptr = report.data();

            attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(report_buf.len, 0);
        }
    });
}

/// Verifies that key attestation rejects a null output buffer pointer with a nonzero length.
TEST_F(azihsm_ecc_keyattest, output_buffer_null_ptr_with_nonzero_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer report_buf{ nullptr, 512 };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);

        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that key attestation succeeds when the output buffer is larger than required.
TEST_F(azihsm_ecc_keyattest, oversized_output_buffer_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer size_query_buf{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &size_query_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(size_query_buf.len, 0);

        std::vector<uint8_t> report(size_query_buf.len + 128, 0xA5);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);

        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
        ASSERT_LE(report_buf.len, report.size());
    });
}

/// Verifies that failed key attestation does not modify the output buffer.
TEST_F(azihsm_ecc_keyattest, failed_attestation_does_not_modify_output_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> report_data(129, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512, 0xA5);
        std::vector<uint8_t> original_report = report;

        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);

        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(report, original_report);
    });
}

/// Verifies that size-query attestation fails when report data has a null pointer and nonzero
/// length.
TEST_F(azihsm_ecc_keyattest, invalid_report_data_size_query_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer invalid_report_data_buf{ nullptr, 64 };

        azihsm_buffer report_buf{ nullptr, 0 };

        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &invalid_report_data_buf, &report_buf);

        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

/// Verifies that zero-length report data succeeds for key attestation across all supported curves.
TEST_F(azihsm_ecc_keyattest, zero_length_report_data_succeeds_for_all_curves)
{
    std::vector<KeyAttestTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing zero-length report data with " + std::string(test_case.test_name));

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

            azihsm_buffer report_data_buf{ nullptr, 0 };

            azihsm_buffer report_buf{ nullptr, 0 };
            auto attest_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(report_buf.len, 0);

            std::vector<uint8_t> report(report_buf.len);
            report_buf.ptr = report.data();

            attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(report_buf.len, 0);
        });
    }
}

/// Verifies that boundary report data lengths succeed for key attestation across all supported
/// curves.
TEST_F(azihsm_ecc_keyattest, boundary_report_data_lengths_succeed_for_all_curves)
{
    std::vector<KeyAttestTestParams> curve_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    std::vector<uint32_t> report_data_lengths = {
        1,
        128,
    };

    for (const auto &curve_case : curve_cases)
    {
        for (auto report_data_len : report_data_lengths)
        {
            SCOPED_TRACE(
                "Testing " + std::string(curve_case.test_name) +
                " with report_data_len=" + std::to_string(report_data_len)
            );

            part_list_.for_each_session([&](azihsm_handle session) {
                auto_key priv_key;
                auto_key pub_key;

                auto err = generate_ecc_keypair(
                    session,
                    curve_case.curve,
                    true,
                    priv_key.get_ptr(),
                    pub_key.get_ptr()
                );
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
                ASSERT_NE(priv_key.get(), 0);
                ASSERT_NE(pub_key.get(), 0);

                std::vector<uint8_t> report_data(report_data_len, 0x42);
                azihsm_buffer report_data_buf{ report_data.data(),
                                               static_cast<uint32_t>(report_data.size()) };

                azihsm_buffer report_buf{ nullptr, 0 };
                auto attest_err =
                    azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
                ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
                ASSERT_GT(report_buf.len, 0);

                std::vector<uint8_t> report(report_buf.len);
                report_buf.ptr = report.data();

                attest_err =
                    azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
                ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
                ASSERT_GT(report_buf.len, 0);
            });
        }
    }
}

/// Verifies that two different ECC private keys produce different key attestation reports.
TEST_F(azihsm_ecc_keyattest, different_keys_produce_different_key_reports)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key_1;
        auto_key pub_key_1;
        auto_key priv_key_2;
        auto_key pub_key_2;

        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_1.get_ptr(),
            pub_key_1.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key_1.get(), 0);
        ASSERT_NE(pub_key_1.get(), 0);

        err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_2.get_ptr(),
            pub_key_2.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key_2.get(), 0);
        ASSERT_NE(pub_key_2.get(), 0);
        ASSERT_NE(priv_key_1.get(), priv_key_2.get());

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf_1{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key_1.get(), &report_data_buf, &report_buf_1);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf_1.len, 0);

        std::vector<uint8_t> report_1(report_buf_1.len);
        report_buf_1.ptr = report_1.data();

        attest_err = azihsm_generate_key_report(priv_key_1.get(), &report_data_buf, &report_buf_1);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf_1.len, 0);

        azihsm_buffer report_buf_2{ nullptr, 0 };
        attest_err = azihsm_generate_key_report(priv_key_2.get(), &report_data_buf, &report_buf_2);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf_2.len, 0);

        std::vector<uint8_t> report_2(report_buf_2.len);
        report_buf_2.ptr = report_2.data();

        attest_err = azihsm_generate_key_report(priv_key_2.get(), &report_data_buf, &report_buf_2);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf_2.len, 0);

        report_1.resize(report_buf_1.len);
        report_2.resize(report_buf_2.len);

        ASSERT_NE(report_1, report_2)
            << "Different ECC private keys should produce different key reports";
    });
}

/// Verifies that different report data produces different key attestation reports for the same key.
TEST_F(azihsm_ecc_keyattest, different_report_data_produces_different_key_reports)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> report_data_1(64, 0x42);
        std::vector<uint8_t> report_data_2(64, 0x43);

        azihsm_buffer report_data_buf_1{ report_data_1.data(),
                                         static_cast<uint32_t>(report_data_1.size()) };
        azihsm_buffer report_data_buf_2{ report_data_2.data(),
                                         static_cast<uint32_t>(report_data_2.size()) };

        azihsm_buffer report_buf_1{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf_1, &report_buf_1);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf_1.len, 0);

        std::vector<uint8_t> report_1(report_buf_1.len);
        report_buf_1.ptr = report_1.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf_1, &report_buf_1);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf_1.len, 0);

        azihsm_buffer report_buf_2{ nullptr, 0 };
        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf_2, &report_buf_2);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf_2.len, 0);

        std::vector<uint8_t> report_2(report_buf_2.len);
        report_buf_2.ptr = report_2.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf_2, &report_buf_2);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf_2.len, 0);

        report_1.resize(report_buf_1.len);
        report_2.resize(report_buf_2.len);

        ASSERT_NE(report_1, report_2)
            << "Different report data should produce different key reports";
    });
}

/// Verifies that repeated reports for the same key and report data have a stable report size.
TEST_F(azihsm_ecc_keyattest, repeated_attestation_has_stable_report_size)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        azihsm_buffer first_size_query{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &first_size_query);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(first_size_query.len, 0);

        azihsm_buffer second_size_query{ nullptr, 0 };
        attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &second_size_query);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(second_size_query.len, 0);

        ASSERT_EQ(first_size_query.len, second_size_query.len);
    });
}

/// Verifies that keys from different ECC curves produce different key attestation reports.
TEST_F(azihsm_ecc_keyattest, different_curves_produce_different_key_reports)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key p256_priv_key;
        auto_key p256_pub_key;
        auto_key p384_priv_key;
        auto_key p384_pub_key;

        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            p256_priv_key.get_ptr(),
            p256_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(p256_priv_key.get(), 0);
        ASSERT_NE(p256_pub_key.get(), 0);

        err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P384,
            true,
            p384_priv_key.get_ptr(),
            p384_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(p384_priv_key.get(), 0);
        ASSERT_NE(p384_pub_key.get(), 0);

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer p256_report_buf{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(p256_priv_key.get(), &report_data_buf, &p256_report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(p256_report_buf.len, 0);

        std::vector<uint8_t> p256_report(p256_report_buf.len);
        p256_report_buf.ptr = p256_report.data();

        attest_err =
            azihsm_generate_key_report(p256_priv_key.get(), &report_data_buf, &p256_report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(p256_report_buf.len, 0);

        azihsm_buffer p384_report_buf{ nullptr, 0 };
        attest_err =
            azihsm_generate_key_report(p384_priv_key.get(), &report_data_buf, &p384_report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(p384_report_buf.len, 0);

        std::vector<uint8_t> p384_report(p384_report_buf.len);
        p384_report_buf.ptr = p384_report.data();

        attest_err =
            azihsm_generate_key_report(p384_priv_key.get(), &report_data_buf, &p384_report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(p384_report_buf.len, 0);

        p256_report.resize(p256_report_buf.len);
        p384_report.resize(p384_report_buf.len);

        ASSERT_NE(p256_report, p384_report)
            << "Different ECC curves should produce different key reports";
    });
}