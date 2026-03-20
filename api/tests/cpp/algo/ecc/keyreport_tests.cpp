// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "algo/aes/helpers.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"

// This file focuses on ECC key attestation report generation and report buffer contracts.
// Note: These tests currently validate API contract behavior (status codes, sizing, and
// basic output presence) and do not parse/validate the internal report binary layout,
// because a public key attestation report format specification is not yet available.

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

            // Verify the report buffer was populated (not all zeros).
            // We intentionally do not validate report field layout here because
            // the report binary format is not yet known.
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
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_HANDLE);
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

TEST_F(azihsm_ecc_keyattest, report_data_boundary_cases)
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

        auto assert_two_pass_success = [&](azihsm_buffer &report_data_buf) {
            azihsm_buffer report_buf{ nullptr, 0 };

            auto size_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(report_buf.len, 0u);

            std::vector<uint8_t> report(report_buf.len);
            report_buf.ptr = report.data();
            auto report_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(report_err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(report_buf.len, 0u);
        };

        azihsm_buffer empty_report_data{ nullptr, 0 };
        assert_two_pass_success(empty_report_data);

        std::vector<uint8_t> max_report_data(128, 0x42);
        azihsm_buffer max_report_data_buf{ max_report_data.data(),
                                           static_cast<uint32_t>(max_report_data.size()) };
        assert_two_pass_success(max_report_data_buf);

        std::vector<uint8_t> over_max_report_data(129, 0x42);
        azihsm_buffer over_max_report_data_buf{ over_max_report_data.data(),
                                                static_cast<uint32_t>(over_max_report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 0 };
        auto over_max_err =
            azihsm_generate_key_report(priv_key.get(), &over_max_report_data_buf, &report_buf);
        ASSERT_NE(over_max_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_keyattest, report_data_invalid_buffer_shape_rejected)
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

        azihsm_buffer invalid_report_data{ nullptr, 1 };
        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &invalid_report_data, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keyattest, report_data_content_variants_succeed)
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

        std::vector<std::vector<uint8_t>> test_vectors = {
            std::vector<uint8_t>(64, 0x00),
            std::vector<uint8_t>(64, 0xA5),
        };

        for (const auto &data : test_vectors)
        {
            azihsm_buffer report_data_buf{ const_cast<uint8_t *>(data.data()),
                                           static_cast<uint32_t>(data.size()) };

            azihsm_buffer report_buf{ nullptr, 0 };
            auto size_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(report_buf.len, 0u);

            std::vector<uint8_t> report(report_buf.len);
            report_buf.ptr = report.data();
            auto attest_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(report_buf.len, 0u);
        }
    });
}

TEST_F(azihsm_ecc_keyattest, output_buffer_contract_cases)
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

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(), static_cast<uint32_t>(report_data.size()) };

        // Output-buffer contract for key report:
        // 1) Size query uses {ptr=nullptr, len=0} and returns BUFFER_TOO_SMALL.
        // 2) Returned len is required capacity (upper bound to allocate).
        // 3) On success, len is overwritten with actual bytes produced (<= capacity).
        azihsm_buffer size_query_buf{ nullptr, 0 };
        auto size_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &size_query_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(size_query_buf.len, 0u);
        const uint32_t required_len = size_query_buf.len;

        // Buffer smaller than required capacity -> BUFFER_TOO_SMALL and len reset to required capacity.
        std::vector<uint8_t> too_small_buf_data(required_len - 1);
        azihsm_buffer too_small_buf{ too_small_buf_data.data(),
                                     static_cast<uint32_t>(too_small_buf_data.size()) };
        auto too_small_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &too_small_buf);
        ASSERT_EQ(too_small_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small_buf.len, required_len);

        // Exact required capacity -> success; len reports actual produced bytes.
        std::vector<uint8_t> exact_buf_data(required_len);
        azihsm_buffer exact_buf{ exact_buf_data.data(), static_cast<uint32_t>(exact_buf_data.size()) };
        auto exact_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &exact_buf);
        ASSERT_EQ(exact_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(exact_buf.len, 0u);
        ASSERT_LE(exact_buf.len, required_len);

        // Larger-than-required capacity -> success; len still reports actual produced bytes.
        std::vector<uint8_t> large_buf_data(required_len + 64);
        azihsm_buffer large_buf{ large_buf_data.data(), static_cast<uint32_t>(large_buf_data.size()) };
        auto large_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &large_buf);
        ASSERT_EQ(large_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(large_buf.len, 0u);
        ASSERT_LE(large_buf.len, required_len);
    });
}

TEST_F(azihsm_ecc_keyattest, report_rejects_invalid_output_buffer_shape)
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

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(), static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer invalid_report_buf{ nullptr, 1 };
        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &invalid_report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_keyattest, report_rejects_non_attestable_handle_classes)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(), static_cast<uint32_t>(report_data.size()) };
        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        // Session handle is not attestable key handle
        auto sess_err = azihsm_generate_key_report(session.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(sess_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);

        // Partition handle is not attestable key handle
        auto part_err = azihsm_generate_key_report(partition.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(part_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);

        // Partition-list handle is not attestable key handle
        auto list_err = azihsm_generate_key_report(part_list_.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(list_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);

        // Symmetric key handle is not attestable key handle
        auto aes_key = generate_aes_key(session.get(), 256);
        auto aes_err = azihsm_generate_key_report(aes_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(aes_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
    });
}

TEST_F(azihsm_ecc_keyattest, report_invalid_and_deleted_key_handle_status)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(), static_cast<uint32_t>(report_data.size()) };
        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto invalid_err = azihsm_generate_key_report(0xDEADBEEF, &report_data_buf, &report_buf);
        ASSERT_EQ(invalid_err, AZIHSM_STATUS_INVALID_HANDLE);

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

        azihsm_handle deleted_key = priv_key.get();
        auto delete_err = azihsm_key_delete(deleted_key);
        ASSERT_EQ(delete_err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        auto deleted_err = azihsm_generate_key_report(deleted_key, &report_data_buf, &report_buf);
        ASSERT_EQ(deleted_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}
