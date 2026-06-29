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
#include "utils/rsa_keygen.hpp"

class azihsm_rsa_keyattest : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

bool buffer_has_non_zero(const std::vector<uint8_t> &buffer, uint32_t len)
{
    const size_t end = std::min(buffer.size(), static_cast<size_t>(len));

    for (size_t i = 0; i < end; ++i)
    {
        if (buffer[i] != 0)
        {
            return true;
        }
    }

    return false;
}

azihsm_status generate_rsa_private_key_for_attest(
    azihsm_handle session,
    auto_key &priv_key,
    auto_key &pub_key
)
{
    auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    if (priv_key.get() == 0 || pub_key.get() == 0)
    {
        return AZIHSM_STATUS_INVALID_HANDLE;
    }

    return AZIHSM_STATUS_SUCCESS;
}

// Verifies that RSA 2048 private key attestation succeeds and returns a populated report.
TEST_F(azihsm_rsa_keyattest, attest_rsa_2048_key)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate an RSA 2048 key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
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

// Verifies that attestation rejects an invalid key handle.
TEST_F(azihsm_rsa_keyattest, attest_invalid_key_handle)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

// Verifies that attestation rejects an RSA public key because only private keys are supported.
TEST_F(azihsm_rsa_keyattest, attest_public_key_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate an RSA 2048 key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
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

// Verifies that exactly 128 bytes of report data is accepted.
TEST_F(azihsm_rsa_keyattest, attest_accepts_max_report_data_size)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

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
        ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
    });
}

// Verifies that report data larger than 128 bytes is rejected.
TEST_F(azihsm_rsa_keyattest, attest_rejects_report_data_larger_than_max)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(129, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies that empty report data is accepted.
TEST_F(azihsm_rsa_keyattest, attest_accepts_empty_report_data)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

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
        ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
    });
}

// Verifies that a too-small report output buffer fails and returns the required size.
TEST_F(azihsm_rsa_keyattest, attest_rejects_small_report_buffer_and_sets_required_size)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(1, 0xA5);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, report.size());
    });
}

// Verifies that the report output buffer struct is required.
TEST_F(azihsm_rsa_keyattest, attest_rejects_null_report_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, nullptr);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies that a null report output pointer with non-zero length is rejected.
TEST_F(azihsm_rsa_keyattest, attest_rejects_null_report_output_pointer_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 512 };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies that report data with null pointer and non-zero length is rejected.
TEST_F(azihsm_rsa_keyattest, attest_rejects_null_report_data_pointer_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer report_data_buf{ nullptr, 64 };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies that repeated attestation calls on the same RSA private key succeed.
TEST_F(azihsm_rsa_keyattest, attest_same_key_multiple_times_succeeds)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        for (int i = 0; i < 3; ++i)
        {
            SCOPED_TRACE("Attestation iteration " + std::to_string(i));

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
            ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
        }
    });
}

// Verifies that a null report data buffer pointer is rejected.
TEST_F(azihsm_rsa_keyattest, attest_rejects_null_report_data_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), nullptr, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies that size-query mode fails for an invalid key handle.
TEST_F(azihsm_rsa_keyattest, attest_invalid_key_handle_size_query_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        (void)session;

        azihsm_handle invalid_key = 0;

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 0 };

        auto attest_err = azihsm_generate_key_report(invalid_key, &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Verifies that a deleted RSA private key cannot be attested.
TEST_F(azihsm_rsa_keyattest, attest_deleted_private_key_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_handle deleted_key = priv_key.get();

        auto err = azihsm_key_delete(deleted_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(deleted_key, &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Verifies that the exact report size returned by the size-query call is sufficient.
TEST_F(azihsm_rsa_keyattest, attest_succeeds_with_exact_required_report_size)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x7B);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer size_query_buf{ nullptr, 0 };

        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &size_query_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(size_query_buf.len, 0);

        std::vector<uint8_t> report(size_query_buf.len);
        azihsm_buffer report_buf{ report.data(), size_query_buf.len };

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
        ASSERT_LE(report_buf.len, report.size());
        ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
    });
}

// Verifies that different valid report data contents can be used for attestation.
TEST_F(azihsm_rsa_keyattest, attest_accepts_different_report_data_patterns)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<std::vector<uint8_t>> report_data_cases = {
            std::vector<uint8_t>(1, 0x00),
            std::vector<uint8_t>(32, 0xFF),
            std::vector<uint8_t>(64, 0xA5),
            std::vector<uint8_t>(128, 0x5A),
        };

        for (size_t i = 0; i < report_data_cases.size(); ++i)
        {
            SCOPED_TRACE("Report data case " + std::to_string(i));

            auto &report_data = report_data_cases[i];
            azihsm_buffer report_data_buf{ report_data.data(),
                                           static_cast<uint32_t>(report_data.size()) };

            azihsm_buffer size_query_buf{ nullptr, 0 };

            auto attest_err =
                azihsm_generate_key_report(priv_key.get(), &report_data_buf, &size_query_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(size_query_buf.len, 0);

            std::vector<uint8_t> report(size_query_buf.len);
            azihsm_buffer report_buf{ report.data(), size_query_buf.len };

            attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
            ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(report_buf.len, 0);
            ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
        }
    });
}

// Verifies that 127-byte report data is accepted just below the max boundary.
TEST_F(azihsm_rsa_keyattest, attest_accepts_report_data_one_less_than_max)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(127, 0x33);
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
        ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
    });
}

// Verifies that a public key also fails during size-query mode.
TEST_F(azihsm_rsa_keyattest, attest_public_key_size_query_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer report_buf{ nullptr, 0 };

        auto attest_err = azihsm_generate_key_report(pub_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_UNSUPPORTED_KEY_KIND);
    });
}

// Verifies that a deleted RSA public key cannot be attested.
TEST_F(azihsm_rsa_keyattest, attest_deleted_public_key_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_handle deleted_key = pub_key.get();

        auto err = azihsm_key_delete(deleted_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        pub_key.release();

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> report(512);
        azihsm_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };

        auto attest_err = azihsm_generate_key_report(deleted_key, &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Verifies that after BUFFER_TOO_SMALL, using the returned size succeeds.
TEST_F(azihsm_rsa_keyattest, attest_retry_after_small_buffer_succeeds)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        std::vector<uint8_t> small_report(1, 0xA5);
        azihsm_buffer report_buf{ small_report.data(), static_cast<uint32_t>(small_report.size()) };

        auto attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(report_buf.len, small_report.size());

        std::vector<uint8_t> report(report_buf.len);
        report_buf.ptr = report.data();

        attest_err = azihsm_generate_key_report(priv_key.get(), &report_data_buf, &report_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(report_buf.len, 0);
        ASSERT_TRUE(buffer_has_non_zero(report, report_buf.len));
    });
}

// Verifies the reported required size is stable across repeated size-query calls.
TEST_F(azihsm_rsa_keyattest, attest_size_query_returns_stable_required_size)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        ASSERT_EQ(
            generate_rsa_private_key_for_attest(session, priv_key, pub_key),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> report_data(64, 0x42);
        azihsm_buffer report_data_buf{ report_data.data(),
                                       static_cast<uint32_t>(report_data.size()) };

        azihsm_buffer first_query_buf{ nullptr, 0 };
        auto attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &first_query_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(first_query_buf.len, 0);

        azihsm_buffer second_query_buf{ nullptr, 0 };
        attest_err =
            azihsm_generate_key_report(priv_key.get(), &report_data_buf, &second_query_buf);
        ASSERT_EQ(attest_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(second_query_buf.len, first_query_buf.len);
    });
}