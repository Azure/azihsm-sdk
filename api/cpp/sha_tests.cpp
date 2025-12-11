// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <vector>
#include <array>

class SHATest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        std::tie(partition_handle, session_handle) = open_session();
        ASSERT_NE(session_handle, 0);
    }

    void TearDown() override
    {
        if (session_handle != 0)
        {
            EXPECT_EQ(azihsm_sess_close(session_handle), AZIHSM_ERROR_SUCCESS);
        }
        if (partition_handle != 0)
        {
            EXPECT_EQ(azihsm_part_close(partition_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    azihsm_handle partition_handle = 0;
    azihsm_handle session_handle = 0;
};

// Test data: 1024 bytes filled with 0x01
const std::array<uint8_t, 1024> TEST_DATA_1K = []()
{
    std::array<uint8_t, 1024> data;
    data.fill(0x01);
    return data;
}();

// Expected SHA-1 digest for TEST_DATA_1K
const std::array<uint8_t, 20> EXPECTED_SHA1 = {
    0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c,
    0x56, 0x96, 0x2c, 0xa3, 0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39};

// Expected SHA-256 digest for TEST_DATA_1K
const std::array<uint8_t, 32> EXPECTED_SHA256 = {
    0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e,
    0x00, 0xe1, 0x25, 0xdf, 0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d,
    0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35, 0x8e, 0xa5,
    0x3a, 0x69};

// Expected SHA-384 digest for TEST_DATA_1K
const std::array<uint8_t, 48> EXPECTED_SHA384 = {
    0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2,
    0xb9, 0x9c, 0x41, 0x00, 0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc,
    0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92, 0xef, 0x9e,
    0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c,
    0x93, 0x4a, 0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7};

// Expected SHA-512 digest for TEST_DATA_1K
const std::array<uint8_t, 64> EXPECTED_SHA512 = {
    0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e,
    0x7c, 0xb4, 0x7f, 0xf9, 0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b,
    0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d, 0x94, 0x53,
    0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a,
    0x1a, 0xda, 0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44,
    0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb, 0xde, 0x66, 0x15, 0x37,
    0x5b, 0xab, 0x4a, 0xe8};

TEST_F(SHATest, SHA1OneShot)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA1,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 20> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest, EXPECTED_SHA1);
}

TEST_F(SHATest, SHA256OneShot)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest, EXPECTED_SHA256);
}

TEST_F(SHATest, SHA384OneShot)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA384,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 48> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest, EXPECTED_SHA384);
}

TEST_F(SHATest, SHA512OneShot)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA512,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 64> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest, EXPECTED_SHA512);
}

TEST_F(SHATest, InvalidAlgorithm)
{
    azihsm_algo algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF), // Invalid algorithm ID
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
}

TEST_F(SHATest, EmptyData)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = nullptr,
        .len = 0};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    // Should either succeed (computing hash of empty data) or fail with invalid argument
    EXPECT_TRUE(err == AZIHSM_ERROR_SUCCESS || err == AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST_F(SHATest, InsufficientDigestBuffer)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    // Buffer too small for SHA-256 (needs 32 bytes, providing only 16)
    std::array<uint8_t, 16> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
}

TEST_F(SHATest, LargeData)
{
    // Test with a larger dataset (10KB)
    std::vector<uint8_t> large_data(10240, 0x42);

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = large_data.data(),
        .len = static_cast<uint32_t>(large_data.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify the digest is not all zeros (basic sanity check)
    bool has_non_zero = false;
    for (auto byte : digest)
    {
        if (byte != 0)
        {
            has_non_zero = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero);
}

// Test various data patterns
TEST_F(SHATest, VariousDataPatterns)
{
    struct TestCase
    {
        std::string name;
        std::vector<uint8_t> data;
        azihsm_algo_id algo_id;
        size_t digest_size;
    };

    std::vector<TestCase> test_cases = {
        {"AllZeros_SHA1", std::vector<uint8_t>(100, 0x00), AZIHSM_ALGO_ID_SHA1, 20},
        {"AllOnes_SHA256", std::vector<uint8_t>(100, 0xFF), AZIHSM_ALGO_ID_SHA256, 32},
        {"Ascending_SHA384", {}, AZIHSM_ALGO_ID_SHA384, 48},
        {"SingleByte_SHA512", {0x42}, AZIHSM_ALGO_ID_SHA512, 64}};

    // Fill ascending pattern
    for (int i = 0; i < 256; ++i)
    {
        test_cases[2].data.push_back(static_cast<uint8_t>(i));
    }

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(test_case.name);

        azihsm_algo algo = {
            .id = test_case.algo_id,
            .params = nullptr,
            .len = 0};

        azihsm_buffer data_buf = {
            .buf = const_cast<uint8_t *>(test_case.data.data()),
            .len = static_cast<uint32_t>(test_case.data.size())};

        std::vector<uint8_t> digest(test_case.digest_size);
        azihsm_buffer digest_buf = {
            .buf = digest.data(),
            .len = static_cast<uint32_t>(digest.size())};

        auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Verify digest is computed (not all zeros)
        bool has_non_zero = false;
        for (auto byte : digest)
        {
            if (byte != 0)
            {
                has_non_zero = true;
                break;
            }
        }
        EXPECT_TRUE(has_non_zero);
    }
}

// ==================== NEGATIVE TESTING ====================

TEST_F(SHATest, NullPointerTests)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    // Test null algorithm pointer
    auto err = azihsm_crypt_digest(session_handle, nullptr, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test null data buffer pointer
    err = azihsm_crypt_digest(session_handle, &algo, nullptr, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test null digest buffer pointer
    err = azihsm_crypt_digest(session_handle, &algo, &data_buf, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST_F(SHATest, InvalidSessionHandle)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    // Test with invalid session handle
    auto err = azihsm_crypt_digest(0xDEADBEEF, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Test with zero session handle
    err = azihsm_crypt_digest(0, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(SHATest, InvalidAlgorithmIds)
{
    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 64> digest; // Large enough for any SHA
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    std::vector<azihsm_algo_id> invalid_algos = {
        static_cast<azihsm_algo_id>(0),          // Zero
        static_cast<azihsm_algo_id>(0xFFFFFFFF), // Max uint32
        static_cast<azihsm_algo_id>(12345),      // Random number
        AZIHSM_ALGO_ID_AES_CBC,                  // Valid but wrong type (AES, not SHA)
        AZIHSM_ALGO_ID_RSA_PKCS,                 // Valid but wrong type (RSA, not SHA)
        AZIHSM_ALGO_ID_ECDSA,                    // Valid but wrong type (ECDSA, not SHA)
        static_cast<azihsm_algo_id>(262149),     // Just after SHA512 (262148)
        static_cast<azihsm_algo_id>(262144),     // Just before SHA1 (262145)
    };

    for (auto invalid_algo : invalid_algos)
    {
        SCOPED_TRACE("Invalid algorithm ID: " + std::to_string(invalid_algo));

        azihsm_algo algo = {
            .id = invalid_algo,
            .params = nullptr,
            .len = 0};

        auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
        EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
    }
}

TEST_F(SHATest, BufferSizeMismatch)
{
    struct TestCase
    {
        azihsm_algo_id algo_id;
        size_t correct_size;
        std::vector<size_t> incorrect_sizes;
    };

    std::vector<TestCase> test_cases = {
        {AZIHSM_ALGO_ID_SHA1, 20, {0, 1, 19, 21, 32, 48, 64}},
        {AZIHSM_ALGO_ID_SHA256, 32, {0, 1, 20, 31, 33, 48, 64}},
        {AZIHSM_ALGO_ID_SHA384, 48, {0, 1, 20, 32, 47, 49, 64}},
        {AZIHSM_ALGO_ID_SHA512, 64, {0, 1, 20, 32, 48, 63, 65, 128}}};

    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    for (const auto &test_case : test_cases)
    {
        for (auto incorrect_size : test_case.incorrect_sizes)
        {
            SCOPED_TRACE("Algorithm: " + std::to_string(test_case.algo_id) +
                         ", incorrect size: " + std::to_string(incorrect_size));

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0};

            std::vector<uint8_t> digest(std::max(incorrect_size, size_t(1))); // Ensure at least 1 byte
            azihsm_buffer digest_buf = {
                .buf = digest.data(),
                .len = static_cast<uint32_t>(incorrect_size)};

            auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
            EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
        }
    }
}

// ==================== CORNER CASES ====================

TEST_F(SHATest, EmptyDataKnownVectors)
{
    // Test known vectors for empty input across all SHA algorithms
    struct TestCase
    {
        azihsm_algo_id algo_id;
        std::vector<uint8_t> expected_digest;
    };

    std::vector<TestCase> test_cases = {
        {AZIHSM_ALGO_ID_SHA1,
         {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
          0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09}},
        {AZIHSM_ALGO_ID_SHA256,
         {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
          0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
          0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
          0xb8, 0x55}}};

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Empty data test for algorithm: " + std::to_string(test_case.algo_id));

        azihsm_algo algo = {
            .id = test_case.algo_id,
            .params = nullptr,
            .len = 0};

        azihsm_buffer data_buf = {
            .buf = nullptr,
            .len = 0};

        std::vector<uint8_t> digest(test_case.expected_digest.size());
        azihsm_buffer digest_buf = {
            .buf = digest.data(),
            .len = static_cast<uint32_t>(digest.size())};

        auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
        if (err == AZIHSM_ERROR_SUCCESS)
        {
            // If empty data is supported, verify the known vector
            EXPECT_EQ(digest, test_case.expected_digest);
        }
        else
        {
            // Empty data might not be supported - that's also valid
            EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
        }
    }
}

TEST_F(SHATest, MaximumDataSize)
{
    // Test with very large data (1MB) to check for overflow/memory issues
    const size_t large_size = 1024 * 1024; // 1MB
    std::vector<uint8_t> large_data(large_size);

    // Fill with a pattern to make it interesting
    for (size_t i = 0; i < large_size; ++i)
    {
        large_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_buffer data_buf = {
        .buf = large_data.data(),
        .len = static_cast<uint32_t>(large_size)};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify the digest is computed
    bool has_non_zero = false;
    for (auto byte : digest)
    {
        if (byte != 0)
        {
            has_non_zero = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero);
}

TEST_F(SHATest, NonNullDataWithZeroLength)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    // Valid pointer but zero length
    uint8_t dummy_byte = 0x42;
    azihsm_buffer data_buf = {
        .buf = &dummy_byte,
        .len = 0};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
    // Should behave the same as empty data test
    EXPECT_TRUE(err == AZIHSM_ERROR_SUCCESS || err == AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST_F(SHATest, AlgorithmParametersHandling)
{
    azihsm_buffer data_buf = {
        .buf = const_cast<uint8_t *>(TEST_DATA_1K.data()),
        .len = static_cast<uint32_t>(TEST_DATA_1K.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    // Test with non-null params (should be ignored for SHA algorithms)
    uint8_t dummy_params[16] = {0};
    azihsm_algo algo_with_params = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = dummy_params,
        .len = sizeof(dummy_params)};

    auto err = azihsm_crypt_digest(session_handle, &algo_with_params, &data_buf, &digest_buf);
    // Should succeed (params ignored) or fail with invalid argument (params not allowed)
    EXPECT_TRUE(err == AZIHSM_ERROR_SUCCESS || err == AZIHSM_ERROR_INVALID_ARGUMENT);

    if (err == AZIHSM_ERROR_SUCCESS)
    {
        // Verify it produces the same result as without parameters
        std::array<uint8_t, 32> digest_no_params;
        azihsm_buffer digest_buf_no_params = {
            .buf = digest_no_params.data(),
            .len = static_cast<uint32_t>(digest_no_params.size())};

        azihsm_algo algo_no_params = {
            .id = AZIHSM_ALGO_ID_SHA256,
            .params = nullptr,
            .len = 0};

        auto err2 = azihsm_crypt_digest(session_handle, &algo_no_params, &data_buf, &digest_buf_no_params);
        EXPECT_EQ(err2, AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(digest, digest_no_params);
    }
}

// ==================== BOUNDARY VALUE TESTING ====================

TEST_F(SHATest, BoundaryDataSizes)
{
    // Test various boundary sizes that might trigger edge cases
    std::vector<size_t> test_sizes = {
        1,   // Minimum
        15,  // Just under 16
        16,  // Exactly 16 (common block boundary)
        17,  // Just over 16
        31,  // Just under 32
        32,  // Exactly 32
        33,  // Just over 32
        63,  // Just under 64
        64,  // Exactly 64 (SHA block size)
        65,  // Just over 64
        127, // Just under 128
        128, // Exactly 128
        129, // Just over 128
        255, // Just under 256
        256, // Exactly 256
        257, // Just over 256
        511, // Just under 512
        512, // Exactly 512
        513, // Just over 512
    };

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    for (auto size : test_sizes)
    {
        SCOPED_TRACE("Boundary test with size: " + std::to_string(size));

        std::vector<uint8_t> test_data(size, 0x55); // Fill with pattern

        azihsm_buffer data_buf = {
            .buf = test_data.data(),
            .len = static_cast<uint32_t>(size)};

        auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Basic sanity check - digest should not be all zeros
        bool has_non_zero = false;
        for (auto byte : digest)
        {
            if (byte != 0)
            {
                has_non_zero = true;
                break;
            }
        }
        EXPECT_TRUE(has_non_zero);
    }
}

// ==================== STRESS TESTING ====================

TEST_F(SHATest, RepeatedOperations)
{
    // Test performing many operations in sequence to check for resource leaks
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_SHA256,
        .params = nullptr,
        .len = 0};

    std::vector<uint8_t> test_data(100, 0x42);
    azihsm_buffer data_buf = {
        .buf = test_data.data(),
        .len = static_cast<uint32_t>(test_data.size())};

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf = {
        .buf = digest.data(),
        .len = static_cast<uint32_t>(digest.size())};

    // Perform 100 hash operations
    std::array<uint8_t, 32> first_digest;
    for (int i = 0; i < 100; ++i)
    {
        SCOPED_TRACE("Iteration: " + std::to_string(i));

        auto err = azihsm_crypt_digest(session_handle, &algo, &data_buf, &digest_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        if (i == 0)
        {
            first_digest = digest;
        }
        else
        {
            // All results should be identical
            EXPECT_EQ(digest, first_digest);
        }
    }
}

TEST_F(SHATest, ShaStreamingDigestAllAlgorithms)
{
    struct TestCase
    {
        azihsm_algo_id algo_id;
        uint32_t expected_len;
        const char *name;
    };

    TestCase test_cases[] = {
        {AZIHSM_ALGO_ID_SHA1, 20, "SHA1"},
        {AZIHSM_ALGO_ID_SHA256, 32, "SHA256"},
        {AZIHSM_ALGO_ID_SHA384, 48, "SHA384"},
        {AZIHSM_ALGO_ID_SHA512, 64, "SHA512"},
    };

    const char *message = "Test message for streaming digest";

    for (const auto &test : test_cases)
    {
        azihsm_algo algo = {.id = test.algo_id, .params = nullptr, .len = 0};

        // Streaming digest
        azihsm_handle digest_ctx = 0;
        auto err = azihsm_crypt_digest_init(session_handle, &algo, &digest_ctx);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to init " << test.name << " digest stream";

        azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};
        err = azihsm_crypt_digest_update(digest_ctx, &message_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to update " << test.name << " digest stream";

        std::vector<uint8_t> streaming_digest_data(test.expected_len);
        azihsm_buffer streaming_digest = {.buf = streaming_digest_data.data(), .len = test.expected_len};
        err = azihsm_crypt_digest_final(digest_ctx, &streaming_digest);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to finalize " << test.name << " digest stream";
        EXPECT_EQ(streaming_digest.len, test.expected_len);

        // Non-streaming digest for comparison
        std::vector<uint8_t> non_streaming_digest_data(test.expected_len);
        azihsm_buffer non_streaming_digest = {.buf = non_streaming_digest_data.data(), .len = test.expected_len};
        err = azihsm_crypt_digest(session_handle, &algo, &message_buf, &non_streaming_digest);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed non-streaming " << test.name << " digest";

        EXPECT_EQ(streaming_digest.len, non_streaming_digest.len);
        EXPECT_EQ(memcmp(streaming_digest.buf, non_streaming_digest.buf, streaming_digest.len), 0)
            << test.name << " streaming and non-streaming digests should match";
    }
}

TEST_F(SHATest, ShaStreamingDigestEmptyMessage)
{
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_SHA256, .params = nullptr, .len = 0};

    // Initialize digest stream
    azihsm_handle digest_ctx = 0;
    auto err = azihsm_crypt_digest_init(session_handle, &algo, &digest_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Don't call update - finalize immediately with empty data
    std::vector<uint8_t> digest_data(32);
    azihsm_buffer digest = {.buf = digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(digest_ctx, &digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest.len, 32u);

    // Verify against expected SHA-256 of empty string
    uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55};
    EXPECT_EQ(memcmp(digest.buf, expected, 32), 0);
}

TEST_F(SHATest, ShaStreamingDigestLargeMessage)
{
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_SHA256, .params = nullptr, .len = 0};

    // Initialize digest stream
    azihsm_handle digest_ctx = 0;
    auto err = azihsm_crypt_digest_init(session_handle, &algo, &digest_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Update with large message in chunks
    const size_t chunk_size = 1024;
    const size_t num_chunks = 1024; // 1MB total
    std::vector<uint8_t> chunk(chunk_size);

    for (size_t i = 0; i < num_chunks; i++)
    {
        std::fill(chunk.begin(), chunk.end(), static_cast<uint8_t>(i % 256));
        azihsm_buffer chunk_buf = {.buf = chunk.data(), .len = (uint32_t)chunk_size};
        err = azihsm_crypt_digest_update(digest_ctx, &chunk_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    // Finalize
    std::vector<uint8_t> digest_data(32);
    azihsm_buffer digest = {.buf = digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(digest_ctx, &digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(digest.len, 32u);

    // Verify against non-streaming version
    std::vector<uint8_t> large_message;
    for (size_t i = 0; i < num_chunks; i++)
    {
        std::vector<uint8_t> chunk_data(chunk_size, static_cast<uint8_t>(i % 256));
        large_message.insert(large_message.end(), chunk_data.begin(), chunk_data.end());
    }

    azihsm_buffer message_buf = {.buf = large_message.data(), .len = (uint32_t)large_message.size()};
    std::vector<uint8_t> expected_digest_data(32);
    azihsm_buffer expected_digest = {.buf = expected_digest_data.data(), .len = 32};
    err = azihsm_crypt_digest(session_handle, &algo, &message_buf, &expected_digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(memcmp(digest.buf, expected_digest.buf, 32), 0);
}

TEST_F(SHATest, ShaStreamingDigestMultipleSmallUpdates)
{
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_SHA256, .params = nullptr, .len = 0};

    // Initialize digest stream
    azihsm_handle digest_ctx = 0;
    auto err = azihsm_crypt_digest_init(session_handle, &algo, &digest_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Update with many small chunks (single bytes)
    const char *message = "abcdefghijklmnopqrstuvwxyz";
    for (size_t i = 0; i < strlen(message); i++)
    {
        azihsm_buffer byte_buf = {.buf = (uint8_t *)&message[i], .len = 1};
        err = azihsm_crypt_digest_update(digest_ctx, &byte_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    // Finalize
    std::vector<uint8_t> digest_data(32);
    azihsm_buffer digest = {.buf = digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(digest_ctx, &digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify against non-streaming version
    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};
    std::vector<uint8_t> expected_digest_data(32);
    azihsm_buffer expected_digest = {.buf = expected_digest_data.data(), .len = 32};
    err = azihsm_crypt_digest(session_handle, &algo, &message_buf, &expected_digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(memcmp(digest.buf, expected_digest.buf, 32), 0);
}

TEST_F(SHATest, ShaStreamingDigestInsufficientBuffer)
{
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_SHA256, .params = nullptr, .len = 0};

    // Initialize digest stream
    azihsm_handle digest_ctx = 0;
    auto err = azihsm_crypt_digest_init(session_handle, &algo, &digest_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    const char *message = "Test message";
    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};
    err = azihsm_crypt_digest_update(digest_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Try to finalize with insufficient buffer
    std::vector<uint8_t> small_digest_data(16); // Too small for SHA-256
    azihsm_buffer small_digest = {.buf = small_digest_data.data(), .len = 16};
    err = azihsm_crypt_digest_final(digest_ctx, &small_digest);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(small_digest.len, 32u); // Should be updated to required size
}

TEST_F(SHATest, ShaStreamingDigestChunkedVsWhole)
{
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_SHA256, .params = nullptr, .len = 0};

    const char *message = "The quick brown fox jumps over the lazy dog";

    // Stream with multiple chunks
    azihsm_handle chunked_ctx = 0;
    auto err = azihsm_crypt_digest_init(session_handle, &algo, &chunked_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    for (size_t i = 0; i < strlen(message); i += 5)
    {
        size_t chunk_len = std::min(size_t(5), strlen(message) - i);
        azihsm_buffer chunk_buf = {.buf = (uint8_t *)&message[i], .len = (uint32_t)chunk_len};
        err = azihsm_crypt_digest_update(chunked_ctx, &chunk_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    std::vector<uint8_t> chunked_digest_data(32);
    azihsm_buffer chunked_digest = {.buf = chunked_digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(chunked_ctx, &chunked_digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Stream with whole message
    azihsm_handle whole_ctx = 0;
    err = azihsm_crypt_digest_init(session_handle, &algo, &whole_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};
    err = azihsm_crypt_digest_update(whole_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::vector<uint8_t> whole_digest_data(32);
    azihsm_buffer whole_digest = {.buf = whole_digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(whole_ctx, &whole_digest);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(memcmp(chunked_digest.buf, whole_digest.buf, 32), 0);
}

TEST_F(SHATest, ShaStreamingDigestInvalidHandle)
{
    const char *message = "Test message";
    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};

    // Try to update with invalid handle
    auto err = azihsm_crypt_digest_update(0xDEADBEEF, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Try to finalize with invalid handle
    std::vector<uint8_t> digest_data(32);
    azihsm_buffer digest = {.buf = digest_data.data(), .len = 32};
    err = azihsm_crypt_digest_final(0xDEADBEEF, &digest);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}