// Copyright (C) Microsoft Corporation. All rights reserved.

#include <array>
#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_sha_digest : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to perform one-shot digest test
    void test_one_shot_digest(
        azihsm_handle session,
        azihsm_algo &algo,
        const uint8_t *data,
        size_t data_len
    )
    {
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(data);
        data_buf.len = static_cast<uint32_t>(data_len);

        // First call to get required digest size
        azihsm_buffer digest_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(digest_buf.len, 0);

        // Allocate buffer and compute digest
        std::vector<uint8_t> digest(digest_buf.len);
        digest_buf.ptr = digest.data();
        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(digest_buf.len, 0);
    }

    // Helper function to perform streaming digest test
    void test_streaming_digest(
        azihsm_handle session,
        azihsm_algo &algo,
        const uint8_t *data,
        size_t data_len,
        size_t chunk_size
    )
    {
        // Initialize streaming context
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session, &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(ctx_handle, 0u);

        // Update with chunks
        for (size_t offset = 0; offset < data_len; offset += chunk_size)
        {
            size_t remaining = data_len - offset;
            size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;

            azihsm_buffer data_buf{};
            data_buf.ptr = const_cast<uint8_t *>(data + offset);
            data_buf.len = static_cast<uint32_t>(current_chunk);

            err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }

        // First call to get required digest size
        azihsm_buffer digest_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(digest_buf.len, 0);

        // Allocate buffer and finalize
        std::vector<uint8_t> digest(digest_buf.len);
        digest_buf.ptr = digest.data();
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(digest_buf.len, 0);
    }
};

// Test data: 1024 bytes filled with 0x01
const std::array<uint8_t, 1024> TEST_DATA_1K = []() {
    std::array<uint8_t, 1024> data;
    data.fill(0x01);
    return data;
}();

// Unified test data structure for SHA tests
struct ShaTestParams
{
    azihsm_algo_id algo_id;
    const char *test_name;
};

// One-Shot Digest Tests
TEST_F(azihsm_sha_digest, one_shot_all_algorithms)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing " + std::string(test_case.test_name) + " one-shot");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            test_one_shot_digest(session, algo, TEST_DATA_1K.data(), TEST_DATA_1K.size());
        });
    }
}

// Streaming Digest Tests - Single Update
TEST_F(azihsm_sha_digest, streaming_single_update_all_algorithms)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing " + std::string(test_case.test_name) + " streaming single update");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            test_streaming_digest(
                session,
                algo,
                TEST_DATA_1K.data(),
                TEST_DATA_1K.size(),
                TEST_DATA_1K.size() // Single chunk
            );
        });
    }
}

// Streaming Digest Tests - Multiple Updates
TEST_F(azihsm_sha_digest, streaming_multiple_updates_all_algorithms)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing " + std::string(test_case.test_name) + " streaming multiple updates");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            test_streaming_digest(
                session,
                algo,
                TEST_DATA_1K.data(),
                TEST_DATA_1K.size(),
                256 // Multiple 256-byte chunks
            );
        });
    }
}

TEST_F(azihsm_sha_digest, empty_data_sha256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        uint8_t empty_data = 0;
        azihsm_buffer data_buf{};
        data_buf.ptr = &empty_data;
        data_buf.len = 0;

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, insufficient_buffer_sha256)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 16> small_digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = small_digest.data();
        digest_buf.len = 16; // Too small for SHA-256 (needs 32)

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(digest_buf.len, 32u); // Updated to required size
    });
}

TEST_F(azihsm_sha_digest, null_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session, nullptr, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, null_data_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session, &algo, nullptr, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, null_digest_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, invalid_session_handle)
{
    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_SHA256;
    algo.params = nullptr;
    algo.len = 0;

    azihsm_buffer data_buf{};
    data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
    data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf{};
    digest_buf.ptr = digest.data();
    digest_buf.len = static_cast<uint32_t>(digest.size());

    // Invalid handle
    auto err = azihsm_crypt_digest(0xDEADBEEF, &algo, &data_buf, &digest_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    // Zero handle
    err = azihsm_crypt_digest(0, &algo, &data_buf, &digest_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_sha_digest, unsupported_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, streaming_empty_data)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session, &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Finalize without any update (hash of empty data)
        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, streaming_insufficient_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session, &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Finalize with insufficient buffer
        std::array<uint8_t, 16> small_digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = small_digest.data();
        digest_buf.len = 16; // Too small for SHA-256

        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(digest_buf.len, 32u); // Updated to required size
    });
}

TEST_F(azihsm_sha_digest, streaming_invalid_context_handle)
{
    azihsm_buffer data_buf{};
    data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
    data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

    // Invalid handle for update
    auto err = azihsm_crypt_digest_update(0xDEADBEEF, &data_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    // Invalid handle for final
    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf{};
    digest_buf.ptr = digest.data();
    digest_buf.len = static_cast<uint32_t>(digest.size());

    err = azihsm_crypt_digest_final(0xDEADBEEF, &digest_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_sha_digest, streaming_null_context_handle)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto err = azihsm_crypt_digest_init(session, &algo, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, streaming_consistency_with_one_shot)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // One-shot digest
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 32> one_shot_digest;
        azihsm_buffer one_shot_buf{};
        one_shot_buf.ptr = one_shot_digest.data();
        one_shot_buf.len = static_cast<uint32_t>(one_shot_digest.size());

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &one_shot_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Streaming digest
        azihsm_handle ctx_handle = 0;
        err = azihsm_crypt_digest_init(session, &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::array<uint8_t, 32> streaming_digest;
        azihsm_buffer streaming_buf{};
        streaming_buf.ptr = streaming_digest.data();
        streaming_buf.len = static_cast<uint32_t>(streaming_digest.size());

        err = azihsm_crypt_digest_final(ctx_handle, &streaming_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Compare results - they should be identical
        ASSERT_EQ(one_shot_digest, streaming_digest);
    });
}