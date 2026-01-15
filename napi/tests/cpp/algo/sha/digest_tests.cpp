// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>
#include <array>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_sha_digest : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Test data: 1024 bytes filled with 0x01
const std::array<uint8_t, 1024> TEST_DATA_1K = []()
{
    std::array<uint8_t, 1024> data;
    data.fill(0x01);
    return data;
}();

TEST_F(azihsm_sha_digest, sha1_one_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA1;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 20> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 20u);
    });
}

TEST_F(azihsm_sha_digest, sha256_one_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

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

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, sha384_one_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 48> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 48u);
    });
}

TEST_F(azihsm_sha_digest, sha512_one_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 64> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 64u);
    });
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
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, insufficient_buffer_sha256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

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

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_BUFFER_TOO_SMALL);
        ASSERT_EQ(digest_buf.len, 32u); // Updated to required size
    });
}

TEST_F(azihsm_sha_digest, null_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), nullptr, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, null_data_buffer)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, nullptr, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, null_digest_buffer)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, nullptr);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
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
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Zero handle
    err = azihsm_crypt_digest(0, &algo, &data_buf, &digest_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(azihsm_sha_digest, unsupported_algorithm)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

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

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

// ==================== Streaming Digest Tests ====================

TEST_F(azihsm_sha_digest, sha256_streaming_single_update)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming context
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(ctx_handle, 0u);

        // Update with data
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize and get digest
        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, sha256_streaming_multiple_updates)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming context
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Update with multiple chunks
        constexpr size_t chunk_size = 256;
        for (size_t offset = 0; offset < TEST_DATA_1K.size(); offset += chunk_size)
        {
            size_t remaining = TEST_DATA_1K.size() - offset;
            size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;

            azihsm_buffer data_buf{};
            data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data() + offset);
            data_buf.len = static_cast<uint32_t>(current_chunk);

            err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
            ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        }

        // Finalize and get digest
        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, sha1_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA1;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize
        std::array<uint8_t, 20> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 20u);
    });
}

TEST_F(azihsm_sha_digest, sha384_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize
        std::array<uint8_t, 48> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 48u);
    });
}

TEST_F(azihsm_sha_digest, sha512_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize
        std::array<uint8_t, 64> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 64u);
    });
}

TEST_F(azihsm_sha_digest, streaming_empty_data)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize without any update (hash of empty data)
        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

TEST_F(azihsm_sha_digest, streaming_insufficient_buffer)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        azihsm_handle ctx_handle = 0;
        auto err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Finalize with insufficient buffer
        std::array<uint8_t, 16> small_digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = small_digest.data();
        digest_buf.len = 16; // Too small for SHA-256

        err = azihsm_crypt_digest_final(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_BUFFER_TOO_SMALL);
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
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Invalid handle for final
    std::array<uint8_t, 32> digest;
    azihsm_buffer digest_buf{};
    digest_buf.ptr = digest.data();
    digest_buf.len = static_cast<uint32_t>(digest.size());

    err = azihsm_crypt_digest_final(0xDEADBEEF, &digest_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(azihsm_sha_digest, streaming_null_context_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto err = azihsm_crypt_digest_init(session.get(), &algo, nullptr);
        ASSERT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sha_digest, streaming_consistency_with_one_shot)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

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

        auto err = azihsm_crypt_digest(session.get(), &algo, &data_buf, &one_shot_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Streaming digest
        azihsm_handle ctx_handle = 0;
        err = azihsm_crypt_digest_init(session.get(), &algo, &ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        std::array<uint8_t, 32> streaming_digest;
        azihsm_buffer streaming_buf{};
        streaming_buf.ptr = streaming_digest.data();
        streaming_buf.len = static_cast<uint32_t>(streaming_digest.size());

        err = azihsm_crypt_digest_final(ctx_handle, &streaming_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Compare results - they should be identical
        ASSERT_EQ(one_shot_digest, streaming_digest);
    });
}