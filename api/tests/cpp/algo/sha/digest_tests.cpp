// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <array>
#include <azihsm_api.h>
#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "utils/auto_ctx.hpp"

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
        auto_ctx ctx_handle;
        auto err = azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(ctx_handle.get(), 0u);

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
        auto size_err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(digest_buf.len, 0);

        // Allocate buffer and finish
        std::vector<uint8_t> digest(digest_buf.len);
        digest_buf.ptr = digest.data();
        err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);
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

static std::vector<uint8_t> hex_to_bytes(const char *hex)
{
    std::vector<uint8_t> bytes;

    for (size_t i = 0; hex[i] != '\0'; i += 2)
    {
        unsigned int value = 0;
        int parsed_count = std::sscanf(hex + i, "%2x", &value);

        if (parsed_count != 1)
        {
            ADD_FAILURE() << "Failed to parse hex string at offset " << i;
            return {};
        }

        bytes.push_back(static_cast<uint8_t>(value));
    }

    return bytes;
}

struct ShaKnownAnswerParams
{
    azihsm_algo_id algo_id;
    const char *test_name;
    const char *expected_hex;
    uint32_t digest_len;
};

// One-Shot Digest Tests
// Verifies one-shot digest succeeds for all supported SHA algorithms.
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
// Verifies streaming digest succeeds with a single update for all supported SHA algorithms.
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
// Verifies streaming digest succeeds across multiple updates for all supported SHA algorithms.
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

// Verifies SHA-256 one-shot digest succeeds for empty input.
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

// Verifies SHA-256 one-shot digest reports the required size when the output buffer is too small.
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

// Verifies one-shot digest rejects a null algorithm argument.
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

// Verifies one-shot digest rejects a null input data buffer argument.
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

// Verifies one-shot digest rejects a null output digest buffer argument.
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

// Verifies one-shot digest rejects invalid and zero session handles.
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

// Verifies one-shot digest rejects an unsupported algorithm id.
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

// Verifies streaming digest initialization rejects a non-digest algorithm.
TEST_F(azihsm_sha_digest, streaming_init_unsupported_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_AES_CBC;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx;
        auto err = azihsm_crypt_digest_init(session, &algo, ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(ctx.get(), 0u);
    });
}

// Verifies streaming SHA-256 digest succeeds when finished without updates.
TEST_F(azihsm_sha_digest, streaming_empty_data)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        auto_ctx ctx_handle;
        auto err = azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Finish without any update (hash of empty data)
        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());
        err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(digest_buf.len, 32u);
    });
}

// Verifies streaming SHA-256 finish reports the required size when the output buffer is too small.
TEST_F(azihsm_sha_digest, streaming_insufficient_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize
        auto_ctx ctx_handle;
        auto err = azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Update
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());
        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Finish with insufficient buffer
        std::array<uint8_t, 16> small_digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = small_digest.data();
        digest_buf.len = 16; // Too small for SHA-256

        err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(digest_buf.len, 32u); // Updated to required size
    });
}

// Verifies streaming digest update and finish reject invalid context handles.
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

    err = azihsm_crypt_digest_finish(0xDEADBEEF, &digest_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Verifies streaming digest update and finish reject session handles used as context handles.
TEST_F(azihsm_sha_digest, streaming_operations_reject_session_handles_as_contexts)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        ASSERT_EQ(azihsm_crypt_digest_update(session, &data_buf), AZIHSM_STATUS_INVALID_HANDLE);

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        ASSERT_EQ(azihsm_crypt_digest_finish(session, &digest_buf), AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Verifies streaming digest initialization rejects a null context output pointer.
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

// Verifies SHA-256 streaming digest output matches the one-shot digest output.
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
        auto_ctx ctx_handle;
        err = azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::array<uint8_t, 32> streaming_digest;
        azihsm_buffer streaming_buf{};
        streaming_buf.ptr = streaming_digest.data();
        streaming_buf.len = static_cast<uint32_t>(streaming_digest.size());

        err = azihsm_crypt_digest_finish(ctx_handle, &streaming_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Compare results - they should be identical
        ASSERT_EQ(one_shot_digest, streaming_digest);
    });
}

// Verifies one-shot digest output matches known-answer vectors for all supported SHA algorithms.
TEST_F(azihsm_sha_digest, one_shot_known_answer_all_algorithms)
{
    std::vector<ShaKnownAnswerParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1", "376f19001dc171e2eb9c56962ca32478caaa7e39", 20 },
        { AZIHSM_ALGO_ID_SHA256,
          "SHA256",
          "5a648d8015900d89664e00e125df179636301a2d8fa191c1aa2bd9358ea53a69",
          32 },
        { AZIHSM_ALGO_ID_SHA384,
          "SHA384",
          "45730a19acff8481e7e2b99c4100a09a0288a3bc45df56ff7e72dd92ef9e4c92f925c9d6ba1ea96c934a5f1e"
          "782a7cc7",
          48 },
        { AZIHSM_ALGO_ID_SHA512,
          "SHA512",
          "19c6841f3d6e33a4d28e7cb47ff938728479c56bb930f3e8535ec24d9453d9665b7dc1163181b94a1ada9554"
          "e953a094ed44fd6faee7a9bbde6615375bab4ae8",
          64 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(test_case.test_name);

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            azihsm_buffer data_buf{};
            data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
            data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

            std::vector<uint8_t> digest(test_case.digest_len);
            azihsm_buffer digest_buf{};
            digest_buf.ptr = digest.data();
            digest_buf.len = test_case.digest_len;

            auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(digest_buf.len, test_case.digest_len);

            auto expected = hex_to_bytes(test_case.expected_hex);
            ASSERT_EQ(digest, expected);
        });
    }
}

// Verifies one-shot digest rejects a null data pointer when the input length is nonzero.
TEST_F(azihsm_sha_digest, one_shot_rejects_null_data_ptr_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = nullptr;
        data_buf.len = 1;

        std::array<uint8_t, 32> digest;
        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = static_cast<uint32_t>(digest.size());

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies streaming digest update rejects a null data pointer when the input length is nonzero.
TEST_F(azihsm_sha_digest, streaming_update_rejects_null_data_ptr_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer data_buf{};
        data_buf.ptr = nullptr;
        data_buf.len = 1;

        auto err = azihsm_crypt_digest_update(ctx_handle, &data_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies one-shot digest rejects a null digest pointer when the output length is nonzero.
TEST_F(azihsm_sha_digest, one_shot_rejects_null_digest_ptr_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        azihsm_buffer digest_buf{};
        digest_buf.ptr = nullptr;
        digest_buf.len = 32;

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies streaming digest finish rejects a null digest pointer when the output length is nonzero.
TEST_F(azihsm_sha_digest, streaming_finish_rejects_null_digest_ptr_with_nonzero_len)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer digest_buf{};
        digest_buf.ptr = nullptr;
        digest_buf.len = 32;

        auto err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies streaming digest initialization rejects a null algorithm argument.
TEST_F(azihsm_sha_digest, streaming_init_rejects_null_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_ctx ctx_handle;

        auto err = azihsm_crypt_digest_init(session, nullptr, ctx_handle.get_ptr());

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(ctx_handle.get(), 0u);
    });
}

// Verifies streaming digest initialization rejects invalid and zero session handles.
TEST_F(azihsm_sha_digest, streaming_init_rejects_invalid_session_handle)
{
    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_SHA256;
    algo.params = nullptr;
    algo.len = 0;

    auto_ctx ctx_handle;

    auto err = azihsm_crypt_digest_init(0xDEADBEEF, &algo, ctx_handle.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(ctx_handle.get(), 0u);

    err = azihsm_crypt_digest_init(0, &algo, ctx_handle.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(ctx_handle.get(), 0u);
}

// Verifies SHA-256 streaming digest using one-byte updates matches the one-shot digest output.
TEST_F(azihsm_sha_digest, streaming_one_byte_updates_match_one_shot)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        std::array<uint8_t, 32> one_shot_digest;
        azihsm_buffer one_shot_buf{};
        one_shot_buf.ptr = one_shot_digest.data();
        one_shot_buf.len = static_cast<uint32_t>(one_shot_digest.size());

        ASSERT_EQ(
            azihsm_crypt_digest(session, &algo, &data_buf, &one_shot_buf),
            AZIHSM_STATUS_SUCCESS
        );

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        for (size_t i = 0; i < TEST_DATA_1K.size(); ++i)
        {
            azihsm_buffer chunk_buf{};
            chunk_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data() + i);
            chunk_buf.len = 1;

            ASSERT_EQ(azihsm_crypt_digest_update(ctx_handle, &chunk_buf), AZIHSM_STATUS_SUCCESS);
        }

        std::array<uint8_t, 32> streaming_digest;
        azihsm_buffer streaming_buf{};
        streaming_buf.ptr = streaming_digest.data();
        streaming_buf.len = static_cast<uint32_t>(streaming_digest.size());

        ASSERT_EQ(azihsm_crypt_digest_finish(ctx_handle, &streaming_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(streaming_digest, one_shot_digest);
    });
}

// Verifies one-shot SHA-256 digest does not overwrite bytes past the requested digest length
// when the backing allocation is larger than digest_buf.len.
TEST_F(azihsm_sha_digest, one_shot_exact_len_with_larger_allocation)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        constexpr uint32_t expected_len = 32;
        std::array<uint8_t, 64> digest{};
        digest.fill(0xA5);

        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = expected_len;

        auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(digest_buf.len, expected_len);

        for (size_t i = expected_len; i < digest.size(); ++i)
        {
            ASSERT_EQ(digest[i], 0xA5)
                << "One-shot digest wrote past requested digest length at byte " << i;
        }
    });
}

static uint32_t expected_digest_len(azihsm_algo_id algo_id)
{
    switch (algo_id)
    {
    case AZIHSM_ALGO_ID_SHA1:
        return 20;
    case AZIHSM_ALGO_ID_SHA256:
        return 32;
    case AZIHSM_ALGO_ID_SHA384:
        return 48;
    case AZIHSM_ALGO_ID_SHA512:
        return 64;
    default:
        return 0;
    }
}

// Verifies one-shot digest output for empty input matches known-answer vectors for all supported
// SHA algorithms.
TEST_F(azihsm_sha_digest, one_shot_empty_data_known_answer_all_algorithms)
{
    std::vector<ShaKnownAnswerParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", 20 },
        { AZIHSM_ALGO_ID_SHA256,
          "SHA256",
          "e3b0c44298fc1c149afbf4c8996fb924"
          "27ae41e4649b934ca495991b7852b855",
          32 },
        { AZIHSM_ALGO_ID_SHA384,
          "SHA384",
          "38b060a751ac96384cd9327eb1b1e36a"
          "21fdb71114be07434c0cc7bf63f6e1da"
          "274edebfe76f65fbd51ad2f14898b95b",
          48 },
        { AZIHSM_ALGO_ID_SHA512,
          "SHA512",
          "cf83e1357eefb8bdf1542850d66d8007"
          "d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f"
          "63b931bd47417a81a538327af927da3e",
          64 },
    };

    uint8_t empty_data = 0;

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(std::string(test_case.test_name) + " empty-data known answer");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            azihsm_buffer data_buf{};
            data_buf.ptr = &empty_data;
            data_buf.len = 0;

            std::vector<uint8_t> digest(test_case.digest_len);
            azihsm_buffer digest_buf{};
            digest_buf.ptr = digest.data();
            digest_buf.len = test_case.digest_len;

            auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(digest_buf.len, test_case.digest_len);

            auto expected = hex_to_bytes(test_case.expected_hex);
            ASSERT_EQ(digest, expected);
        });
    }
}

// Verifies streaming digest output matches known-answer vectors for all supported SHA algorithms.
TEST_F(azihsm_sha_digest, streaming_known_answer_all_algorithms)
{
    std::vector<ShaKnownAnswerParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1", "376f19001dc171e2eb9c56962ca32478caaa7e39", 20 },
        { AZIHSM_ALGO_ID_SHA256,
          "SHA256",
          "5a648d8015900d89664e00e125df179636301a2d8fa191c1aa2bd9358ea53a69",
          32 },
        { AZIHSM_ALGO_ID_SHA384,
          "SHA384",
          "45730a19acff8481e7e2b99c4100a09a0288a3bc45df56ff7e72dd92ef9e4c92f925c9d6ba1ea96c934a5f1e"
          "782a7cc7",
          48 },
        { AZIHSM_ALGO_ID_SHA512,
          "SHA512",
          "19c6841f3d6e33a4d28e7cb47ff938728479c56bb930f3e8535ec24d9453d9665b7dc1163181b94a1ada9554"
          "e953a094ed44fd6faee7a9bbde6615375bab4ae8",
          64 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(std::string(test_case.test_name) + " streaming known answer");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            auto_ctx ctx_handle;
            ASSERT_EQ(
                azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
                AZIHSM_STATUS_SUCCESS
            );

            // Use uneven chunks to exercise non-block-aligned streaming updates.
            for (size_t offset = 0; offset < TEST_DATA_1K.size(); offset += 17)
            {
                size_t remaining = TEST_DATA_1K.size() - offset;
                size_t current_chunk = remaining < 17 ? remaining : 17;

                azihsm_buffer chunk_buf{};
                chunk_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data() + offset);
                chunk_buf.len = static_cast<uint32_t>(current_chunk);

                ASSERT_EQ(
                    azihsm_crypt_digest_update(ctx_handle, &chunk_buf),
                    AZIHSM_STATUS_SUCCESS
                );
            }

            std::vector<uint8_t> digest(test_case.digest_len);
            azihsm_buffer digest_buf{};
            digest_buf.ptr = digest.data();
            digest_buf.len = test_case.digest_len;

            ASSERT_EQ(azihsm_crypt_digest_finish(ctx_handle, &digest_buf), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(digest_buf.len, test_case.digest_len);

            auto expected = hex_to_bytes(test_case.expected_hex);
            ASSERT_EQ(digest, expected);
        });
    }
}

// Verifies one-shot size queries report the expected digest length for each supported SHA
// algorithm.
TEST_F(azihsm_sha_digest, size_query_reports_expected_digest_length_all_algorithms)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(std::string(test_case.test_name) + " size query");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            azihsm_buffer data_buf{};
            data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
            data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

            azihsm_buffer digest_buf{};
            digest_buf.ptr = nullptr;
            digest_buf.len = 0;

            auto err = azihsm_crypt_digest(session, &algo, &data_buf, &digest_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(digest_buf.len, expected_digest_len(test_case.algo_id));
        });
    }
}

// Verifies streaming finish size queries report the expected digest length for each supported SHA
// algorithm.
TEST_F(azihsm_sha_digest, streaming_size_query_reports_expected_digest_length_all_algorithms)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE(std::string(test_case.test_name) + " streaming size query");

        part_list_.for_each_session([&](azihsm_handle session) {
            azihsm_algo algo{};
            algo.id = test_case.algo_id;
            algo.params = nullptr;
            algo.len = 0;

            auto_ctx ctx_handle;
            ASSERT_EQ(
                azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_buffer data_buf{};
            data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
            data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

            ASSERT_EQ(azihsm_crypt_digest_update(ctx_handle, &data_buf), AZIHSM_STATUS_SUCCESS);

            azihsm_buffer digest_buf{};
            digest_buf.ptr = nullptr;
            digest_buf.len = 0;

            auto err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(digest_buf.len, expected_digest_len(test_case.algo_id));
        });
    }
}

// Verifies streaming digest output matches one-shot output across varied chunk boundaries.
TEST_F(azihsm_sha_digest, streaming_different_chunk_boundaries_match_one_shot)
{
    std::vector<ShaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_SHA1, "SHA1" },
        { AZIHSM_ALGO_ID_SHA256, "SHA256" },
        { AZIHSM_ALGO_ID_SHA384, "SHA384" },
        { AZIHSM_ALGO_ID_SHA512, "SHA512" },
    };

    std::vector<size_t> chunk_sizes = {
        3, 7, 31, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    };

    for (const auto &test_case : test_cases)
    {
        for (size_t chunk_size : chunk_sizes)
        {
            SCOPED_TRACE(
                std::string(test_case.test_name) + " chunk_size=" + std::to_string(chunk_size)
            );

            part_list_.for_each_session([&](azihsm_handle session) {
                azihsm_algo algo{};
                algo.id = test_case.algo_id;
                algo.params = nullptr;
                algo.len = 0;

                const uint32_t digest_len = expected_digest_len(test_case.algo_id);

                azihsm_buffer data_buf{};
                data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
                data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

                std::vector<uint8_t> one_shot_digest(digest_len);
                azihsm_buffer one_shot_buf{};
                one_shot_buf.ptr = one_shot_digest.data();
                one_shot_buf.len = digest_len;

                ASSERT_EQ(
                    azihsm_crypt_digest(session, &algo, &data_buf, &one_shot_buf),
                    AZIHSM_STATUS_SUCCESS
                );

                auto_ctx ctx_handle;
                ASSERT_EQ(
                    azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
                    AZIHSM_STATUS_SUCCESS
                );

                for (size_t offset = 0; offset < TEST_DATA_1K.size(); offset += chunk_size)
                {
                    size_t remaining = TEST_DATA_1K.size() - offset;
                    size_t current_chunk = remaining < chunk_size ? remaining : chunk_size;

                    azihsm_buffer chunk_buf{};
                    chunk_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data() + offset);
                    chunk_buf.len = static_cast<uint32_t>(current_chunk);

                    ASSERT_EQ(
                        azihsm_crypt_digest_update(ctx_handle, &chunk_buf),
                        AZIHSM_STATUS_SUCCESS
                    );
                }

                std::vector<uint8_t> streaming_digest(digest_len);
                azihsm_buffer streaming_buf{};
                streaming_buf.ptr = streaming_digest.data();
                streaming_buf.len = digest_len;

                ASSERT_EQ(
                    azihsm_crypt_digest_finish(ctx_handle, &streaming_buf),
                    AZIHSM_STATUS_SUCCESS
                );

                ASSERT_EQ(streaming_digest, one_shot_digest);
            });
        }
    }
}

// Verifies streaming digest update rejects a null data buffer argument.
TEST_F(azihsm_sha_digest, streaming_update_rejects_null_data_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        auto err = azihsm_crypt_digest_update(ctx_handle, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies streaming digest finish rejects a null digest buffer argument.
TEST_F(azihsm_sha_digest, streaming_finish_rejects_null_digest_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        auto err = azihsm_crypt_digest_finish(ctx_handle, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies streaming SHA-256 digest finish does not overwrite bytes past the requested digest
// length when the backing allocation is larger than digest_buf.len.
TEST_F(azihsm_sha_digest, streaming_finish_exact_len_with_larger_allocation)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx ctx_handle;
        ASSERT_EQ(
            azihsm_crypt_digest_init(session, &algo, ctx_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer data_buf{};
        data_buf.ptr = const_cast<uint8_t *>(TEST_DATA_1K.data());
        data_buf.len = static_cast<uint32_t>(TEST_DATA_1K.size());

        ASSERT_EQ(azihsm_crypt_digest_update(ctx_handle, &data_buf), AZIHSM_STATUS_SUCCESS);

        constexpr uint32_t expected_len = 32;
        std::array<uint8_t, 64> digest{};
        digest.fill(0xA5);

        azihsm_buffer digest_buf{};
        digest_buf.ptr = digest.data();
        digest_buf.len = expected_len;

        auto err = azihsm_crypt_digest_finish(ctx_handle, &digest_buf);

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(digest_buf.len, expected_len);

        for (size_t i = expected_len; i < digest.size(); ++i)
        {
            ASSERT_EQ(digest[i], 0xA5)
                << "Streaming digest finish wrote past requested digest length at byte " << i;
        }
    });
}

// Verifies one-shot digest rejects a valid but non-digest algorithm.
TEST_F(azihsm_sha_digest, one_shot_rejects_non_digest_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_AES_CBC;
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