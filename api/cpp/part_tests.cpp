// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

TEST(part_test, azihsm_part_get_list)
{
    auto handle = azihsm_handle{0};

    auto err = azihsm_part_get_list(&handle);
    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);
}

TEST(part_test, azihsm_part_get_path)
{
    auto handle = azihsm_handle{0};

    auto err = azihsm_part_get_list(&handle);
    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);

    uint32_t count = 0;
    err = azihsm_part_get_count(handle, &count);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_GT(count, 0);

    AzihsmStr path = {nullptr, 0};
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_GT(path.len, 0);

    std::vector<AzihsmCharType> buffer(path.len);
    path.str = &buffer[0];
    uint32_t path_len_orig = path.len;
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(path.len, path_len_orig);
}

TEST(part_test, azihsm_part_get_path_invalid_handle)
{
    auto handle = azihsm_handle{0};
    AzihsmStr path = {nullptr, 0};

    auto err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(part_test, azihsm_part_get_path_null_path_ptr)
{
    auto handle = azihsm_handle{0};

    auto err = azihsm_part_get_list(&handle);
    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);

    AzihsmStr path = {nullptr, 42};
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(part_test, azihsm_part_get_path_invalid_index)
{
    auto handle = azihsm_handle{0};

    auto err = azihsm_part_get_list(&handle);
    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);

    uint32_t count = 0;
    err = azihsm_part_get_count(handle, &count);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_GT(count, 0);

    AzihsmStr path = {nullptr, 0};
    err = azihsm_part_get_path(handle, count, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INDEX_OUT_OF_RANGE);
}

TEST(part_test, azihsm_part_open_close)
{
    auto [handle_part, path] = open_partition();

    azihsm_part_close(handle_part);
}

TEST(part_test, azihsm_part_get_list_null_handle)
{
    azihsm_handle *null_handle = nullptr;
    auto err = azihsm_part_get_list(null_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(part_test, azihsm_part_get_count_null_output)
{
    auto handle = azihsm_handle{0};
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    err = azihsm_part_get_count(handle, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(part_test, azihsm_part_get_path_zero_length_with_non_null_path)
{
    auto handle = azihsm_handle{0};
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    AzihsmCharType dummy[10] = {0};
    AzihsmStr path = {dummy, 0};
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER); // length 0 with non-null path is invalid
}

TEST(part_test, azihsm_part_free_list_double_free)
{
    auto handle = azihsm_handle{0};
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);

    EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(handle, 0);

    // Second free should return invalid handle
    EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(part_test, azihsm_part_get_count_after_free)
{
    auto handle = azihsm_handle{0};
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS);

    uint32_t count = 0;
    err = azihsm_part_get_count(handle, &count);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(part_test, azihsm_part_get_path_small_buffer)
{
    auto handle = azihsm_handle{0};
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    AzihsmStr path = {nullptr, 0};
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_GT(path.len, 0);

    // Provide a smaller buffer than required
    std::vector<AzihsmCharType> buffer(path.len - 1);
    uint32_t small_len = path.len - 1;
    path.str = buffer.data();
    path.len = small_len;
    err = azihsm_part_get_path(handle, 0, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
}

TEST(part_test, azihsm_part_get_path_null_path_and_zero_length)
{
    auto handle = azihsm_handle{0};
    ASSERT_EQ(azihsm_part_get_list(&handle), AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    AzihsmStr path = {nullptr, 0};
    EXPECT_EQ(azihsm_part_get_path(handle, 0, &path), AZIHSM_ERROR_INSUFFICIENT_BUFFER);
}

TEST(part_test, azihsm_part_get_count_invalid_handle_value)
{
    azihsm_handle fake_handle = 0xDEADBEEF;
    uint32_t count = 0;
    auto err = azihsm_part_get_count(fake_handle, &count);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(part_test, azihsm_part_get_path_max_valid_index)
{
    auto handle = azihsm_handle{0};
    ASSERT_EQ(azihsm_part_get_list(&handle), AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&handle]
        { EXPECT_EQ(azihsm_part_free_list(handle), AZIHSM_ERROR_SUCCESS); });

    uint32_t count = 0;
    ASSERT_EQ(azihsm_part_get_count(handle, &count), AZIHSM_ERROR_SUCCESS);
    ASSERT_GT(count, 0);

    uint32_t len = 0;
    AzihsmStr path = {nullptr, 0};
    EXPECT_EQ(azihsm_part_get_path(handle, count - 1, &path), AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<AzihsmCharType> buffer(path.len);
    path.str = buffer.data();
    EXPECT_EQ(azihsm_part_get_path(handle, count - 1, &path), AZIHSM_ERROR_SUCCESS);
}

TEST(part_test, azihsm_part_get_list_multiple_times)
{
    for (int i = 0; i < 10; ++i)
    {
        azihsm_handle handle = 0;
        auto err = azihsm_part_get_list(&handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(handle, 0u);

        err = azihsm_part_free_list(handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }
}

TEST(part_test, azihsm_part_open_null_path)
{
    azihsm_handle handle = 0;
    auto err = azihsm_part_open(nullptr, &handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(handle, 0u);
}

TEST(part_test, azihsm_part_open_null_handle)
{
    std::vector<AzihsmCharType> path_vec = create_azihsm_str("/dev/azihsm-emu0");
    AzihsmStr path_str = {path_vec.data(), static_cast<uint32_t>(path_vec.size())};
    auto err = azihsm_part_open(&path_str, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(part_test, azihsm_part_open_invalid_path)
{
    std::vector<AzihsmCharType> path_vec = create_azihsm_str("/nonexistent/path");
    AzihsmStr path_str = {path_vec.data(), static_cast<uint32_t>(path_vec.size())};
    azihsm_handle handle = 0;
    auto err = azihsm_part_open(&path_str, &handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(part_test, azihsm_part_close_invalid_handle)
{
    azihsm_handle fake_handle = 0xDEADBEEF;
    auto err = azihsm_part_close(fake_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(part_test, azihsm_part_double_close)
{
    auto [handle, path] = open_partition();

    EXPECT_EQ(azihsm_part_close(handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_part_close(handle), AZIHSM_ERROR_INVALID_HANDLE); // should not allow double close
}

TEST(part_test, azihsm_part_open_close_multiple_times)
{
    for (int i = 0; i < 5; ++i)
    {
        auto [handle_part, path] = open_partition();

        EXPECT_NE(handle_part, 0u);
        EXPECT_FALSE(path.empty());

        EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS);
    }
}

TEST(part_test, azihsm_part_open_from_partition_list)
{
    azihsm_handle list_handle = 0;
    ASSERT_EQ(azihsm_part_get_list(&list_handle), AZIHSM_ERROR_SUCCESS);
    auto guard = scope_guard::make_scope_exit(
        [&]
        { EXPECT_EQ(azihsm_part_free_list(list_handle), AZIHSM_ERROR_SUCCESS); });

    uint32_t count = 0;
    ASSERT_EQ(azihsm_part_get_count(list_handle, &count), AZIHSM_ERROR_SUCCESS);
    ASSERT_GT(count, 0u);

    uint32_t path_len = 0;
    AzihsmStr path = {nullptr, 0};
    ASSERT_EQ(azihsm_part_get_path(list_handle, 0, &path), AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    std::vector<AzihsmCharType> buffer(path.len);
    path.str = buffer.data();
    ASSERT_EQ(azihsm_part_get_path(list_handle, 0, &path), AZIHSM_ERROR_SUCCESS);

    azihsm_handle part_handle = 0;
    auto err = azihsm_part_open(&path, &part_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(part_handle, 0u);

    EXPECT_EQ(azihsm_part_close(part_handle), AZIHSM_ERROR_SUCCESS);
}
