// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <thread>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"

TEST(azihsm_part, get_list)
{
    auto handle = azihsm_handle{ 0 };
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    auto guard = scope_guard::make_scope_exit([&handle] {
        ASSERT_EQ(azihsm_part_free_list(handle), AZIHSM_STATUS_SUCCESS);
    });
    ASSERT_NE(handle, 0);
}

TEST(azihsm_part, get_list_null_handle)
{
    auto err = azihsm_part_get_list(nullptr);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
}

TEST(azihsm_part, free_list)
{
    auto handle = azihsm_handle{ 0 };
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    err = azihsm_part_free_list(handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
}

TEST(azihsm_part, free_list_double_free)
{
    auto handle = azihsm_handle{ 0 };
    auto err = azihsm_part_get_list(&handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    err = azihsm_part_free_list(handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Second free should return invalid handle
    err = azihsm_part_free_list(handle);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST(azihsm_part, free_list_invalid_handle_value)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    auto err = azihsm_part_free_list(bad_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST(azihsm_part, get_count)
{
    auto handle = PartitionListHandle();
    auto count = uint32_t{ 0 };
    auto err = azihsm_part_get_count(handle.get(), &count);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_GT(count, 0);
}

TEST(azihsm_part, get_count_null_output)
{
    auto handle = PartitionListHandle();
    auto err = azihsm_part_get_count(handle.get(), nullptr);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
}

TEST(azihsm_part, get_count_invalid_handle_value)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    uint32_t count = 0;
    auto err = azihsm_part_get_count(bad_handle, &count);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST(azihsm_part, get_path)
{
    auto handle = PartitionListHandle();
    uint32_t count = handle.count();

    for (auto i = 0u; i < count; ++i)
    {
        azihsm_str path = { nullptr, 0 };
        auto err = azihsm_part_get_path(handle.get(), i, &path);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(path.len, 0);

        std::vector<azihsm_char> buffer(path.len, 0);
        path.str = buffer.data();

        uint32_t path_len = path.len;
        err = azihsm_part_get_path(handle.get(), i, &path);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(path.len, path_len);
    }
}

TEST(azihsm_part, get_path_invalid_handle)
{
    auto bad_handle = 0xDEADBEEF;
    azihsm_str path = { nullptr, 0 };
    auto err = azihsm_part_get_path(bad_handle, 0, &path);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST(azihsm_part, get_path_null_path_ptr)
{
    auto handle = PartitionListHandle();
    for (auto i = 0u; i < handle.count(); ++i)
    {
        azihsm_str path = { nullptr, 42 };
        auto err = azihsm_part_get_path(handle.get(), i, &path);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    }
}

TEST(azihsm_part, get_path_invalid_index)
{
    auto handle = PartitionListHandle();
    uint32_t count = handle.count();
    for (auto i = 0u; i < handle.count(); ++i)
    {
        azihsm_str path = { nullptr, 0 };
        auto err = azihsm_part_get_path(handle.get(), count, &path);
        ASSERT_EQ(err, AZIHSM_STATUS_INDEX_OUT_OF_RANGE);
    }
}

TEST(azihsm_part, open_close)
{
    auto handle_list = PartitionListHandle();
    uint32_t count = handle_list.count();

    for (auto i = 0u; i < count; ++i)
    {
        auto path = handle_list.get_path(i);

        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(part_handle, 0u);

        err = azihsm_part_close(part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    }
}

TEST(azihsm_part, open_close_multiple_times)
{
    auto handle_list = PartitionListHandle();
    uint32_t count = handle_list.count();

    for (auto i = 0u; i < count; ++i)
    {
        auto path = handle_list.get_path(i);

        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        for (int j = 0; j < 5; ++j)
        {
            azihsm_handle part_handle = 0;
            auto err = azihsm_part_open(&path_str, &part_handle);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(part_handle, 0u);

            err = azihsm_part_close(part_handle);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }
    }
}

TEST(azihsm_part, open_same_partition_multiple_times)
{
    auto handle_list = PartitionListHandle();
    uint32_t count = handle_list.count();

    for (auto i = 0u; i < count; ++i)
    {
        auto path = handle_list.get_path(i);

        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        std::vector<PartitionHandle> part_handles;

        // Open the same partition 5 times
        for (int j = 0; j < 5; ++j)
        {
            part_handles.push_back(PartitionHandle(path));
        }

        part_handles.clear(); // All handles will be closed here
    }
}

TEST(azihsm_part, open_double_close)
{
    auto handle_list = PartitionListHandle();
    uint32_t count = handle_list.count();

    for (auto i = 0u; i < count; ++i)
    {
        auto path = handle_list.get_path(i);

        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        azihsm_handle part_handle = 0;
        auto err = azihsm_part_open(&path_str, &part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(part_handle, 0u);

        err = azihsm_part_close(part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Second close should return invalid handle
        err = azihsm_part_close(part_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    }
}