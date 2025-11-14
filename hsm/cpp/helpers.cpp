// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <vector>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

static std::once_flag partition_init_flag;

std::vector<AzihsmCharType> get_partition_path(azihsm_handle handle, uint32_t part_index)
{
    AzihsmStr path = {nullptr, 0};
    auto err = azihsm_part_get_path(handle, part_index, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_NE(path.len, 0);

    std::vector<AzihsmCharType> buffer(path.len);
    path.str = &buffer[0];
    err = azihsm_part_get_path(handle, part_index, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    return std::move(buffer);
}

std::pair<azihsm_handle, std::vector<AzihsmCharType>> open_partition(uint32_t part_index)
{
    azihsm_handle list_handle = 0;
    auto err = azihsm_part_get_list(&list_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(list_handle, 0);

    auto list_guard = scope_guard::make_scope_exit(
        [list_handle]()
        {
            EXPECT_EQ(azihsm_part_free_list(list_handle), AZIHSM_ERROR_SUCCESS);
        });

    std::vector<AzihsmCharType> path_vec = get_partition_path(list_handle, part_index);

    azihsm_handle part_handle = 0;
    AzihsmStr path = {path_vec.data(), static_cast<uint32_t>(path_vec.size())};
    err = azihsm_part_open(&path, &part_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(part_handle, 0);

    std::call_once(partition_init_flag, [part_handle, &err]()
                   {
                       azihsm_app_creds creds;
                       memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
                       memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));
                       err = azihsm_part_init(part_handle, &creds);
                       EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS); });

    return {part_handle, std::move(path_vec)};
}

std::vector<AzihsmCharType> create_azihsm_str(const char *str)
{
    size_t len = strlen(str) + 1;
    std::vector<AzihsmCharType> result(len);

    // Convert char to AzihsmCharType (handles both u8 and u16)
    for (size_t i = 0; i < len; ++i)
    {
        result[i] = static_cast<AzihsmCharType>(str[i]);
    }

    return result;
}

// Helper function to open a session
std::pair<azihsm_handle, azihsm_handle> open_session()
{
    auto [part_handle, path] = open_partition();

    azihsm_handle session_handle = 0;
    azihsm_api_rev api_rev;
    api_rev.major = 1;
    api_rev.minor = 0;

    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    auto err = azihsm_sess_open(part_handle, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &session_handle);
    if (err != AZIHSM_ERROR_SUCCESS)
    {
        azihsm_part_close(part_handle);
        return {0, 0};
    }

    return {part_handle, session_handle};
}