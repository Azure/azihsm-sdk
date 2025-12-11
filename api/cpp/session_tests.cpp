// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

// Test credentials for use in unit tests. Keep these in sync with
// TEST_CRED_ID & TEST_CRED_PIN in api/ddi/lib/tests/common.rs
uint8_t TEST_CRED_ID[16] = {
    0x70,
    0xFC,
    0xF7,
    0x30,
    0xB8,
    0x76,
    0x42,
    0x38,
    0xB8,
    0x35,
    0x80,
    0x10,
    0xCE,
    0x8A,
    0x3F,
    0x76,
};

uint8_t TEST_CRED_PIN[16] = {
    0xDB,
    0x3D,
    0xC7,
    0x7F,
    0xC2,
    0x2E,
    0x43,
    0x00,
    0x80,
    0xD4,
    0x1B,
    0x31,
    0xB6,
    0xF0,
    0x48,
    0x00,
};

TEST(session_test, azihsm_sess_open_close)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        {
            EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS);
        });

    auto sess_handle = azihsm_handle{0};
    azihsm_api_rev api_rev;
    api_rev.major = 1;
    api_rev.minor = 0;

    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));
    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(sess_handle, 0);

    err = azihsm_sess_close(sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
}

TEST(session_test, azihsm_sess_open_null_api_rev)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, nullptr, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(session_test, azihsm_sess_open_null_creds)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};
    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, nullptr, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(session_test, azihsm_sess_open_null_sess_handle)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
}

TEST(session_test, azihsm_sess_open_invalid_partition_handle)
{
    azihsm_api_rev api_rev{1, 0};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(0xDEADBEEF, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(session_test, azihsm_sess_close_invalid_handle)
{
    auto err = azihsm_sess_close(0xBADCAFE);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(session_test, azihsm_sess_double_close)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_handle sess_handle = 0;
    ASSERT_EQ(azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle), AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(sess_handle, 0u);

    EXPECT_EQ(azihsm_sess_close(sess_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_sess_close(sess_handle), AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(session_test, azihsm_sess_open_close_multiple)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    for (int i = 0; i < 5; ++i)
    {
        azihsm_handle sess_handle = 0;
        EXPECT_EQ(azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle), AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(sess_handle, 0u);
        EXPECT_EQ(azihsm_sess_close(sess_handle), AZIHSM_ERROR_SUCCESS);
    }
}

TEST(session_test, azihsm_sess_open_with_wrong_handle_type)
{
    azihsm_handle list_handle = 0;
    ASSERT_EQ(azihsm_part_get_list(&list_handle), AZIHSM_ERROR_SUCCESS);

    auto guard = scope_guard::make_scope_exit(
        [&]()
        { EXPECT_EQ(azihsm_part_free_list(list_handle), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(list_handle, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST(session_test, azihsm_sess_open_with_corrupt_creds)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{1, 0};

    azihsm_app_creds creds{};

    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_OPEN_SESSION_FAILED);
}

TEST(session_test, azihsm_sess_open_with_unsupported_api_rev)
{
    auto [handle_part, path] = open_partition();
    auto part_guard = scope_guard::make_scope_exit(
        [handle_part]()
        { EXPECT_EQ(azihsm_part_close(handle_part), AZIHSM_ERROR_SUCCESS); });

    azihsm_api_rev api_rev{99, 99};
    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_handle sess_handle = 0;
    auto err = azihsm_sess_open(handle_part, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &sess_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_API_REV);
}
