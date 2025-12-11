// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

class KeyManagementTest : public ::testing::Test
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

TEST_F(KeyManagementTest, KeyGenArgumentValidation)
{
    azihsm_handle key_handle = 0;

    // Valid algorithm for testing
    azihsm_algo valid_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    azihsm_key_prop valid_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};
    azihsm_key_prop_list valid_prop_list = {.props = valid_props, .count = 1};

    // Null session handle
    auto err = azihsm_key_gen(0, &valid_algo, &valid_prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
    EXPECT_EQ(key_handle, 0);

    // Null algorithm pointer
    err = azihsm_key_gen(session_handle, nullptr, &valid_prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(key_handle, 0);

    // Null key handle pointer
    err = azihsm_key_gen(session_handle, &valid_algo, &valid_prop_list, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Invalid algorithm ID
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0};
    err = azihsm_key_gen(session_handle, &invalid_algo, &valid_prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
    EXPECT_EQ(key_handle, 0);

    // Null properties (should be allowed for some algorithms)
    err = azihsm_key_gen(session_handle, &valid_algo, nullptr, &key_handle);
    // This might succeed or fail depending on algorithm requirements - check implementation

    // Properties with zero count but non-null props
    azihsm_key_prop_list zero_count_props = {.props = valid_props, .count = 0};
    err = azihsm_key_gen(session_handle, &valid_algo, &zero_count_props, &key_handle);
    // Should be treated as no properties

    // Properties with non-zero count but null props array
    azihsm_key_prop_list null_props_array = {.props = nullptr, .count = 1};
    err = azihsm_key_gen(session_handle, &valid_algo, &null_props_array, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(key_handle, 0);
}

TEST_F(KeyManagementTest, KeyDeleteArgumentValidation)
{
    // Null session handle
    auto err = azihsm_key_delete(0, 0x12345678);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Invalid key handle
    err = azihsm_key_delete(session_handle, 0xDEADBEEF);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Zero key handle (typically invalid)
    err = azihsm_key_delete(session_handle, 0);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
}

TEST_F(KeyManagementTest, KeyPropertyValidation)
{
    azihsm_handle key_handle = 0;
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    // Property with null value pointer
    uint32_t bit_len = 128;
    azihsm_key_prop null_val_prop = {
        .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
        .val = nullptr,
        .len = sizeof(bit_len)};
    azihsm_key_prop_list null_val_list = {.props = &null_val_prop, .count = 1};

    auto err = azihsm_key_gen(session_handle, &algo, &null_val_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(key_handle, 0);

    // Property with zero length but non-null value
    azihsm_key_prop zero_len_prop = {
        .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
        .val = &bit_len,
        .len = 0};
    azihsm_key_prop_list zero_len_list = {.props = &zero_len_prop, .count = 1};

    err = azihsm_key_gen(session_handle, &algo, &zero_len_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(key_handle, 0);

    // Unknown property ID
    azihsm_key_prop unknown_prop = {
        .id = static_cast<azihsm_key_prop_id>(0xFFFFFFFF),
        .val = &bit_len,
        .len = sizeof(bit_len)};
    azihsm_key_prop_list unknown_list = {.props = &unknown_prop, .count = 1};

    err = azihsm_key_gen(session_handle, &algo, &unknown_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_KEY_PROPERTY_NOT_PRESENT);
    EXPECT_EQ(key_handle, 0);
}

TEST_F(KeyManagementTest, SessionVsApplicationKeys)
{
    // Test session key lifecycle
    {
        azihsm_handle key_handle = 0;
        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        uint32_t bit_len = 128;
        bool session_only = true;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_SESSION, .val = &session_only, .len = sizeof(session_only)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 2};

        // Generate session key
        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(key_handle, 0);

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (key_handle != 0) {
                azihsm_key_delete(session_handle, key_handle);
            } });

        // Session key should be deletable from same session
        err = azihsm_key_delete(session_handle, key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        key_handle = 0; // Prevent double delete in guard
    }

    // Test application key lifecycle
    {
        azihsm_handle key_handle = 0;
        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        uint32_t bit_len = 128;
        bool session_only = false; // Application key
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_SESSION, .val = &session_only, .len = sizeof(session_only)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 2};

        // Generate application key
        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(key_handle, 0);

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (key_handle != 0) {
                azihsm_key_delete(session_handle, key_handle);
            } });

        // Application key should be deletable
        err = azihsm_key_delete(session_handle, key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        key_handle = 0; // Prevent double delete in guard
    }
}

TEST_F(KeyManagementTest, CrossSessionKeyAccess)
{
    // Generate a session-only key in first session
    azihsm_handle session_key = 0;
    {
        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        uint32_t bit_len = 128;
        bool session_only = true;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_SESSION, .val = &session_only, .len = sizeof(session_only)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 2};

        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &session_key);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(session_key, 0);
    }

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (session_key != 0) {
            azihsm_key_delete(session_handle, session_key);
        } });

    // Open second session
    auto [partition_handle2, session_handle2] = open_session();
    auto session_guard = scope_guard::make_scope_exit([&]
                                                      {
        EXPECT_EQ(azihsm_sess_close(session_handle2), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(azihsm_part_close(partition_handle2), AZIHSM_ERROR_SUCCESS); });

    ASSERT_NE(session_handle2, 0);

    // Try to delete session key from different session - should fail
    auto err = azihsm_key_delete(session_handle2, session_key);
    EXPECT_EQ(err, AZIHSM_DELETE_KEY_FAILED);
}

TEST_F(KeyManagementTest, KeyPropertyCombinations)
{
    azihsm_handle key_handle = 0;
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    // Test comprehensive property set
    uint32_t bit_len = 256;
    bool session_only = false;
    bool encrypt_allowed = true;
    bool decrypt_allowed = true;
    bool wrap_allowed = false;
    bool unwrap_allowed = false;

    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_SESSION, .val = &session_only, .len = sizeof(session_only)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_allowed, .len = sizeof(encrypt_allowed)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_allowed, .len = sizeof(decrypt_allowed)},
        {.id = AZIHSM_KEY_PROP_ID_WRAP, .val = &wrap_allowed, .len = sizeof(wrap_allowed)},
        {.id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &unwrap_allowed, .len = sizeof(unwrap_allowed)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 6};

    auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(key_handle, 0);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });
}

TEST_F(KeyManagementTest, DuplicateProperties)
{
    azihsm_handle key_handle = 0;
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    // Test duplicate bit length properties
    uint32_t bit_len1 = 128;
    uint32_t bit_len2 = 256;

    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len1, .len = sizeof(bit_len1)},
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len2, .len = sizeof(bit_len2)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    // Should succeed using last value
    if (err == AZIHSM_ERROR_SUCCESS && key_handle != 0)
    {
        EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
    }
}