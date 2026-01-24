// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"

class azihsm_sess : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_sess, open_and_close)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sess_handle, 0);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });
    });
}

TEST_F(azihsm_sess, open_null_sess_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, nullptr);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess, open_null_api_rev)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;

        auto err = azihsm_sess_open(partition.get(), nullptr, &creds, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess, open_null_creds)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_handle sess_handle = 0;

        auto err = azihsm_sess_open(partition.get(), &api_rev, nullptr, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess, open_invalid_partition_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle bad_handle = 0xDEADBEEF;
        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;

        auto err = azihsm_sess_open(bad_handle, &api_rev, &creds, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_sess, close_invalid_handle)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        azihsm_handle bad_handle = 0xBADCAFE;
        auto err = azihsm_sess_close(bad_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_sess, close_double_close)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;

        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // First close should succeed
        err = azihsm_sess_close(sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Second close should fail
        err = azihsm_sess_close(sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_sess, open_close_multiple)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        // Open and close sessions sequentially
        for (int i = 0; i < 5; ++i)
        {
            azihsm_handle sess_handle = 0;
            auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);

            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(sess_handle, 0);

            err = azihsm_sess_close(sess_handle);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }
    });
}

TEST_F(azihsm_sess, open_with_wrong_handle_type)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto list_handle_wrapper = PartitionListHandle();
        azihsm_handle list_handle = list_handle_wrapper.get();

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(list_handle, &api_rev, &creds, &sess_handle);

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_sess, open_with_corrupt_creds)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{}; // All zeros - invalid credentials

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_sess, open_with_unsupported_api_rev)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 99, 99 }; // Unsupported version
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_sess, get_prop_api_rev)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });

        azihsm_api_rev retrieved_api_rev = { 0, 0 };
        azihsm_session_prop prop = { AZIHSM_SESSION_PROP_ID_API_REV,
                                     &retrieved_api_rev,
                                     sizeof(retrieved_api_rev) };

        err = azihsm_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(prop.len, sizeof(azihsm_api_rev));
        ASSERT_EQ(retrieved_api_rev.major, 1);
        ASSERT_EQ(retrieved_api_rev.minor, 0);
    });
}

TEST_F(azihsm_sess, get_prop_api_rev_buffer_too_small)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });

        // Provide buffer that's too small
        azihsm_api_rev retrieved_api_rev = { 0, 0 };
        azihsm_session_prop prop = { AZIHSM_SESSION_PROP_ID_API_REV,
                                     &retrieved_api_rev,
                                     1 }; // Only 1 byte instead of sizeof

        err = azihsm_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(prop.len, sizeof(azihsm_api_rev)); // Should return required size
    });
}

TEST_F(azihsm_sess, get_prop_null_prop_ptr)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });

        err = azihsm_session_get_prop(sess_handle, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_sess, get_prop_invalid_handle)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    azihsm_api_rev api_rev = { 0, 0 };
    azihsm_session_prop prop = { AZIHSM_SESSION_PROP_ID_API_REV, &api_rev, sizeof(api_rev) };

    auto err = azihsm_session_get_prop(bad_handle, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_sess, get_prop_unsupported_property)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        azihsm_handle sess_handle = 0;
        auto err = azihsm_sess_open(partition.get(), &api_rev, &creds, &sess_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto guard = scope_guard::make_scope_exit([&sess_handle] {
            ASSERT_EQ(azihsm_sess_close(sess_handle), AZIHSM_STATUS_SUCCESS);
        });

        // Test an unsupported property
        azihsm_session_prop prop = { static_cast<azihsm_session_prop_id>(-1), nullptr, 0 };

        err = azihsm_session_get_prop(sess_handle, &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_UNSUPPORTED_PROPERTY);
    });
}

TEST_F(azihsm_sess, get_prop_wrong_handle_type)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        azihsm_api_rev api_rev = { 0, 0 };
        azihsm_session_prop prop = { AZIHSM_SESSION_PROP_ID_API_REV, &api_rev, sizeof(api_rev) };

        // Try to use partition handle instead of session handle
        auto err = azihsm_session_get_prop(partition.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}