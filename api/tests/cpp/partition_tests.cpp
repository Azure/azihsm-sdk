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

TEST(azihsm_part, get_prop_path)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_PATH, nullptr, 0 };
        auto err = azihsm_part_get_prop(partition.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(partition.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_driver_version)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_DRIVER_VERSION, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_firmware_version)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_FIRMWARE_VERSION, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_hardware_version)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_HARDWARE_VERSION, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_pci_hw_id)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_PCI_HW_ID, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_min_api_rev)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        azihsm_api_rev api_rev = { 0, 0 };
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MIN_API_REV, &api_rev, sizeof(api_rev) };

        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(prop.len, sizeof(azihsm_api_rev));
        ASSERT_GT(api_rev.major, 0);
    });
}

TEST(azihsm_part, get_prop_max_api_rev)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        azihsm_api_rev api_rev = { 0, 0 };
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MAX_API_REV, &api_rev, sizeof(api_rev) };

        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(prop.len, sizeof(azihsm_api_rev));
        ASSERT_GT(api_rev.major, 0);
    });
}

TEST(azihsm_part, get_prop_api_rev_range)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        azihsm_api_rev min_api_rev = { 0, 0 };
        azihsm_api_rev max_api_rev = { 0, 0 };

        azihsm_part_prop min_prop = { AZIHSM_PART_PROP_ID_MIN_API_REV,
                                      &min_api_rev,
                                      sizeof(min_api_rev) };
        auto err = azihsm_part_get_prop(part.get(), &min_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_part_prop max_prop = { AZIHSM_PART_PROP_ID_MAX_API_REV,
                                      &max_api_rev,
                                      sizeof(max_api_rev) };
        err = azihsm_part_get_prop(part.get(), &max_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Min should be less than or equal to max
        ASSERT_TRUE(
            min_api_rev.major < max_api_rev.major ||
            (min_api_rev.major == max_api_rev.major && min_api_rev.minor <= max_api_rev.minor)
        );
    });
}

TEST(azihsm_part, get_prop_manufacturer_cert)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MANUFACTURER_CERT, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(prop.len, 0);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);

        // Verify the certificate chain is in PEM format
        std::string cert_chain(buffer.begin(), buffer.begin() + prop.len);
        ASSERT_TRUE(cert_chain.find("-----BEGIN CERTIFICATE-----") != std::string::npos);
        ASSERT_TRUE(cert_chain.find("-----END CERTIFICATE-----") != std::string::npos);
    });
}

TEST(azihsm_part, get_prop_manufacturer_cert_buffer_too_small)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First get the required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MANUFACTURER_CERT, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        uint32_t required_size = prop.len;
        ASSERT_GT(required_size, 0);

        // Provide buffer that's too small
        std::vector<uint8_t> buffer(required_size - 1);
        prop.val = buffer.data();
        prop.len = static_cast<uint32_t>(buffer.size());

        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(prop.len, required_size); // Should return required size
    });
}

TEST(azihsm_part, get_prop_backup_masking_key)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_masked_owner_backup_key)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // First call to get required size
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY, nullptr, 0 };
        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        // Second call with properly sized buffer
        std::vector<uint8_t> buffer(prop.len);
        prop.val = buffer.data();
        err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(prop.len, 0);
    });
}

TEST(azihsm_part, get_prop_null_prop_ptr)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        auto err = azihsm_part_get_prop(part.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST(azihsm_part, get_prop_invalid_handle)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_PATH, nullptr, 0 };

    auto err = azihsm_part_get_prop(bad_handle, &prop);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST(azihsm_part, get_prop_buffer_too_small_api_rev)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // Provide buffer that's too small
        azihsm_api_rev api_rev = { 0, 0 };
        azihsm_part_prop prop = { AZIHSM_PART_PROP_ID_MIN_API_REV,
                                  &api_rev,
                                  1 }; // Only 1 byte instead of sizeof

        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(prop.len, sizeof(azihsm_api_rev)); // Should return required size
    });
}

TEST(azihsm_part, get_prop_unsupported_property)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // Test an unsupported property
        azihsm_part_prop prop = { static_cast<azihsm_part_prop_id>(-1), nullptr, 0 };

        auto err = azihsm_part_get_prop(part.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_UNSUPPORTED_PARTITION_PROPERTY);
    });
}

TEST(azihsm_part, get_prop_all_supported_properties)
{
    auto part_list = PartitionListHandle();

    part_list.for_each_part([](std::vector<azihsm_char> &path) {
        auto part = PartitionHandle(path);

        // Test all supported properties
        struct
        {
            azihsm_part_prop_id id;
            const char *name;
        } supported_props[] = {
            { AZIHSM_PART_PROP_ID_TYPE, "TYPE" },
            { AZIHSM_PART_PROP_ID_PATH, "PATH" },
            { AZIHSM_PART_PROP_ID_DRIVER_VERSION, "DRIVER_VERSION" },
            { AZIHSM_PART_PROP_ID_FIRMWARE_VERSION, "FIRMWARE_VERSION" },
            { AZIHSM_PART_PROP_ID_HARDWARE_VERSION, "HARDWARE_VERSION" },
            { AZIHSM_PART_PROP_ID_PCI_HW_ID, "PCI_HW_ID" },
            { AZIHSM_PART_PROP_ID_MIN_API_REV, "MIN_API_REV" },
            { AZIHSM_PART_PROP_ID_MAX_API_REV, "MAX_API_REV" },
            { AZIHSM_PART_PROP_ID_MANUFACTURER_CERT, "MANUFACTURER_CERT" },
            { AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY, "BACKUP_MASKING_KEY" },
            { AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY, "MASKED_OWNER_BACKUP_KEY" },
        };

        for (const auto &test_prop : supported_props)
        {
            SCOPED_TRACE(test_prop.name);

            // First call to get size
            azihsm_part_prop prop = { test_prop.id, nullptr, 0 };
            auto err = azihsm_part_get_prop(part.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_GT(prop.len, 0);

            // Second call with buffer
            std::vector<uint8_t> buffer(prop.len);
            prop.val = buffer.data();
            err = azihsm_part_get_prop(part.get(), &prop);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }
    });
}
