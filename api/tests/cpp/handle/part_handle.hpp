// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef PARTITION_HANDLE_HPP
#define PARTITION_HANDLE_HPP

#include <azihsm_api.h>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "part_list_handle.hpp"

// Test credentials for use in unit tests.
constexpr uint8_t TEST_CRED_ID[16] = { 0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38,
                                       0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76 };

constexpr uint8_t TEST_CRED_PIN[16] = { 0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00,
                                        0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00 };

class PartitionHandle
{
  public:
    PartitionHandle(std::vector<azihsm_char> &path) : handle_(0)
    {
        open_and_init(path, 0);
    }

    ~PartitionHandle() noexcept
    {
        if (handle_ != 0)
        {
            azihsm_part_close(handle_);
        }
    }

    PartitionHandle(const PartitionHandle &) = delete;
    PartitionHandle &operator=(const PartitionHandle &) = delete;

    PartitionHandle(PartitionHandle &&other) noexcept : handle_(other.handle_)
    {
        other.handle_ = 0;
    }

    PartitionHandle &operator=(PartitionHandle &&other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != 0)
            {
                azihsm_part_close(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = 0;
        }
        return *this;
    }

    azihsm_handle get() const noexcept
    {
        return handle_;
    }

    explicit operator bool() const noexcept
    {
        return handle_ != 0;
    }

  private:
    azihsm_handle handle_;

    static std::mutex &get_init_mutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    static std::unordered_set<uint32_t> &get_initialized_partitions()
    {
        static std::unordered_set<uint32_t> initialized;
        return initialized;
    }

    void open_and_init(std::vector<azihsm_char> &path, uint32_t index)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        auto err = azihsm_part_open(&path_str, &handle_);
        if (err != AZIHSM_ERROR_SUCCESS)
        {
            throw std::runtime_error("Failed to open partition. Error: " + std::to_string(err));
        }

        std::lock_guard<std::mutex> lock(get_init_mutex());
        auto &initialized = get_initialized_partitions();

        if (initialized.find(index) == initialized.end())
        {
            azihsm_credentials creds{};
            std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
            std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

            err = azihsm_part_init(handle_, &creds);
            if (err != AZIHSM_ERROR_SUCCESS)
            {
                azihsm_part_close(handle_);
                handle_ = 0;
                throw std::runtime_error(
                    "Failed to initialize partition. Error: " + std::to_string(err)
                );
            }

            initialized.insert(index);
        }
    }
};

#endif // PARTITION_HANDLE_HPP