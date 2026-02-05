// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef PARTITION_HANDLE_HPP
#define PARTITION_HANDLE_HPP

#include <azihsm_api.h>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "part_list_handle.hpp"
#include "test_creds.hpp"

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

    void open_and_init(std::vector<azihsm_char> &path, uint32_t index)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        auto err = azihsm_part_open(&path_str, &handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to open partition. Error: " + std::to_string(err));
        }

        std::lock_guard<std::mutex> lock(get_init_mutex());

        // Always reset partition state to ensure clean initialization
        // This clears any previous credentials and state from prior test runs or failures
        err = azihsm_part_reset(handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(handle_);
            handle_ = 0;
            throw std::runtime_error("Failed to reset partition. Error: " + std::to_string(err));
        }

        // Always initialize after reset to ensure partition is ready for tests

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        err = azihsm_part_init(handle_, &creds, nullptr, nullptr, nullptr);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(handle_);
            handle_ = 0;
            throw std::runtime_error(
                "Failed to initialize partition. Error: " + std::to_string(err)
            );
        }
    }
};

#endif // PARTITION_HANDLE_HPP