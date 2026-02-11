// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SESSION_HANDLE_HPP
#define SESSION_HANDLE_HPP

#include <azihsm_api.h>
#include <cstring>
#include <stdexcept>
#include <string>

#include "test_creds.hpp"

class SessionHandle
{
  public:
    SessionHandle(azihsm_handle part_handle) : handle_(0)
    {
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        auto err = azihsm_sess_open(part_handle, &TEST_API_REV, &creds, nullptr, &handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to open session. Error: " + std::to_string(err));
        }
    }

    ~SessionHandle() noexcept
    {
        if (handle_ != 0)
        {
            auto err = azihsm_sess_close(handle_);
            if (err != AZIHSM_STATUS_SUCCESS)
            {
                printf("Warning: Failed to close session handle %u. Error: %d\n", handle_, err);
            }
        }
    }

    SessionHandle(const SessionHandle &) = delete;
    SessionHandle &operator=(const SessionHandle &) = delete;

    SessionHandle(SessionHandle &&other) noexcept : handle_(other.handle_)
    {
        other.handle_ = 0;
    }

    SessionHandle &operator=(SessionHandle &&other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != 0)
            {
                auto err = azihsm_sess_close(handle_);
                if (err != AZIHSM_STATUS_SUCCESS)
                {
                    printf("Warning: Failed to close session handle %u. Error: %d\n", handle_, err);
                }
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
};

#endif // SESSION_HANDLE_HPP