// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef SESSION_HANDLE_HPP
#define SESSION_HANDLE_HPP

#include <azihsm_api.h>
#include <cstring>
#include <stdexcept>
#include <string>

#include "part_handle.hpp"

class SessionHandle
{
  public:
    SessionHandle(azihsm_handle part_handle) : handle_(0)
    {
        azihsm_api_rev api_rev{ 1, 0 };
        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        auto err = azihsm_sess_open(part_handle, &api_rev, &creds, &handle_);
        if (err != AZIHSM_ERROR_SUCCESS)
        {
            throw std::runtime_error("Failed to open session. Error: " + std::to_string(err));
        }
    }

    ~SessionHandle() noexcept
    {
        if (handle_ != 0)
        {
            azihsm_sess_close(handle_);
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
                azihsm_sess_close(handle_);
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