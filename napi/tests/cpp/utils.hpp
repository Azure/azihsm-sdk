#pragma once

#include <azihsm_api.h>

// Generic RAII wrapper for managing an existing HSM key with automatic cleanup
struct AutoKey
{
    azihsm_handle handle = 0;

    AutoKey() = default;

    // Prevent copying
    AutoKey(const AutoKey &) = delete;
    AutoKey &operator=(const AutoKey &) = delete;

    // Allow moving
    AutoKey(AutoKey &&other) noexcept : handle(other.handle)
    {
        other.handle = 0;
    }

    AutoKey &operator=(AutoKey &&other) noexcept
    {
        if (this != &other)
        {
            if (handle != 0)
            {
                azihsm_key_delete(handle);
            }
            handle = other.handle;
            other.handle = 0;
        }
        return *this;
    }

    ~AutoKey()
    {
        if (handle != 0)
        {
            azihsm_key_delete(handle);
        }
    }

    azihsm_handle get() const
    {
        return handle;
    }
    azihsm_handle *get_ptr()
    {
        return &handle;
    }

    // Allow implicit conversion to azihsm_handle for convenience
    operator azihsm_handle() const
    {
        return handle;
    }
};
