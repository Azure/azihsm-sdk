// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef PARTITION_HANDLE_HPP
#define PARTITION_HANDLE_HPP

#include <azihsm_api.h>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../utils/part_init_config.hpp"
#include "../utils/utils.hpp"
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

    // Wrap a pre-opened partition handle for RAII cleanup only (no open/reset/init).
    static PartitionHandle from_raw(azihsm_handle handle)
    {
        return PartitionHandle(handle);
    }

  private:
    azihsm_handle handle_;

    // Private constructor for wrapping a pre-opened handle
    explicit PartitionHandle(azihsm_handle handle) : handle_(handle)
    {
    }

    static std::mutex &get_init_mutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // Per-path cache of the MOBK derived on the first init after the
    // device powers up. `init_bk3` (the DDI operation that derives
    // MOBK from OBK) is one-shot per power cycle and is preserved
    // across NSSR/reset, so subsequent inits must supply the cached
    // MOBK directly instead of re-providing the OBK.
    static std::unordered_map<std::string, std::vector<uint8_t>> &get_mobk_cache()
    {
        static std::unordered_map<std::string, std::vector<uint8_t>> cache;
        return cache;
    }

    void open_and_init(std::vector<azihsm_char> &path, uint32_t index)
    {
        azihsm_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        auto api_rev = test_api_rev();
        auto err = azihsm_part_open(&path_str, &handle_, api_rev);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to open partition. Error: " + std::to_string(err));
        }

        std::lock_guard<std::mutex> lock(get_init_mutex());

        // Reset before initialization to clear any previous state and ensure clean state for each
        // test
        err = azihsm_part_reset(handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(handle_);
            handle_ = 0;
            throw std::runtime_error("Failed to reset partition. Error: " + std::to_string(err));
        }

        azihsm_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        PartInitConfig init_config{};
        make_part_init_config(handle_, init_config);

        // OBK-first / MOBK-fallback strategy.
        // On cold device: OBK succeeds, MOBK is persisted to file.
        // On warm device: OBK returns BK3_ALREADY_INITIALIZED, helper
        // loads cached MOBK from in-memory cache or file and retries.
        std::string path_key(reinterpret_cast<const char *>(path.data()), path.size());
        auto &cache = get_mobk_cache();

        // Try in-memory cache first (avoids the failed OBK round-trip
        // within the same process).
        auto it = cache.find(path_key);
        azihsm_buffer mobk_buf{};
        if (it != cache.end() &&
            init_config.backup_config.source == AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER)
        {
            mobk_buf.ptr = it->second.data();
            mobk_buf.len = static_cast<uint32_t>(it->second.size());
            init_config.backup_config.owner_backup_key = nullptr;
            init_config.backup_config.masked_owner_backup_key = &mobk_buf;
        }

        err = part_init_with_mobk_fallback(handle_, &creds, init_config, nullptr);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            azihsm_part_close(handle_);
            handle_ = 0;
            throw std::runtime_error(
                "Failed to initialize partition. Error: " + std::to_string(err)
            );
        }

        // Update the in-memory cache with the current MOBK.
        if (init_config.backup_config.source == AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER)
        {
            auto mobk = query_mobk_property(handle_);
            if (!mobk.empty())
            {
                cache[path_key] = std::move(mobk);
            }
        }
    }
};

#endif // PARTITION_HANDLE_HPP