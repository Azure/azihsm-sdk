// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef PART_LIST_HANDLE_HPP
#define PART_LIST_HANDLE_HPP

#include <azihsm_api.h>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief RAII wrapper for HSM partition list handle.
 *
 * This class provides automatic resource management for HSM partition list
 * handles, ensuring that resources are properly released when the object
 * goes out of scope. It also provides convenient methods to query partition
 * information.
 */
class PartitionListHandle
{
  public:
    /**
     * @brief Constructs a PartitionListHandle and retrieves the partition list.
     *
     * @throws std::runtime_error if the partition list cannot be retrieved.
     */
    PartitionListHandle() : handle_(0)
    {
        auto err = azihsm_part_get_list(&handle_);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to get partition list. Error: " + std::to_string(err));
        }
    }

    /**
     * @brief Destructor that automatically frees the partition list.
     */
    ~PartitionListHandle() noexcept
    {
        if (handle_ != 0)
        {
            azihsm_part_free_list(handle_);
        }
    }

    // Delete copy constructor and copy assignment operator
    PartitionListHandle(const PartitionListHandle &) = delete;
    PartitionListHandle &operator=(const PartitionListHandle &) = delete;

    /**
     * @brief Move constructor.
     *
     * @param other The PartitionListHandle to move from.
     */
    PartitionListHandle(PartitionListHandle &&other) noexcept : handle_(other.handle_)
    {
        other.handle_ = 0;
    }

    /**
     * @brief Move assignment operator.
     *
     * @param other The PartitionListHandle to move from.
     * @return Reference to this object.
     */
    PartitionListHandle &operator=(PartitionListHandle &&other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != 0)
            {
                azihsm_part_free_list(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = 0;
        }
        return *this;
    }

    /**
     * @brief Gets the raw handle value.
     *
     * @return The underlying azihsm_handle.
     */
    azihsm_handle get() const noexcept
    {
        return handle_;
    }

    /**
     * @brief Gets the number of partitions in the list.
     *
     * @return The partition count.
     * @throws std::runtime_error if the count cannot be retrieved.
     */
    uint32_t count() const
    {
        uint32_t count = 0;
        auto err = azihsm_part_get_count(handle_, &count);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to get partition count. Error: " + std::to_string(err)
            );
        }
        return count;
    }

    /**
     * @brief Gets the path of a partition at the specified index.
     *
     * @param index The index of the partition (zero-based).
     * @return The partition path as a string.
     * @throws std::runtime_error if the path cannot be retrieved.
     * @throws std::out_of_range if the index is invalid.
     */
    std::vector<azihsm_char> get_path(uint32_t index) const
    {
        azihsm_str path = { nullptr, 0 };

        // First call to get the required buffer size
        auto err = azihsm_part_get_path(handle_, index, &path);
        if (err == AZIHSM_STATUS_INDEX_OUT_OF_RANGE)
        {
            throw std::out_of_range("Partition index out of range: " + std::to_string(index));
        }
        if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            throw std::runtime_error(
                "Failed to get partition path size. Error: " + std::to_string(err)
            );
        }

        // Allocate buffer and retrieve the path
        std::vector<azihsm_char> buffer(path.len);
        path.str = buffer.data();

        err = azihsm_part_get_path(handle_, index, &path);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to get partition path. Error: " + std::to_string(err));
        }

        return buffer;
    }

    void for_each_part(const std::function<void(std::vector<azihsm_char> &)> &func) const
    {
        uint32_t part_count = count();
        for (uint32_t i = 0; i < part_count; ++i)
        {
            auto path = get_path(i);
            func(path);
        }
    }

    /**
     * @brief Iterates over each partition and provides a session handle to the callback.
     *
     * This method creates a partition handle and session for each partition,
     * then invokes the provided function with the session handle.
     *
     * @param func The function to call for each session. It receives:
     *             - session: The session handle for the partition
     * @throws Any exception thrown by the callback function.
     */
    void for_each_session(const std::function<void(azihsm_handle)> &func) const;

    /**
     * @brief Checks if the partition list is valid (non-zero handle).
     *
     * @return true if the handle is valid, false otherwise.
     */
    explicit operator bool() const noexcept
    {
        return handle_ != 0;
    }

  private:
    azihsm_handle handle_;
};

#endif // PART_LIST_HANDLE_HPP