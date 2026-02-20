// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <filesystem>
#include <memory>
#include <string>

/// Well-known directory name for resiliency test data.
static constexpr const char *RESILIENCY_DIR_NAME = "azihsm_resiliency_test";

/// Opaque context owning the test directory and lock file descriptor/handle.
/// The destructor closes the lock file and removes the directory.
struct ResiliencyTestCtx
{
    std::filesystem::path temp_dir;
    std::string lock_path;
#ifdef _WIN32
    void *lock_handle; // HANDLE
#else
    int lock_fd;
#endif

    ResiliencyTestCtx();
    ~ResiliencyTestCtx();

    /// Returns the shared directory path.
    const std::filesystem::path &dir() const { return temp_dir; }

    // Non-copyable, non-movable (pointers into this object are handed out).
    ResiliencyTestCtx(const ResiliencyTestCtx &) = delete;
    ResiliencyTestCtx &operator=(const ResiliencyTestCtx &) = delete;
    ResiliencyTestCtx(ResiliencyTestCtx &&) = delete;
    ResiliencyTestCtx &operator=(ResiliencyTestCtx &&) = delete;
};

/// Build an azihsm_resiliency_config backed by the given directory.
///
/// The directory must already exist. Each thread or process should call
/// this to get its own config handle pointing at the shared storage and
/// lock file.
///
/// @param[in]  ctx         The owning test context (provides the dir and lock fd/handle).
/// @param[out] config_out  Populated with vtable pointers and the context.
void make_resiliency_config_in(
    ResiliencyTestCtx &ctx,
    azihsm_resiliency_config &config_out);

/// Convenience wrapper: creates (or resets) the shared directory, opens
/// the lock file, builds an azihsm_resiliency_config, and returns the
/// RAII context.
///
/// The returned ResiliencyTestCtx must outlive the config.
///
/// @param[out] config_out  Populated with vtable pointers and the context.
/// @return Owning pointer to the test context.
std::unique_ptr<ResiliencyTestCtx> make_resiliency_config(
    azihsm_resiliency_config &config_out);