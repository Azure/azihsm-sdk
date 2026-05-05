// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <filesystem>
#include <gtest/gtest.h>

/// Returns the standard test API revision (1.0) used across all C++ tests.
inline azihsm_api_rev test_api_rev()
{
    return azihsm_api_rev{ 1, 0 };
}

/// Returns the system temporary directory (`/tmp` on Linux, `%TEMP%` on Windows).
/// Fails the current test if the temp directory cannot be determined.
inline std::filesystem::path get_test_tmp_dir()
{
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        ADD_FAILURE() << "get_test_tmp_dir: unable to determine temp directory: " << ec.message();
        return {};
    }
    return dir;
}
