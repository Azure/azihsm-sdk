// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <vector>

inline constexpr uint32_t kReportDataSize = 128;
inline constexpr uint32_t kLegacyReportDataSize = 64;
#if SESSION_EX_TESTS
inline constexpr uint32_t kValidReportDataSize = kReportDataSize;
#else
inline constexpr uint32_t kValidReportDataSize = kLegacyReportDataSize;
#endif

/// Returns the standard test API revision (1.0) used by MBOR tests.
inline azihsm_api_rev test_api_rev()
{
    return azihsm_api_rev{ 1, 0 };
}

/// Returns the minimum API revision used by `open_session_ex` test fixtures.
inline azihsm_api_rev session_ex_test_api_rev()
{
    return azihsm_api_rev{ 1, 1 };
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

/// Returns true if any byte in `bytes` is non-zero (i.e. not all-zero).
inline bool any_nonzero(const std::vector<uint8_t> &bytes)
{
    for (uint8_t b : bytes)
    {
        if (b != 0)
        {
            return true;
        }
    }
    return false;
}
