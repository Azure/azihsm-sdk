// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#else
#include <fstream>
#endif

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

/// Generates a random IV of the given size using the platform's CSPRNG
/// (Windows CNG's BCryptGenRandom on Windows, `/dev/urandom` elsewhere).
/// Fails the current test if the RNG call fails.
inline std::vector<uint8_t> test_iv(size_t size)
{
    std::vector<uint8_t> iv(size);
    // fill IV with all zeros
    //std::fill(iv.begin(), iv.end(), 0);
    //return iv;

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        iv.data(),
        static_cast<ULONG>(iv.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != STATUS_SUCCESS)
    {
        ADD_FAILURE() << "test_iv: BCryptGenRandom failed with status 0x" << std::hex << status;
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom)
    {
        ADD_FAILURE() << "test_iv: failed to open /dev/urandom";
        return iv;
    }
    urandom.read(reinterpret_cast<char *>(iv.data()), static_cast<std::streamsize>(iv.size()));
    if (!urandom || static_cast<size_t>(urandom.gcount()) != iv.size())
    {
        ADD_FAILURE() << "test_iv: short read from /dev/urandom";
    }
#endif
    return iv;
}
