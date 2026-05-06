// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <ios>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
// clang-format on
#else
#include <fstream>
#endif

/// Generates a random IV of the given size using the platform's CSPRNG
/// (Windows CNG's BCryptGenRandom on Windows, `/dev/urandom` elsewhere).
/// Fails the current test if the RNG call fails.
inline std::vector<uint8_t> test_iv(size_t size)
{
    std::vector<uint8_t> iv(size);

#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        iv.data(),
        static_cast<ULONG>(iv.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status != STATUS_SUCCESS)
    {
        ADD_FAILURE() << "test_iv: BCryptGenRandom failed with status 0x" << std::hex << status;
        return iv;
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