// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file rsa_resiliency_tests.cpp
///
/// RSA resiliency stress tests: sign/verify (PKCS#1) and encrypt/decrypt
/// (RSA-OAEP) under concurrent partition resets.

#include "resiliency_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class rsa_resiliency : public resiliency_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// RSA PKCS#1 sign/verify round-trips survive concurrent partition resets.
TEST_F(rsa_resiliency, rsa_sign_verify_survives_resets)
{
    // Import an RSA key into the HSM as a session key.
    auto pkey = generate_rsa_session_key(libctx());
    ASSERT_NE(pkey, nullptr) << "RSA session keygen failed";

    ResetHandle rh(api());

    // Background reset thread.
    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> reset_count{ 0 };

    std::thread reset_thread([&] {
        while (!stop.load())
        {
            if (api().reset(rh.h) == HSM_OK)
                reset_count.fetch_add(1);
            std::this_thread::sleep_for(RESET_INTERVAL);
        }
    });

    // PKCS#1 sign + verify in a loop.
    uint32_t ok_count = 0;
    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        bool ok = rsa_sign_verify_roundtrip(libctx(), pkey.get());
        EXPECT_TRUE(ok) << "RSA sign/verify op " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}

/// RSA-OAEP encrypt/decrypt round-trips survive concurrent partition resets.
TEST_F(rsa_resiliency, rsa_encrypt_decrypt_survives_resets)
{
    // Import RSA key with keyEncipherment usage for encrypt/decrypt.
    auto pkey = generate_rsa_session_key(libctx(), 2048, "keyEncipherment");
    ASSERT_NE(pkey, nullptr) << "RSA encryption keygen failed";

    ResetHandle rh(api());

    // Background reset thread.
    std::atomic<bool> stop{ false };
    std::atomic<uint32_t> reset_count{ 0 };

    std::thread reset_thread([&] {
        while (!stop.load())
        {
            if (api().reset(rh.h) == HSM_OK)
                reset_count.fetch_add(1);
            std::this_thread::sleep_for(RESET_INTERVAL);
        }
    });

    // RSA-OAEP encrypt + decrypt in a loop.
    uint32_t ok_count = 0;
    for (uint32_t i = 0; i < STRESS_OPS; ++i)
    {
        bool ok = rsa_encrypt_decrypt_roundtrip(libctx(), pkey.get());
        EXPECT_TRUE(ok) << "RSA enc/dec op " << i << " failed";
        if (ok)
            ok_count++;
        std::this_thread::sleep_for(WORKER_SLEEP);
    }

    stop.store(true);
    reset_thread.join();

    EXPECT_EQ(ok_count, STRESS_OPS);
    EXPECT_GT(reset_count.load(), 0u) << "No resets fired";
}
